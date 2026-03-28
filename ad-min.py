from flask import Flask, request, jsonify, send_file
import subprocess
import sqlite3
import os
import yaml
import hashlib

app = Flask(__name__)
db = sqlite3.connect("admin.db", check_same_thread=False)


def get_user(req):
    token = req.headers.get("X-Auth-Token")
    if not token:
        return None
    cur = db.cursor()
    cur.execute("SELECT id, username, role FROM users WHERE token = ?", (token,))
    return cur.fetchone()


# VULN: SSTI — user input rendered as Jinja2 template
@app.route("/api/preview/template", methods=["POST"])
def preview_template():
    user = get_user(request)
    if not user:
        return jsonify({"error": "unauthorized"}), 401
    template_str = request.json.get("body", "")
    from jinja2 import Environment
    env = Environment()
    rendered = env.from_string(template_str).render(user=user)
    return jsonify({"preview": rendered})


# VULN: Mass assignment — user-controlled fields merged into DB update
@app.route("/api/profile/update", methods=["POST"])
def update_profile():
    user = get_user(request)
    if not user:
        return jsonify({"error": "unauthorized"}), 401
    fields = request.json
    # Attacker can set role=admin, is_verified=true, etc.
    set_clause = ", ".join(f"{k} = ?" for k in fields.keys())
    values = list(fields.values()) + [user[0]]
    cur = db.cursor()
    cur.execute(f"UPDATE users SET {set_clause} WHERE id = ?", values)
    db.commit()
    return jsonify({"status": "updated"})


# VULN: Insecure YAML deserialization
@app.route("/api/import/settings", methods=["POST"])
def import_settings():
    raw = request.data.decode("utf-8")
    config = yaml.load(raw, Loader=yaml.Loader)  # unsafe Loader
    return jsonify({"keys": list(config.keys())})


# VULN: Weak password hashing — MD5 with no salt
@app.route("/api/auth/register", methods=["POST"])
def register():
    username = request.json.get("username")
    password = request.json.get("password")
    hashed = hashlib.md5(password.encode()).hexdigest()
    cur = db.cursor()
    cur.execute("INSERT INTO users (username, password_hash) VALUES (?, ?)", (username, hashed))
    db.commit()
    return jsonify({"status": "registered"})


# VULN: File upload with no extension/type validation
@app.route("/api/upload/avatar", methods=["POST"])
def upload_avatar():
    user = get_user(request)
    if not user:
        return jsonify({"error": "unauthorized"}), 401
    f = request.files.get("file")
    save_path = os.path.join("/var/app/uploads/avatars", f.filename)
    f.save(save_path)
    return jsonify({"path": save_path})


# VULN: Timing side-channel on API key comparison
@app.route("/api/webhook/verify", methods=["POST"])
def verify_webhook():
    provided = request.headers.get("X-Webhook-Secret", "")
    expected = os.environ.get("WEBHOOK_SECRET", "default-secret")
    if provided == expected:  # not constant-time
        return jsonify({"valid": True})
    return jsonify({"valid": False}), 403


# VULN: Admin endpoint leaks all user data including tokens
@app.route("/api/admin/export")
def export_users():
    user = get_user(request)
    if not user or user[2] != "admin":
        return jsonify({"error": "forbidden"}), 403
    cur = db.cursor()
    cur.execute("SELECT id, username, token, password_hash, role FROM users")
    rows = cur.fetchall()
    return jsonify(rows)


# VULN: Log injection — user input written to log file unsanitized
@app.route("/api/feedback", methods=["POST"])
def submit_feedback():
    msg = request.json.get("message", "")
    with open("/var/log/app/feedback.log", "a") as f:
        f.write(f"[FEEDBACK] {msg}\n")  # newline injection possible
    return jsonify({"status": "received"})


# VULN: Unrestricted file download — path not validated
@app.route("/api/download")
def download_file():
    path = request.args.get("path")
    return send_file(path)


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=8080)
