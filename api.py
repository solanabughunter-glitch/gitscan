from flask import Flask, request, jsonify, redirect
import subprocess
import sqlite3
import pickle
import base64
import os

app = Flask(__name__)
db = sqlite3.connect("app.db", check_same_thread=False)

# ---- AUTH -erteesserf
def get_current_user():
    token = request.headers.get("Authorization")
    if not token:
        return None
    cur = db.cursor()
    cur.execute("SELECT id, role FROM users WHERE token = ?", (token,))
    return cur.fetchone()


# VULN: SQL Injection — user input concatenated into query
@app.route("/api/users/search")
def search_users():
    query = request.args.get("q", "")
    cur = db.cursor()
    cur.execute("SELECT * FROM users WHERE username LIKE '%" + query + "%'")
    return jsonify(cur.fetchall())


# VULN: Command Injection — user input passed to subprocess with shell=True
@app.route("/api/tools/ping")
def ping_host():
    host = request.args.get("host", "127.0.0.1")
    result = subprocess.check_output(f"ping -c 1 {host}", shell=True)
    return result


# VULN: IDOR — no ownership check, any authenticated user can view any order
@app.route("/api/orders/<order_id>")
def get_order(order_id):
    user = get_current_user()
    if not user:
        return jsonify({"error": "unauthorized"}), 401
    # Missing: does this order belong to this user?
    cur = db.cursor()
    cur.execute("SELECT * FROM orders WHERE id = ?", (order_id,))
    return jsonify(cur.fetchone())


# VULN: Broken access control — admin endpoint with no role check
@app.route("/api/admin/delete_user", methods=["POST"])
def admin_delete_user():
    user = get_current_user()
    if not user:
        return jsonify({"error": "unauthorized"}), 401
    # Missing: if user.role != "admin": return 403
    target_id = request.json.get("user_id")
    cur = db.cursor()
    cur.execute("DELETE FROM users WHERE id = ?", (target_id,))
    db.commit()
    return jsonify({"status": "deleted"})


# VULN: Unsafe deserialization — pickle.loads on user-controlled input
@app.route("/api/import/config", methods=["POST"])
def import_config():
    data = request.json.get("payload")
    config = pickle.loads(base64.b64decode(data))
    return jsonify({"imported": len(config)})


# VULN: SSRF — user-controlled URL fetched server-side
@app.route("/api/fetch")
def fetch_url():
    import requests as req
    url = request.args.get("url")
    resp = req.get(url)
    return resp.text


# VULN: Path traversal — no sanitization on filename
@app.route("/api/files/read")
def read_file():
    filename = request.args.get("name")
    filepath = os.path.join("/var/app/uploads", filename)
    with open(filepath, "r") as f:
        return f.read()


# VULN: Open redirect — user-controlled redirect target
@app.route("/api/redirect")
def do_redirect():
    target = request.args.get("url", "/")
    return redirect(target)


# VULN: Race condition — check-then-act without locking on balance
@app.route("/api/wallet/withdraw", methods=["POST"])
def withdraw():
    user = get_current_user()
    if not user:
        return jsonify({"error": "unauthorized"}), 401
    amount = float(request.json.get("amount"))
    cur = db.cursor()
    cur.execute("SELECT balance FROM wallets WHERE user_id = ?", (user[0],))
    balance = cur.fetchone()[0]
    if balance >= amount:
        # TOCTOU: balance could change between check and update
        cur.execute("UPDATE wallets SET balance = balance - ? WHERE user_id = ?", (amount, user[0]))
        db.commit()
        return jsonify({"status": "ok", "remaining": balance - amount})
    return jsonify({"error": "insufficient funds"}), 400


# VULN: Info disclosure — full stack trace and DB error returned to user
@app.route("/api/debug/query")
def debug_query():
    sql = request.args.get("sql", "SELECT 1")
    try:
        cur = db.cursor()
        cur.execute(sql)
        return jsonify(cur.fetchall())
    except Exception as e:
        return jsonify({"error": str(e), "query": sql, "db_path": db.database}), 500


if __name__ == "__main__":
    app.run(debug=True, host="0.0.0.0")
