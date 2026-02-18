source 'https://rubygems.org'

# Standard definition (Vulnerable if public & not claimed)
gem 'rails', '~> 7.0.4'

# Simple version pinning
gem "pgxcccww"

# [EDGE CASE] Git source
# Should be ignored by dependency confusion scanners usually
gem 'rack', git: 'https://github.com/rack/rack.git'

# [EDGE CASE] Path source (Internal)
gem 'my_internal_auth', path: './lib/my_internal_auth'

# [EDGE CASE] Github shorthand (Specific to Bundler)
gem 'nokogiri', github: 'sparklemotion/nokogiri'

group :development, :test do
  # Gems only for dev/test
  gem 'rspec-rails', '~> 5.0'
  gem 'debug', platforms: %i[ mri mingw x64_mingw ]
end

group :development do
  # Commented out gem (Scanner should ignore this)
  # gem 'web-console'
  
  gem 'listen', '~> 3.3'
end

# Complex formatting
gem 'sentry-ruby',
    require: 'sentry-ruby'
