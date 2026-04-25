# trustforge-rails

Rails engine that auto-installs `TrustForge::Rack` middleware in your Rails app.

## Install

```ruby
# Gemfile
gem "trustforge-rails", "~> 0.1"
```

```sh
bundle install
```

## Configure

```ruby
# config/initializers/trustforge.rb
TrustForge::Rails.configure do |c|
  c.daemon_url = ENV["TF_DAEMON_URL"]
  c.mode = :enforce
end
```

## Test

```sh
bundle install
bundle exec rspec
```
