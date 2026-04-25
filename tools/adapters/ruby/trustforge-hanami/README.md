# trustforge-hanami

Hanami 2 middleware for TrustForge. Wraps `TrustForge::Rack` for use with
Hanami's Rack-compatible middleware stack.

## Install

```ruby
# Gemfile
gem "trustforge-hanami", "~> 0.1"
```

## Use

```ruby
require "trustforge/hanami"

module MyApp
  class App < Hanami::App
    config.middleware.use TrustForge::Hanami::Middleware,
      client: TrustForge::Client.new(daemon_url: ENV["TF_DAEMON_URL"])
  end
end
```

## Test

```sh
bundle install
bundle exec rspec
```
