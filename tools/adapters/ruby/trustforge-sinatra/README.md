# trustforge-sinatra

Sinatra extension for TrustForge.

## Install

```ruby
# Gemfile
gem "trustforge-sinatra", "~> 0.1"
```

## Use

```ruby
require "sinatra/trustforge"

class App < Sinatra::Base
  set :trustforge_daemon_url, ENV["TF_DAEMON_URL"]
  register Sinatra::TrustForge
end
```

## Test

```sh
bundle install
bundle exec rspec
```
