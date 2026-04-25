# trustforge (Ruby Rack middleware)

Rack middleware that gates every request through `tf-daemon`'s `/v1/decide`
endpoint.

## Install

```ruby
# Gemfile
gem "trustforge", "~> 0.1"
```

```sh
bundle install
```

## Usage

```ruby
require "trustforge"

client = TrustForge::Client.new(daemon_url: "http://127.0.0.1:8731")

use TrustForge::Rack,
    client: client,
    action: ->(env) { "http.#{env['REQUEST_METHOD'].downcase}" },
    mode: :enforce
```

## Test

```sh
bundle install
bundle exec rspec
```

Requires Ruby ≥ 2.6 and the `rspec` + `rack-test` dev gems.
