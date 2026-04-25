# frozen_string_literal: true

$LOAD_PATH.unshift File.expand_path("../../trustforge/lib", __dir__)
$LOAD_PATH.unshift File.expand_path("../lib", __dir__)
require "trustforge"
require "sinatra/trustforge"

# Stand-in app object that mimics Sinatra's settings DSL just enough.
class FakeSinatraApp
  attr_accessor :settings_hash, :middleware
  def initialize
    @settings_hash = {}
    @middleware = []
  end

  def set(key, value)
    @settings_hash[key] = value
    define_singleton_method(:settings) { OpenStruct.new(@settings_hash) } unless respond_to?(:settings)
  end

  def settings
    OpenStruct.new(@settings_hash)
  end

  def use(klass, **kwargs)
    @middleware << [klass, kwargs]
  end
end

require "ostruct"

RSpec.describe Sinatra::TrustForge do
  it "registers settings on the app" do
    app = FakeSinatraApp.new
    Sinatra::TrustForge.registered(app)
    expect(app.settings.trustforge_daemon_url).to start_with("http")
    expect(app.settings.trustforge_mode).to eq(:enforce)
  end

  it "installs TrustForge::Rack middleware" do
    app = FakeSinatraApp.new
    Sinatra::TrustForge.registered(app)
    klasses = app.middleware.map(&:first)
    expect(klasses).to include(::TrustForge::Rack)
  end

  it "passes a client and mode to the middleware" do
    app = FakeSinatraApp.new
    Sinatra::TrustForge.registered(app)
    _, kwargs = app.middleware.first
    expect(kwargs[:client]).to be_a(::TrustForge::Client)
    expect(kwargs[:mode]).to eq(:enforce)
  end
end
