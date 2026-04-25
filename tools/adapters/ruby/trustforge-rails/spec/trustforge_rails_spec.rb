# frozen_string_literal: true

$LOAD_PATH.unshift File.expand_path("../../trustforge/lib", __dir__)
$LOAD_PATH.unshift File.expand_path("../lib", __dir__)
require "trustforge/rails"

RSpec.describe TrustForge::Rails do
  it "exposes a Config object with sensible defaults" do
    cfg = TrustForge::Rails::Config.new
    expect(cfg.daemon_url).to be_a(String)
    expect(cfg.mode).to eq(:enforce)
    expect(cfg.enabled).to eq(true)
  end

  it "configure block mutates the singleton config" do
    described_class.configure do |c|
      c.daemon_url = "http://example.invalid"
      c.mode = :"observe-only"
    end
    expect(described_class.config.daemon_url).to eq("http://example.invalid")
    expect(described_class.config.mode).to eq(:"observe-only")
  end

  it "build_middleware_args returns a usable client + mode" do
    described_class.configure do |c|
      c.daemon_url = "http://127.0.0.1:8731"
      c.mode = :enforce
    end
    args = described_class.build_middleware_args
    expect(args[:client]).to be_a(TrustForge::Client)
    expect(args[:mode]).to eq(:enforce)
  end
end
