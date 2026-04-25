# frozen_string_literal: true

$LOAD_PATH.unshift File.expand_path("../../trustforge/lib", __dir__)
$LOAD_PATH.unshift File.expand_path("../lib", __dir__)
require "json"
require "rack/mock"
require "trustforge/hanami"

RSpec.describe TrustForge::Hanami::Middleware do
  let(:inner) { ->(_env) { [200, { "content-type" => "text/plain" }, ["ok"]] } }

  def fake_client(decision:)
    c = Object.new
    c.define_singleton_method(:decide) do |_req|
      TrustForge::DecideResponse.new("decision" => decision, "proof_id" => "p1")
    end
    c
  end

  it "is the same class as TrustForge::Rack (Rack-compatible)" do
    expect(described_class).to eq(TrustForge::Rack)
  end

  it "allows requests when decision is allow" do
    app = described_class.new(inner, client: fake_client(decision: "allow"))
    res = Rack::MockRequest.new(app).get("/")
    expect(res.status).to eq(200)
  end

  it "blocks requests when decision is deny" do
    app = described_class.new(inner, client: fake_client(decision: "deny"))
    res = Rack::MockRequest.new(app).get("/")
    expect(res.status).to eq(403)
  end
end
