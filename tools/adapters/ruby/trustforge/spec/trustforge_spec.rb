# frozen_string_literal: true

require "json"
require "rack/test"
require_relative "../lib/trustforge"

RSpec.describe TrustForge do
  let(:inner_app) do
    ->(_env) { [200, { "content-type" => "text/plain" }, ["ok"]] }
  end

  def fake_client(decision:, reason: "", raise_error: nil)
    client = Object.new
    client.define_singleton_method(:decide) do |req|
      raise raise_error if raise_error
      @last_req = req
      TrustForge::DecideResponse.new(
        "decision" => decision, "reason" => reason, "proof_id" => "p1"
      )
    end
    client.define_singleton_method(:last_req) { @last_req }
    client
  end

  it "DecideRequest serializes to a hash with required fields" do
    r = TrustForge::DecideRequest.new(
      action: "fs.read", trace_id: "trace-1", actor: "tf:actor:agent:example.com/x"
    )
    h = r.to_h
    expect(h["action"]).to eq("fs.read")
    expect(h["trace_id"]).to eq("trace-1")
    expect(h["actor"]).to eq("tf:actor:agent:example.com/x")
    expect(h["context"]).to eq({})
  end

  it "DecideRequest rejects empty action" do
    expect { TrustForge::DecideRequest.new(action: "", trace_id: "t") }
      .to raise_error(ArgumentError)
  end

  it "Rack middleware forwards an allow decision and exposes it on env" do
    client = fake_client(decision: "allow")
    app = TrustForge::Rack.new(inner_app, client: client)
    mock = Rack::MockRequest.new(app)
    res = mock.get("/widgets")
    expect(res.status).to eq(200)
    expect(client.last_req.action).to eq("http.get")
    expect(client.last_req.target).to eq("/widgets")
  end

  it "Rack middleware blocks on deny in enforce mode" do
    client = fake_client(decision: "deny", reason: "policy")
    app = TrustForge::Rack.new(inner_app, client: client, mode: :enforce)
    mock = Rack::MockRequest.new(app)
    res = mock.post("/admin")
    expect(res.status).to eq(403)
    body = JSON.parse(res.body)
    expect(body["decision"]).to eq("deny")
    expect(body["reason"]).to eq("policy")
  end

  it "Rack middleware allows requests in observe-only mode even on deny" do
    client = fake_client(decision: "deny")
    app = TrustForge::Rack.new(inner_app, client: client, mode: :"observe-only")
    mock = Rack::MockRequest.new(app)
    res = mock.get("/")
    expect(res.status).to eq(200)
  end
end
