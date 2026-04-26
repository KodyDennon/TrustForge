require "./spec_helper"

# A terminal handler used as `next` for our middleware in tests. Records
# whether it was invoked and writes a marker body when it runs.
class MarkerHandler
  include HTTP::Handler

  property called : Bool = false

  def call(context : HTTP::Server::Context)
    @called = true
    context.response.status_code = 200
    context.response.print("next-ran")
  end
end

# Wires `mw` -> `terminal` so we can drive a single request through the chain.
def chain(mw : TrustForge::Kemal::Middleware) : MarkerHandler
  terminal = MarkerHandler.new
  mw.next = terminal
  terminal
end

private def make_client(stub : StubTransport) : TrustForge::Client
  TrustForge::Client.new("http://127.0.0.1:8787", transport: stub)
end

describe TrustForge::Kemal::Middleware do
  it "passes through when allowed" do
    stub = StubTransport.json({"decision" => "allow"})
    mw = TrustForge::Kemal::Middleware.new(make_client(stub), action: "x")
    terminal = chain(mw)
    ctx, _ = build_context
    mw.call(ctx)
    terminal.called.should be_true
    ctx.response.status_code.should eq(200)
  end

  it "writes 403 on deny" do
    stub = StubTransport.json({
      "decision" => "deny",
      "reason"   => "blocked",
      "proof_id" => "p-9",
    })
    mw = TrustForge::Kemal::Middleware.new(make_client(stub), action: "x")
    terminal = chain(mw)
    ctx, _ = build_context(method: "POST", path: "/admin")
    mw.call(ctx)
    terminal.called.should be_false
    ctx.response.status_code.should eq(403)
  end

  it "writes 202 + x-tf-approval-id on approval-required" do
    stub = StubTransport.json({
      "decision"    => "approval-required",
      "approval_id" => "appr-7",
    })
    mw = TrustForge::Kemal::Middleware.new(make_client(stub), action: "x")
    terminal = chain(mw)
    ctx, _ = build_context(method: "POST")
    mw.call(ctx)
    terminal.called.should be_false
    ctx.response.status_code.should eq(202)
    ctx.response.headers["x-tf-approval-id"]?.should eq("appr-7")
  end

  it "writes 503 on daemon error in enforce mode" do
    stub = StubTransport.new.with_error(TrustForge::Error.new("boom"))
    mw = TrustForge::Kemal::Middleware.new(make_client(stub), action: "x")
    terminal = chain(mw)
    ctx, _ = build_context
    mw.call(ctx)
    terminal.called.should be_false
    ctx.response.status_code.should eq(503)
  end

  it "passes through on deny in observe-only mode" do
    stub = StubTransport.json({"decision" => "deny", "reason" => "would-block"})
    mw = TrustForge::Kemal::Middleware.new(
      make_client(stub),
      action: "x",
      mode: TrustForge::AdapterMode::ObserveOnly
    )
    terminal = chain(mw)
    ctx, _ = build_context
    mw.call(ctx)
    terminal.called.should be_true
    ctx.response.status_code.should eq(200)
  end

  it "passes through on daemon error in observe-only mode" do
    stub = StubTransport.new.with_error(TrustForge::Error.new("network down"))
    mw = TrustForge::Kemal::Middleware.new(
      make_client(stub),
      action: "x",
      mode: TrustForge::AdapterMode::ObserveOnly
    )
    terminal = chain(mw)
    ctx, _ = build_context
    mw.call(ctx)
    terminal.called.should be_true
  end

  it "uses ActionResolver to derive per-request action" do
    stub = StubTransport.json({"decision" => "allow"})
    resolver = TrustForge::Kemal::Middleware::ActionResolver.new do |c|
      "verb." + c.request.method.downcase
    end
    mw = TrustForge::Kemal::Middleware.new(make_client(stub), action: resolver)
    chain(mw)
    ctx, _ = build_context(method: "DELETE")
    mw.call(ctx)
    body = JSON.parse(stub.captured_body.not_nil!)
    body["action"].as_s.should eq("verb.delete")
  end

  it "extracts bearer token and emits trace_id from header" do
    stub = StubTransport.json({"decision" => "allow"})
    mw = TrustForge::Kemal::Middleware.new(make_client(stub), action: "x")
    chain(mw)
    ctx, _ = build_context(
      method: "GET",
      path: "/r",
      headers: {
        "authorization"  => "Bearer my-token",
        "x-tf-trace-id"  => "tf-fixed-1",
      }
    )
    mw.call(ctx)
    body = JSON.parse(stub.captured_body.not_nil!)
    body["host_token"].as_s.should eq("my-token")
    body["host_token_kind"].as_s.should eq("bearer-opaque")
    body["trace_id"].as_s.should eq("tf-fixed-1")
  end

  it "invokes on_decision callback with the decision" do
    stub = StubTransport.json({"decision" => "allow", "proof_id" => "p-call"})
    captured : TrustForge::DecideResponse? = nil
    cb = TrustForge::Kemal::Middleware::DecisionCallback.new do |_ctx, r|
      captured = r
      nil
    end
    mw = TrustForge::Kemal::Middleware.new(
      make_client(stub),
      action: "x",
      on_decision: cb
    )
    chain(mw)
    ctx, _ = build_context
    mw.call(ctx)
    captured.should_not be_nil
    captured.not_nil!.proof_id.should eq("p-call")
  end
end
