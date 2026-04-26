require "./spec_helper"

describe TrustForge::Lucky do
  it "returns Allow on allow" do
    stub = StubTransport.json({"decision" => "allow", "proof_id" => "p"})
    client = TrustForge::Client.new("http://127.0.0.1:8787", transport: stub)
    outcome = TrustForge::Lucky.authorize(
      client: client,
      action: "x",
      method: "GET",
      path: "/x"
    )
    outcome.should be_a(TrustForge::Lucky::Outcome::Allow)
    outcome.as(TrustForge::Lucky::Outcome::Allow).response.proof_id.should eq("p")
  end

  it "returns Deny on deny in enforce mode" do
    stub = StubTransport.json({"decision" => "deny", "reason" => "no"})
    client = TrustForge::Client.new("http://127.0.0.1:8787", transport: stub)
    outcome = TrustForge::Lucky.authorize(
      client: client,
      action: "x",
      method: "POST",
      path: "/x"
    )
    outcome.should be_a(TrustForge::Lucky::Outcome::Deny)
    outcome.as(TrustForge::Lucky::Outcome::Deny).response.reason.should eq("no")
  end

  it "returns ApprovalRequired on approval-required" do
    stub = StubTransport.json({
      "decision"    => "approval-required",
      "approval_id" => "appr-1",
    })
    client = TrustForge::Client.new("http://127.0.0.1:8787", transport: stub)
    outcome = TrustForge::Lucky.authorize(
      client: client,
      action: "x",
      method: "POST",
      path: "/x"
    )
    outcome.should be_a(TrustForge::Lucky::Outcome::ApprovalRequired)
    outcome.as(TrustForge::Lucky::Outcome::ApprovalRequired).response.approval_id.should eq("appr-1")
  end

  it "returns DaemonError when client raises in enforce mode" do
    stub = StubTransport.new.with_error(TrustForge::Error.new("boom"))
    client = TrustForge::Client.new("http://127.0.0.1:8787", transport: stub)
    outcome = TrustForge::Lucky.authorize(
      client: client,
      action: "x",
      method: "GET",
      path: "/x"
    )
    outcome.should be_a(TrustForge::Lucky::Outcome::DaemonError)
    outcome.as(TrustForge::Lucky::Outcome::DaemonError).error.message.should eq("boom")
  end

  it "in observe-only mode, deny becomes Allow" do
    stub = StubTransport.json({"decision" => "deny"})
    client = TrustForge::Client.new("http://127.0.0.1:8787", transport: stub)
    outcome = TrustForge::Lucky.authorize(
      client: client,
      action: "x",
      method: "GET",
      path: "/x",
      mode: TrustForge::AdapterMode::ObserveOnly
    )
    outcome.should be_a(TrustForge::Lucky::Outcome::Allow)
  end

  it "in observe-only mode, daemon error becomes LogOnly" do
    stub = StubTransport.new.with_error(TrustForge::Error.new("net"))
    client = TrustForge::Client.new("http://127.0.0.1:8787", transport: stub)
    outcome = TrustForge::Lucky.authorize(
      client: client,
      action: "x",
      method: "GET",
      path: "/x",
      mode: TrustForge::AdapterMode::ObserveOnly
    )
    outcome.should be_a(TrustForge::Lucky::Outcome::LogOnly)
  end

  it "extracts bearer token from authorization" do
    stub = StubTransport.json({"decision" => "allow"})
    client = TrustForge::Client.new("http://127.0.0.1:8787", transport: stub)
    TrustForge::Lucky.authorize(
      client: client,
      action: "x",
      method: "POST",
      path: "/x",
      authorization: "Bearer abc.def"
    )
    body = JSON.parse(stub.captured_body.not_nil!)
    body["host_token"].as_s.should eq("abc.def")
    body["host_token_kind"].as_s.should eq("bearer-opaque")
  end

  it "uses cookie session token when no bearer header" do
    stub = StubTransport.json({"decision" => "allow"})
    client = TrustForge::Client.new("http://127.0.0.1:8787", transport: stub)
    TrustForge::Lucky.authorize(
      client: client,
      action: "x",
      method: "GET",
      path: "/x",
      cookie_tf_session: "sess-123"
    )
    body = JSON.parse(stub.captured_body.not_nil!)
    body["host_token"].as_s.should eq("sess-123")
    body["host_token_kind"].as_s.should eq("session-cookie")
  end

  it "uses provided trace header verbatim" do
    stub = StubTransport.json({"decision" => "allow"})
    client = TrustForge::Client.new("http://127.0.0.1:8787", transport: stub)
    TrustForge::Lucky.authorize(
      client: client,
      action: "x",
      method: "GET",
      path: "/x",
      trace_header: "tf-fixed-7"
    )
    body = JSON.parse(stub.captured_body.not_nil!)
    body["trace_id"].as_s.should eq("tf-fixed-7")
  end
end
