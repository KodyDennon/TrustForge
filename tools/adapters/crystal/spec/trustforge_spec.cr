require "./spec_helper"

describe TrustForge do
  describe "#decide" do
    it "returns parsed response on 200" do
      stub = StubTransport.json({
        "decision"    => "allow",
        "proof_id"    => "p-1",
        "danger_tags" => ["fs"],
      })
      client = TrustForge::Client.new("http://127.0.0.1:8787", transport: stub)
      req = TrustForge::DecideRequest.new(action: "fs.read", trace_id: "tf-1")
      r = client.decide(req)
      r.decision.should eq("allow")
      r.proof_id.should eq("p-1")
      r.danger_tags.should eq(["fs"])
      r.allow?.should be_true
    end

    it "raises Error on 4xx" do
      stub = StubTransport.json({"decision" => "deny"}, status: 403)
      client = TrustForge::Client.new("http://127.0.0.1:8787", transport: stub)
      req = TrustForge::DecideRequest.new(action: "x", trace_id: "t")
      expect_raises(TrustForge::Error, /403/) do
        client.decide(req)
      end
    end

    it "raises Error on transport failure" do
      stub = StubTransport.new.with_error(TrustForge::Error.new("boom", 0, nil))
      client = TrustForge::Client.new("http://127.0.0.1:8787", transport: stub)
      req = TrustForge::DecideRequest.new(action: "x", trace_id: "t")
      expect_raises(TrustForge::Error, /boom/) do
        client.decide(req)
      end
    end

    it "sends correctly shaped JSON and headers" do
      stub = StubTransport.json({"decision" => "allow"})
      client = TrustForge::Client.new(
        "http://127.0.0.1:8787/",
        admin_token: "ADMIN",
        transport: stub
      )
      req = TrustForge::DecideRequest.new(
        action: "fs.read",
        trace_id: "tf-xyz",
        target: "/etc/hosts",
        host_token: "abc.def",
        host_token_kind: "oauth-jwt"
      )
      client.decide(req)

      stub.captured_url.should eq("http://127.0.0.1:8787/v1/decide")
      stub.captured_method.should eq("POST")
      stub.captured_headers["authorization"]?.should eq("Bearer ADMIN")
      stub.captured_headers["content-type"]?.should eq("application/json")

      body = JSON.parse(stub.captured_body.not_nil!)
      body["action"].as_s.should eq("fs.read")
      body["trace_id"].as_s.should eq("tf-xyz")
      body["host_token"].as_s.should eq("abc.def")
      body["host_token_kind"].as_s.should eq("oauth-jwt")
      body["target"].as_s.should eq("/etc/hosts")
      body.as_h.has_key?("actor").should be_false
    end
  end

  describe "#evaluate" do
    it "maps verbs to symbols" do
      cases = {
        "allow"             => :allow,
        "deny"              => :deny,
        "approval-required" => :approval_required,
        "escalate"          => :approval_required,
        "log-only"          => :log_only,
        "weird"             => :deny,
      }
      cases.each do |verb, expected|
        stub = StubTransport.json({"decision" => verb})
        client = TrustForge::Client.new("http://127.0.0.1:8787", transport: stub)
        req = TrustForge::DecideRequest.new(action: "x", trace_id: "t")
        tag, _ = client.evaluate(req)
        tag.should eq(expected)
      end
    end
  end

  describe ".new_trace_id" do
    it "produces a tf- prefixed id" do
      id = TrustForge.new_trace_id
      id.starts_with?("tf-").should be_true
      id.size.should eq(3 + 16)
    end
  end

  describe ".extract_bearer" do
    it "parses well-formed bearer header" do
      tok, kind = TrustForge.extract_bearer("Bearer abc.def")
      tok.should eq("abc.def")
      kind.should eq("bearer-opaque")
    end

    it "is case-insensitive" do
      tok, _ = TrustForge.extract_bearer("bearer xyz")
      tok.should eq("xyz")
    end

    it "returns nil for malformed/missing header" do
      tok, _ = TrustForge.extract_bearer(nil)
      tok.should be_nil

      tok2, _ = TrustForge.extract_bearer("Basic abc")
      tok2.should be_nil
    end
  end

  describe "DecideResponse decoding" do
    it "is lenient about missing fields" do
      r = TrustForge::DecideResponse.from_json(%({"decision":"allow"}))
      r.decision.should eq("allow")
      r.reason.should eq("")
      r.proof_id.should eq("")
      r.authority_mode.should eq("layered")
      r.danger_tags.should eq([] of String)
    end
  end
end
