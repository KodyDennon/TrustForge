-- Run with `busted spec/trustforge_spec.lua` (or `busted` in this dir).

package.path = "src/?.lua;src/?/init.lua;" .. package.path

local trustforge = require("trustforge")

describe("decision constants", function()
  it("exposes all canonical decisions", function()
    assert.equal("allow", trustforge.DECISIONS.ALLOW)
    assert.equal("deny", trustforge.DECISIONS.DENY)
    assert.equal("approval-required", trustforge.DECISIONS.APPROVAL_REQUIRED)
    assert.equal("escalate", trustforge.DECISIONS.ESCALATE)
    assert.equal("log-only", trustforge.DECISIONS.LOG_ONLY)
  end)
end)

describe("encode_request_body", function()
  it("includes only the action when no extras are set", function()
    local body = trustforge.encode_request_body({ action = "fs.read" })
    assert.is_truthy(body:find("fs.read", 1, true))
    assert.is_nil(body:find("host_token", 1, true))
    assert.is_nil(body:find("target", 1, true))
  end)

  it("includes optional fields when provided", function()
    local body = trustforge.encode_request_body({
      action = "net.connect",
      host_token = "abc",
      host_token_kind = "session",
      target = "/x",
      trace_id = "tf-1",
    })
    assert.is_truthy(body:find('"host_token":"abc"', 1, true))
    assert.is_truthy(body:find('"host_token_kind":"session"', 1, true))
    assert.is_truthy(body:find('"target":"/x"', 1, true))
    assert.is_truthy(body:find('"trace_id":"tf-1"', 1, true))
  end)

  it("rejects requests without action", function()
    assert.has_error(function()
      trustforge.encode_request_body({})
    end)
  end)
end)

describe("parse_response_body", function()
  it("parses an allow", function()
    local body = '{"decision":"allow","reason":"ok","proof_id":"p1","danger_tags":["fs.read"]}'
    local r, err = trustforge.parse_response_body(body)
    assert.is_nil(err)
    assert.equal("allow", r.decision)
    assert.equal("p1", r.proof_id)
    assert.same({ "fs.read" }, r.danger_tags)
  end)

  it("parses approval-required with id", function()
    local body = '{"decision":"approval-required","reason":"need","proof_id":"p2","approval_id":"a-9"}'
    local r = trustforge.parse_response_body(body)
    assert.equal("approval-required", r.decision)
    assert.equal("a-9", r.approval_id)
  end)

  it("rejects malformed JSON", function()
    local r, err = trustforge.parse_response_body("not json")
    assert.is_nil(r)
    assert.is_table(err)
    assert.equal("invalid-response", err.kind)
  end)
end)

describe("extract_bearer", function()
  it("handles case-insensitive prefix", function()
    assert.equal("abc", trustforge.extract_bearer("Bearer abc"))
    assert.equal("xyz", trustforge.extract_bearer("bearer xyz"))
  end)
  it("trims whitespace", function()
    assert.equal("tok", trustforge.extract_bearer("Bearer  tok  "))
  end)
  it("rejects empty", function()
    assert.is_nil(trustforge.extract_bearer("Bearer "))
  end)
  it("rejects non-bearer", function()
    assert.is_nil(trustforge.extract_bearer("Basic abc"))
  end)
end)

describe("decision_response", function()
  it("allow -> nil", function()
    assert.is_nil(trustforge.decision_response({ decision = "allow" }))
    assert.is_nil(trustforge.decision_response({ decision = "log-only" }))
  end)
  it("deny -> 403", function()
    local s = trustforge.decision_response({ decision = "deny" })
    assert.equal(403, s)
  end)
  it("approval-required -> 202 with header", function()
    local s, h = trustforge.decision_response({
      decision = "approval-required", approval_id = "a-1",
    })
    assert.equal(202, s)
    assert.equal("a-1", h["x-tf-approval-id"])
  end)
  it("unknown -> 503", function()
    local s = trustforge.decision_response({ decision = "wat" })
    assert.equal(503, s)
  end)
end)

describe("Client.decide with stub backend", function()
  it("returns parsed response on 200", function()
    local c = trustforge.new_client()
    c:set_backend(function()
      return {
        status = 200,
        body = '{"decision":"allow","reason":"","proof_id":"p"}',
      }
    end)
    local r, err = c:decide({ action = "fs.read" })
    assert.is_nil(err)
    assert.equal("allow", r.decision)
  end)

  it("maps 503 to daemon-unavailable", function()
    local c = trustforge.new_client()
    c:set_backend(function()
      return { status = 503, body = "boom" }
    end)
    local r, err = c:decide({ action = "fs.read" })
    assert.is_nil(r)
    assert.equal("daemon-unavailable", err.kind)
  end)

  it("maps 401 to daemon-rejected", function()
    local c = trustforge.new_client()
    c:set_backend(function()
      return { status = 401, body = "no" }
    end)
    local r, err = c:decide({ action = "fs.read" })
    assert.is_nil(r)
    assert.equal("daemon-rejected", err.kind)
    assert.equal(401, err.code)
  end)
end)

describe("build_request_from_headers", function()
  it("extracts bearer + trace + path", function()
    local headers = {
      ["authorization"] = "Bearer abc",
      ["x-tf-trace-id"] = "tf-9",
    }
    local req = trustforge.build_request_from_headers(
      "fs.read", "/x", function(n) return headers[n] end)
    assert.equal("fs.read", req.action)
    assert.equal("abc", req.host_token)
    assert.equal("tf-9", req.trace_id)
    assert.equal("/x", req.target)
  end)
end)
