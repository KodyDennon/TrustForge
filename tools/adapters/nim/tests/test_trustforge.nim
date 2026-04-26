import std/[options, unittest, strutils, tables]
import trustforge

suite "decisions":
  test "round-trip":
    check parseDecision("allow") == dAllow
    check parseDecision("deny") == dDeny
    check parseDecision("approval-required") == dApprovalRequired
    check parseDecision("escalate") == dEscalate
    check parseDecision("log-only") == dLogOnly
    check parseDecision("nope") == dUnknown
    check decisionToString(dAllow) == "allow"
    check decisionToString(dApprovalRequired) == "approval-required"

suite "encodeRequestBody":
  test "minimal":
    let body = encodeRequestBody(newRequest("fs.read"))
    check body.contains("fs.read")
    check not body.contains("host_token")
    check not body.contains("target")

  test "full":
    let req = newRequest(
      "net.connect",
      hostToken = some("abc"),
      hostTokenKind = some("session"),
      target = some("/x"),
      traceId = some("tf-1"),
    )
    let body = encodeRequestBody(req)
    check body.contains("\"host_token\":\"abc\"")
    check body.contains("\"host_token_kind\":\"session\"")
    check body.contains("\"target\":\"/x\"")
    check body.contains("\"trace_id\":\"tf-1\"")

suite "parseResponseBody":
  test "allow":
    let body = """{"decision":"allow","reason":"ok","proof_id":"p1","danger_tags":["fs.read","sensitive"]}"""
    let r = parseResponseBody(body)
    check r.decision == dAllow
    check r.reason == "ok"
    check r.proofId == "p1"
    check r.approvalId.isNone
    check r.dangerTags == @["fs.read", "sensitive"]

  test "approval-required":
    let body = """{"decision":"approval-required","reason":"need","proof_id":"p2","approval_id":"a-9","danger_tags":[]}"""
    let r = parseResponseBody(body)
    check r.decision == dApprovalRequired
    check r.approvalId.isSome
    check r.approvalId.get() == "a-9"

  test "missing fields":
    let body = """{"decision":"deny"}"""
    let r = parseResponseBody(body)
    check r.decision == dDeny
    check r.reason == ""
    check r.proofId == ""

  test "invalid raises":
    expect TrustforgeError:
      discard parseResponseBody("not json")

suite "extractBearer":
  test "case-insensitive":
    check extractBearer("Bearer abc") == some("abc")
    check extractBearer("bearer xyz") == some("xyz")
  test "trim":
    check extractBearer("Bearer  tok  ") == some("tok")
  test "rejects empty":
    check extractBearer("Bearer ") == none(string)
  test "rejects basic":
    check extractBearer("Basic abc") == none(string)

suite "evaluate":
  let client = newClient(Config(
    daemonUrl: "http://127.0.0.1:1",
    mode: mObserveOnly,
    timeoutMs: 200,
  ))

  test "observe-only on daemon failure":
    let res = evaluate(client, newRequest("fs.read"))
    check res.decision == mdAllow

  test "enforce returns 503 on daemon failure":
    let strict = newClient(Config(
      daemonUrl: "http://127.0.0.1:1",
      mode: mEnforce,
      timeoutMs: 200,
    ))
    let res = evaluate(strict, newRequest("fs.read"))
    check res.decision == mdShortCircuit
    check res.statusCode == 503

suite "buildRequestFromHeaders":
  test "extracts bearer + trace":
    var hdrs = initTable[string, string]()
    hdrs["authorization"] = "Bearer abc"
    hdrs["x-tf-trace-id"] = "tf-9"
    proc lookup(name: string): string =
      hdrs.getOrDefault(name, "")
    let req = buildRequestFromHeaders("fs.read", "/x", lookup)
    check req.action == "fs.read"
    check req.hostToken == some("abc")
    check req.traceId == some("tf-9")
    check req.target == some("/x")
