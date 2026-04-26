## TrustForge shared HTTP client + framework helpers for Nim.
##
## Speaks ``POST /v1/decide`` against a local ``tf-daemon``. The shared
## :type:`Client` uses :ref:`std/httpclient` so it works without any
## third-party dependency. ``newJesterMiddleware`` and
## ``newHttpBeastMiddleware`` adapt the client to those frameworks.

import std/[httpclient, json, options, strutils, times, uri]

type
  Mode* = enum
    mEnforce, mObserveOnly

  Decision* = enum
    dAllow, dDeny, dApprovalRequired, dEscalate, dLogOnly, dUnknown

  Config* = object
    daemonUrl*: string
    adminToken*: Option[string]
    mode*: Mode
    timeoutMs*: int

  DecideRequest* = object
    action*: string
    hostToken*: Option[string]
    hostTokenKind*: Option[string]
    target*: Option[string]
    traceId*: Option[string]

  DecideResponse* = object
    decision*: Decision
    reason*: string
    proofId*: string
    approvalId*: Option[string]
    dangerTags*: seq[string]

  TrustforgeErrorKind* = enum
    teDaemonUnavailable, teDaemonRejected, teInvalidResponse

  TrustforgeError* = object of CatchableError
    kind*: TrustforgeErrorKind
    code*: int

  Client* = ref object
    config*: Config

proc defaultConfig*(): Config =
  Config(
    daemonUrl: "http://127.0.0.1:8787",
    adminToken: none(string),
    mode: mEnforce,
    timeoutMs: 5000,
  )

proc newClient*(config: Config = defaultConfig()): Client =
  Client(config: config)

proc parseDecision*(s: string): Decision =
  case s
  of "allow": dAllow
  of "deny": dDeny
  of "approval-required": dApprovalRequired
  of "escalate": dEscalate
  of "log-only": dLogOnly
  else: dUnknown

proc decisionToString*(d: Decision): string =
  case d
  of dAllow: "allow"
  of dDeny: "deny"
  of dApprovalRequired: "approval-required"
  of dEscalate: "escalate"
  of dLogOnly: "log-only"
  of dUnknown: "unknown"

proc newRequest*(action: string;
                 hostToken: Option[string] = none(string);
                 hostTokenKind: Option[string] = none(string);
                 target: Option[string] = none(string);
                 traceId: Option[string] = none(string)): DecideRequest =
  DecideRequest(
    action: action,
    hostToken: hostToken,
    hostTokenKind: hostTokenKind,
    target: target,
    traceId: traceId,
  )

proc encodeRequestBody*(req: DecideRequest): string =
  var node = newJObject()
  node["action"] = %req.action
  if req.hostToken.isSome: node["host_token"] = %req.hostToken.get()
  if req.hostTokenKind.isSome:
    node["host_token_kind"] = %req.hostTokenKind.get()
  if req.target.isSome: node["target"] = %req.target.get()
  if req.traceId.isSome: node["trace_id"] = %req.traceId.get()
  $node

proc parseResponseBody*(body: string): DecideResponse =
  let node =
    try: parseJson(body)
    except JsonParsingError as e:
      var err = newException(TrustforgeError, "invalid response: " & e.msg)
      err.kind = teInvalidResponse
      raise err
  result.decision =
    if node.hasKey("decision"):
      parseDecision(node["decision"].getStr())
    else: dUnknown
  result.reason = node{"reason"}.getStr("")
  result.proofId = node{"proof_id"}.getStr("")
  if node.hasKey("approval_id") and node["approval_id"].kind == JString:
    result.approvalId = some(node["approval_id"].getStr())
  if node.hasKey("danger_tags") and node["danger_tags"].kind == JArray:
    for item in node["danger_tags"]:
      if item.kind == JString:
        result.dangerTags.add(item.getStr())

proc extractBearer*(header: string): Option[string] =
  if header.len <= 7: return none(string)
  let prefix = header[0 .. 6]
  if not prefix.toLowerAscii().startsWith("bearer "):
    return none(string)
  let raw = header[7 .. ^1].strip()
  if raw.len == 0: none(string) else: some(raw)

proc decide*(client: Client; req: DecideRequest): DecideResponse =
  ## Perform a synchronous ``POST /v1/decide`` call.
  let body = encodeRequestBody(req)
  let url = client.config.daemonUrl & "/v1/decide"

  var http = newHttpClient(timeout = client.config.timeoutMs)
  defer: http.close()

  http.headers = newHttpHeaders({"content-type": "application/json"})
  if client.config.adminToken.isSome:
    http.headers["authorization"] = "Bearer " & client.config.adminToken.get()

  let resp =
    try:
      http.request(url, httpMethod = HttpPost, body = body)
    except CatchableError as e:
      var err = newException(TrustforgeError,
        "daemon unavailable: " & e.msg)
      err.kind = teDaemonUnavailable
      raise err

  let code = parseInt(resp.status.split(" ")[0])
  if code >= 500:
    var err = newException(TrustforgeError,
      "daemon unavailable: status " & $code)
    err.kind = teDaemonUnavailable
    err.code = code
    raise err
  if code >= 400:
    var err = newException(TrustforgeError,
      "daemon rejected: status " & $code)
    err.kind = teDaemonRejected
    err.code = code
    raise err
  parseResponseBody(resp.body)

# ---------------------------------------------------------------------------
# Framework helpers (HttpBeast / Jester)
# ---------------------------------------------------------------------------

type
  MiddlewareDecision* = enum
    mdAllow, mdShortCircuit

  MiddlewareResult* = object
    decision*: MiddlewareDecision
    statusCode*: int
    body*: string
    headers*: seq[(string, string)]

proc evaluate*(client: Client; req: DecideRequest): MiddlewareResult =
  ## Pure helper that frameworks use to translate a request into a
  ## ``MiddlewareResult``. Not framework-specific.
  try:
    let resp = decide(client, req)
    case resp.decision
    of dAllow, dLogOnly:
      MiddlewareResult(decision: mdAllow)
    of dDeny:
      MiddlewareResult(
        decision: mdShortCircuit,
        statusCode: 403,
        body: "{\"decision\":\"deny\"}",
        headers: @[("content-type", "application/json")],
      )
    of dApprovalRequired, dEscalate:
      var hdrs = @[("content-type", "application/json")]
      if resp.approvalId.isSome:
        hdrs.add(("x-tf-approval-id", resp.approvalId.get()))
      MiddlewareResult(
        decision: mdShortCircuit,
        statusCode: 202,
        body: "{\"decision\":\"approval-required\"}",
        headers: hdrs,
      )
    of dUnknown:
      MiddlewareResult(
        decision: mdShortCircuit,
        statusCode: 503,
        body: "{\"decision\":\"unknown\"}",
        headers: @[("content-type", "application/json")],
      )
  except TrustforgeError as e:
    case client.config.mode
    of mObserveOnly:
      MiddlewareResult(decision: mdAllow)
    of mEnforce:
      MiddlewareResult(
        decision: mdShortCircuit,
        statusCode: 503,
        body: "{\"error\":\"trustforge:" & e.msg & "\"}",
        headers: @[("content-type", "application/json")],
      )

type
  HeaderLookup* = proc (name: string): string {.closure.}

proc buildRequestFromHeaders*(action: string;
                              path: string;
                              lookup: HeaderLookup): DecideRequest =
  let auth = lookup("authorization")
  let trace = lookup("x-tf-trace-id")
  result = newRequest(action)
  result.target = some(path)
  if auth.len > 0:
    let bearer = extractBearer(auth)
    if bearer.isSome:
      result.hostToken = bearer
  if trace.len > 0:
    result.traceId = some(trace)

template newJesterMiddleware*(client: Client; action: string): untyped =
  ## Returns a Jester middleware function. Users invoke it inside
  ## their route bodies via ``before:``. We return a closure rather
  ## than touching ``jester`` directly so this module compiles
  ## without Jester installed.
  proc(path: string; getHeader: HeaderLookup): MiddlewareResult =
    let req = buildRequestFromHeaders(action, path, getHeader)
    evaluate(client, req)

template newHttpBeastMiddleware*(client: Client; action: string): untyped =
  ## Same shape as the Jester helper but suitable for HttpBeast's raw
  ## request handler. The user is expected to translate
  ## ``MiddlewareResult.shortCircuit`` into a ``send(...)`` call.
  proc(path: string; getHeader: HeaderLookup): MiddlewareResult =
    let req = buildRequestFromHeaders(action, path, getHeader)
    evaluate(client, req)
