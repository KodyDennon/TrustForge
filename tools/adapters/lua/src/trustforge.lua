--[[ TrustForge shared HTTP client for Lua.

Speaks `POST /v1/decide` against a local tf-daemon. Two HTTP backends
are auto-selected at runtime:

  * `lua-resty-http`  (when running under OpenResty / nginx-Lua)
  * `socket.http`     (vanilla Lua, used for unit tests)

The client returns `(decision_table, nil)` on success or
`(nil, err_table)` on failure. Frameworks layer on top of `decide`.
]]

local json = require("dkjson")

local M = {}

M.MODE_ENFORCE      = "enforce"
M.MODE_OBSERVE_ONLY = "observe-only"

M.DECISIONS = {
  ALLOW              = "allow",
  DENY               = "deny",
  APPROVAL_REQUIRED  = "approval-required",
  ESCALATE           = "escalate",
  LOG_ONLY           = "log-only",
}

local default_config = {
  daemon_url  = "http://127.0.0.1:8787",
  admin_token = nil,
  mode        = M.MODE_ENFORCE,
  timeout_ms  = 5000,
}

-- ----- helpers -------------------------------------------------------------

local function shallow_merge(a, b)
  local out = {}
  for k, v in pairs(a) do out[k] = v end
  for k, v in pairs(b or {}) do out[k] = v end
  return out
end

--- Build a JSON body from a request table.
function M.encode_request_body(req)
  assert(type(req) == "table", "req must be a table")
  assert(type(req.action) == "string", "req.action is required")
  local body = { action = req.action }
  if req.host_token      then body.host_token      = req.host_token end
  if req.host_token_kind then body.host_token_kind = req.host_token_kind end
  if req.target          then body.target          = req.target end
  if req.trace_id        then body.trace_id        = req.trace_id end
  return json.encode(body)
end

--- Parse a response body. Returns (response_table, nil) or (nil, err).
function M.parse_response_body(body)
  local obj, _, err = json.decode(body)
  if err then
    return nil, { kind = "invalid-response", message = err }
  end
  if type(obj) ~= "table" then
    return nil, { kind = "invalid-response", message = "not an object" }
  end
  local danger_tags = {}
  if type(obj.danger_tags) == "table" then
    for _, v in ipairs(obj.danger_tags) do
      if type(v) == "string" then table.insert(danger_tags, v) end
    end
  end
  return {
    decision    = obj.decision    or "unknown",
    reason      = obj.reason      or "",
    proof_id    = obj.proof_id    or "",
    approval_id = obj.approval_id,
    danger_tags = danger_tags,
  }, nil
end

--- Extract a Bearer token from an Authorization header value.
function M.extract_bearer(header)
  if type(header) ~= "string" then return nil end
  if #header <= 7 then return nil end
  local prefix = header:sub(1, 7):lower()
  if prefix ~= "bearer " then return nil end
  local raw = header:sub(8)
  -- trim
  raw = raw:gsub("^%s+", ""):gsub("%s+$", "")
  if raw == "" then return nil end
  return raw
end

-- ----- HTTP backends -------------------------------------------------------

local function http_with_resty(url, body, headers, timeout_ms)
  local ok, http = pcall(require, "resty.http")
  if not ok then return nil, "resty-http-not-available" end
  local cli = http.new()
  cli:set_timeout(timeout_ms)
  local res, err = cli:request_uri(url, {
    method  = "POST",
    body    = body,
    headers = headers,
  })
  if not res then return nil, err end
  return { status = res.status, body = res.body }
end

local function http_with_socket(url, body, headers, timeout_ms)
  local ok_http, http = pcall(require, "socket.http")
  if not ok_http then return nil, "socket-http-not-available" end
  local ok_ltn12, ltn12 = pcall(require, "ltn12")
  if not ok_ltn12 then return nil, "ltn12-not-available" end
  http.TIMEOUT = math.max(1, math.floor(timeout_ms / 1000))
  local resp_body = {}
  local _, code = http.request{
    url = url,
    method = "POST",
    headers = headers,
    source = ltn12.source.string(body),
    sink   = ltn12.sink.table(resp_body),
  }
  return { status = code, body = table.concat(resp_body) }
end

-- ----- public API ----------------------------------------------------------

local Client = {}
Client.__index = Client

function M.new_client(config)
  local cfg = shallow_merge(default_config, config)
  return setmetatable({ config = cfg, _http_backend = nil }, Client)
end

--- Override the HTTP backend (used by tests).
function Client:set_backend(fn)
  self._http_backend = fn
end

function Client:_pick_backend()
  if self._http_backend then return self._http_backend end
  if ngx and ngx.var then return http_with_resty end
  return http_with_socket
end

function Client:decide(req)
  local body = M.encode_request_body(req)
  local url = self.config.daemon_url .. "/v1/decide"
  local headers = { ["content-type"] = "application/json" }
  if self.config.admin_token then
    headers["authorization"] = "Bearer " .. self.config.admin_token
  end
  local res, err = self:_pick_backend()(
    url, body, headers, self.config.timeout_ms)
  if not res then
    return nil, { kind = "daemon-unavailable", message = err }
  end
  if res.status >= 500 then
    return nil, { kind = "daemon-unavailable",
                  message = "status " .. tostring(res.status) }
  end
  if res.status >= 400 then
    return nil, { kind = "daemon-rejected",
                  message = res.body, code = res.status }
  end
  return M.parse_response_body(res.body)
end

M.Client = Client

--- Map a parsed `DecideResponse` to a (status, headers, body) triple
--- describing how the framework should reply (or nil if it should
--- just continue to the inner handler).
function M.decision_response(resp)
  local d = resp.decision
  if d == M.DECISIONS.ALLOW or d == M.DECISIONS.LOG_ONLY then
    return nil
  elseif d == M.DECISIONS.DENY then
    return 403, { ["content-type"] = "application/json" },
           '{"decision":"deny"}'
  elseif d == M.DECISIONS.APPROVAL_REQUIRED or d == M.DECISIONS.ESCALATE then
    local hdrs = { ["content-type"] = "application/json" }
    if resp.approval_id then hdrs["x-tf-approval-id"] = resp.approval_id end
    return 202, hdrs, '{"decision":"approval-required"}'
  else
    return 503, { ["content-type"] = "application/json" },
           '{"decision":"unknown"}'
  end
end

--- Build a `DecideRequest` from a (action, path, header-lookup) tuple.
--- Used by the OpenResty middleware and by tests.
function M.build_request_from_headers(action, path, get_header)
  local req = { action = action, target = path }
  local auth = get_header("authorization") or get_header("Authorization")
  if auth then
    local bearer = M.extract_bearer(auth)
    if bearer then req.host_token = bearer end
  end
  local trace = get_header("x-tf-trace-id") or get_header("X-TF-Trace-Id")
  if trace then req.trace_id = trace end
  return req
end

return M
