--[[ OpenResty `access_by_lua` middleware for TrustForge.

Usage (nginx.conf):

    access_by_lua_block {
        local tf = require "trustforge.openresty"
        tf.guard {
          client = my_client,
          action = "http.request",
        }
    }

The `guard()` call short-circuits the request via `ngx.exit(...)`
when the daemon denies / requests approval, and otherwise lets the
request flow to the upstream/content phase.
]]

local trustforge = require("trustforge")

local M = {}

local function ngx_get_header(name)
  if not ngx or not ngx.req then return nil end
  return ngx.req.get_headers()[name]
end

--- Run a TrustForge decision check during the access phase.
--- Options:
---   client (Client)  required — created via trustforge.new_client
---   action (string)  required
function M.guard(opts)
  assert(opts, "opts required")
  assert(opts.client, "opts.client required")
  assert(opts.action, "opts.action required")

  local path = (ngx and ngx.var and ngx.var.uri) or "/"
  local req = trustforge.build_request_from_headers(
    opts.action, path, ngx_get_header)
  local resp, err = opts.client:decide(req)
  if not resp then
    if opts.client.config.mode == trustforge.MODE_OBSERVE_ONLY then return end
    if ngx then
      ngx.status = 503
      ngx.header["content-type"] = "application/json"
      ngx.say('{"error":"trustforge:' .. (err and err.kind or "unknown") .. '"}')
      return ngx.exit(503)
    end
    error(err and err.message or "trustforge unavailable")
  end

  local status, headers, body = trustforge.decision_response(resp)
  if not status then return end
  if ngx then
    ngx.status = status
    for k, v in pairs(headers or {}) do ngx.header[k] = v end
    ngx.say(body)
    return ngx.exit(status)
  end
  return status, headers, body
end

--- Build a request handler usable from `access_by_lua_block` directly.
function M.access(opts)
  return function() return M.guard(opts) end
end

return M
