-- SPDX-License-Identifier: Apache-2.0 OR MIT
--
-- LuCI controller for the TrustForge status dashboard.
--
-- Exposes:
--   /admin/services/trustforge          (overview view)
--   /admin/services/trustforge/status   (JSON: liveness)
--   /admin/services/trustforge/decisions(JSON: histogram)
--   /admin/services/trustforge/proofs   (JSON: recent proof events)

module("luci.controller.trustforge", package.seeall)

local sys  = require "luci.sys"
local json = require "luci.jsonc"
local nx   = require "nixio"

local SOCKET = "/var/run/trustforge/decide.sock"

function index()
    if not nixio.fs.access("/etc/config/trustforge") then
        return
    end

    local page = entry({"admin", "services", "trustforge"},
                       template("trustforge/index"),
                       _("TrustForge"), 60)
    page.dependent = true
    page.acl_depends = { "luci-app-trustforge" }

    entry({"admin", "services", "trustforge", "status"},
          call("action_status")).leaf = true
    entry({"admin", "services", "trustforge", "decisions"},
          call("action_decisions")).leaf = true
    entry({"admin", "services", "trustforge", "proofs"},
          call("action_proofs")).leaf = true
end

-- Tiny client for the daemon's local control socket. The daemon speaks
-- a line-delimited JSON protocol on `decide.sock`; we only ever send
-- read-only queries here.
local function _query(verb)
    local sock = nx.socket("unix", "stream")
    if not sock then return nil, "no-socket" end
    local ok, err = sock:connect(SOCKET)
    if not ok then sock:close(); return nil, err end
    sock:send('{"op":"' .. verb .. '"}\n')
    local line = sock:read("*l")
    sock:close()
    if not line then return nil, "no-reply" end
    return json.parse(line)
end

local function _emit_json(payload)
    luci.http.prepare_content("application/json")
    luci.http.write_json(payload or {})
end

function action_status()
    local pid = sys.exec("pgrep -x tf-daemon | head -n1"):gsub("%s", "")
    local data = _query("status") or {}
    data.running = (pid ~= "")
    data.pid = (pid ~= "" and tonumber(pid)) or nil
    _emit_json(data)
end

function action_decisions()
    _emit_json(_query("decision_histogram") or { allow = 0, deny = 0, ask = 0 })
end

function action_proofs()
    _emit_json(_query("recent_proofs") or { events = {} })
end
