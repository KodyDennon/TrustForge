package = "trustforge"
version = "1.0.0-1"

source = {
   url = "git+https://example.invalid/trustforge.git",
   tag = "v1.0.0",
}

description = {
   summary = "TrustForge HTTP client + OpenResty middleware for Lua.",
   detailed = [[
      Speaks `POST /v1/decide` against a local tf-daemon. Provides a
      pure-Lua client (using `lua-resty-http` when running under
      OpenResty, falling back to `socket.http` otherwise) and an
      OpenResty `access_by_lua` middleware factory.
   ]],
   homepage = "https://example.invalid/trustforge",
   license  = "Apache-2.0",
}

dependencies = {
   "lua >= 5.1",
   "dkjson >= 2.5",
   -- Optional, picked up at runtime:
   --   "lua-resty-http"  (OpenResty)
   --   "luasocket"       (CLI / non-OR Lua)
}

build = {
   type = "builtin",
   modules = {
      ["trustforge"]            = "src/trustforge.lua",
      ["trustforge.openresty"]  = "src/trustforge/openresty.lua",
   },
}

test_dependencies = {
   "busted >= 2.0",
}

test = {
   type = "busted",
}
