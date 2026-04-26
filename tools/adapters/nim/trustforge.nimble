# Package
version       = "0.1.0"
author        = "TrustForge contributors"
description   = "TrustForge HTTP client + middleware factories for Nim (Jester / HttpBeast)."
license       = "Apache-2.0"
srcDir        = "src"

# Dependencies
requires "nim >= 1.6.0"
# Optional runtime deps for the framework helpers; users wire these in
# their own apps. Listed for documentation. Tests only use stdlib.
# requires "jester >= 0.5.0"
# requires "httpbeast >= 0.4.0"

# Tasks
task test, "Run trustforge unit tests":
  exec "nim c --hints:off -r tests/test_trustforge.nim"
