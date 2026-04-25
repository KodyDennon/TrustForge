#!/usr/bin/env bun
/**
 * Backwards-compatible entry point. The full implementation lives in
 * `./index.ts` which exports the registry-based dispatcher. This file
 * exists so older invocations of `tools/tf-cli/src/cli.ts` keep
 * working through the v0.1.0 transition.
 */

import { run } from "./index.js";

// Translate legacy single-word verbs (`tf approve`, `tf deny`, `tf revoke`)
// into the new noun/verb form (`tf approval approve`, …) so existing
// scripts and the original cli.test.ts keep working.
function rewriteLegacy(argv: string[]): string[] {
  const [head] = argv;
  if (!head) return argv;
  switch (head) {
    case "approve":
      return ["approval", "approve", ...argv.slice(1)];
    case "deny":
      return ["approval", "deny", ...argv.slice(1)];
    // `tf revoke <kind> <id>` → `tf revoke <kind> <id>` is already valid.
    default:
      return argv;
  }
}

if (import.meta.main) {
  const argv = rewriteLegacy(process.argv.slice(2));
  const exit = await run(argv);
  process.exit(exit);
}

export { run };
