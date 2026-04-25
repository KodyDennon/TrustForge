/**
 * B8 guard / policy correctness:
 *   - glob `?` is escaped (was passed through as regex zero-or-one)
 *   - non-ASCII glob patterns work (TS uses Unicode code units; Rust now
 *     iterates chars())
 *   - negative_capability `name` is glob-matched (was `===`)
 *   - policy action_pattern / subject_pattern use the SAME glob, NOT
 *     `new RegExp(...)` — defeats ReDoS from untrusted policies
 *   - Cedar / Rego stubs return graceful deny (no longer throw)
 */
import { describe, expect, test } from "bun:test";
import {
  AgentGuard,
  CedarPolicyEngine,
  NativePolicyEngine,
  RegoPolicyEngine,
} from "../src/index";

describe("B8 — glob escapes regex meta characters", () => {
  test("`?` in a target_set glob no longer matches one fewer char", () => {
    const guard = AgentGuard.fromContract({
      contract_version: "1",
      spec_version: "TF-0006-draft",
      project: "b8",
      trust_domain: "example.com",
      actions: [
        {
          name: "fs.write",
          risk: "R0",
          approval: "none",
          reversible: true,
          // Pre-B8 this matched both `tf:actor:user` and `tf:actor:use`
          // because `?` was passed through as the regex zero-or-one
          // quantifier.
          deny_actors: ["tf:actor:user?"],
        },
      ],
    });
    const a = guard.check({ actor: "tf:actor:user?", action: "fs.write" });
    const b = guard.check({ actor: "tf:actor:use", action: "fs.write" });
    expect(a.kind).toBe("deny");
    expect(b.kind).toBe("allow");
  });
});

describe("B8 — non-ASCII glob patterns", () => {
  test("a glob containing `é` matches an `é`-bearing actor URI", () => {
    const guard = AgentGuard.fromContract({
      contract_version: "1",
      spec_version: "TF-0006-draft",
      project: "b8",
      trust_domain: "example.com",
      actions: [
        {
          name: "fs.write",
          risk: "R0",
          approval: "none",
          reversible: true,
          allow_actors: ["tf:actor:human:example.com/résumé"],
        },
      ],
    });
    const ok = guard.check({ actor: "tf:actor:human:example.com/résumé", action: "fs.write" });
    expect(ok.kind).toBe("allow");
  });
});

describe("B8 — negative_capability name is glob-matched", () => {
  test("`fs.write*` blocks `fs.write.tmp`", () => {
    const guard = AgentGuard.fromContract(
      {
        contract_version: "1",
        spec_version: "TF-0006-draft",
        project: "b8",
        trust_domain: "example.com",
        actions: [{ name: "fs.write.tmp", risk: "R0", approval: "none", reversible: true }],
      },
      {
        negativeCapabilities: [{ name: "fs.write*", reason: "no writes from this caller" }],
      },
    );
    const decision = guard.check({
      actor: "tf:actor:agent:example.com/x",
      action: "fs.write.tmp",
    });
    expect(decision.kind).toBe("deny");
  });
});

describe("B8 — policy patterns are globs, not regexes (ReDoS-safe)", () => {
  test("a pathological pattern doesn't hang evaluate (would have via new RegExp)", () => {
    // (a+)+b — catastrophic backtracking against a long string of `a`.
    // Pre-B8 the engine did `new RegExp(action_pattern).test(query.action)`
    // which would chew CPU for seconds on this input. Post-B8 it goes
    // through globMatch which escapes everything except `*` / `**` so
    // there's no exponential backtracking.
    const engine = new NativePolicyEngine({
      policy: {
        policy_version: "1",
        trust_domain: "example.com",
        engine_hint: "native",
        rules: [
          {
            id: "redos.test",
            effect: "deny",
            action_pattern: "(a+)+b",
            reason: "redos test",
          } as never,
        ],
        negative_capabilities: [],
      } as never,
    });
    const longA = "a".repeat(50);
    const before = Date.now();
    const d = engine.evaluate({ subject: "tf:actor:agent:example.com/x", action: longA });
    const elapsed = Date.now() - before;
    expect(elapsed).toBeLessThan(50); // sub-50ms on any modern machine
    expect(d.decision).toBe("deny"); // default deny — pattern doesn't glob-match
  });
});

describe("B8 — Cedar / Rego graceful deny", () => {
  test("Cedar returns deny + clear reason instead of throwing", () => {
    const engine = new CedarPolicyEngine();
    const d = engine.evaluate({ subject: "tf:actor:agent:example.com/x", action: "fs.read" });
    expect(d.decision).toBe("deny");
    expect(d.reason).toContain("cedar adapter");
  });

  test("Rego returns deny + clear reason instead of throwing", () => {
    const engine = new RegoPolicyEngine();
    const d = engine.evaluate({ subject: "tf:actor:agent:example.com/x", action: "fs.read" });
    expect(d.decision).toBe("deny");
    expect(d.reason).toContain("rego adapter");
  });
});
