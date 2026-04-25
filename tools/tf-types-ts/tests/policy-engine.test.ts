import { describe, expect, test } from "bun:test";
import {
  NativePolicyEngine,
  policyEngineForManifest,
  type PolicyQuery,
} from "../src/index";
import type { Policy } from "../src/generated/policy";

const policy: Policy = {
  policy_version: "1",
  trust_domain: "example.com",
  engine_hint: "native",
  rules: [
    {
      id: "deny.write.secrets",
      effect: "deny",
      action: "file.write",
      target_patterns: ["secrets/**", ".env"],
      reason: "secrets are off-limits",
    } as Policy["rules"][number],
    {
      id: "escalate.payments",
      effect: "escalate",
      // Glob pattern (post-B8). Pre-B8 this was a regex; the engine now
      // matches policy patterns through the same glob impl as
      // negative_capabilities so untrusted policies can't ReDoS.
      action_pattern: "payment.*",
      reason: "payments require human approval",
      approval: "quorum",
    } as Policy["rules"][number],
    {
      id: "log.read",
      effect: "log_only",
      action: "file.read",
      reason: "audited but not gated",
    } as Policy["rules"][number],
    {
      id: "allow.write.source",
      effect: "allow",
      action: "file.write",
      target_patterns: ["src/**"],
      reason: "writes to src/ are allowed",
    } as Policy["rules"][number],
  ],
  negative_capabilities: [
    {
      name: "shell.exec",
      reason: "shell is forbidden in this domain",
    },
  ],
  continuous_reevaluation: {
    triggers: ["revocation", "session_rekey"],
  },
};

describe("NativePolicyEngine", () => {
  const engine = new NativePolicyEngine({ policy });

  test("negative capability beats every allow rule", () => {
    const d = engine.evaluate({
      subject: "tf:actor:agent:example.com/code-helper",
      action: "shell.exec",
      target: "/bin/ls",
    });
    expect(d.decision).toBe("deny");
    expect(d.reason).toContain("shell is forbidden");
  });

  test("deny rule wins over allow rule below it", () => {
    const d = engine.evaluate({
      subject: "tf:actor:agent:example.com/code-helper",
      action: "file.write",
      target: "secrets/master.key",
    });
    expect(d.decision).toBe("deny");
    expect(d.rule_id).toBe("deny.write.secrets");
  });

  test("allow rule matches when target glob holds", () => {
    const d = engine.evaluate({
      subject: "tf:actor:agent:example.com/code-helper",
      action: "file.write",
      target: "src/main.ts",
    });
    expect(d.decision).toBe("allow");
    expect(d.rule_id).toBe("allow.write.source");
  });

  test("escalate rule with quorum approval becomes escalate decision", () => {
    const d = engine.evaluate({
      subject: "tf:actor:agent:example.com/code-helper",
      action: "payment.charge",
      target: "vendor:42",
    });
    expect(d.decision).toBe("escalate");
    expect(d.approval).toBe("quorum");
  });

  test("log_only rule produces a log-only decision", () => {
    const d = engine.evaluate({
      subject: "tf:actor:agent:example.com/code-helper",
      action: "file.read",
      target: "any.txt",
    });
    expect(d.decision).toBe("log-only");
    expect(d.rule_id).toBe("log.read");
  });

  test("default deny when no rule matches", () => {
    const d = engine.evaluate({
      subject: "tf:actor:agent:example.com/code-helper",
      action: "kernel.module.load",
      target: "snake-oil.ko",
    });
    expect(d.decision).toBe("deny");
    expect(d.rule_id).toBeUndefined();
    expect(d.reason).toContain("default deny");
  });

  test("decision carries policy manifest hash", () => {
    const d = engine.evaluate({
      subject: "tf:actor:agent:example.com/code-helper",
      action: "file.read",
    } as PolicyQuery);
    expect(d.policy_manifest_hash).toMatch(/^sha256-[0-9a-f]{64}$/);
  });

  test("continuousTriggers exposes the manifest's reeval triggers", () => {
    expect(engine.continuousTriggers().sort()).toEqual(["revocation", "session_rekey"]);
  });

  test("policyEngineForManifest returns NativePolicyEngine for engine_hint=native", () => {
    const e = policyEngineForManifest(policy);
    expect(e.engine).toBe("native");
  });

  test("Cedar/Rego stubs return a graceful deny (post-B8) instead of throwing", () => {
    // Pre-B8 the stubs threw, which let plugin RPCs surface as
    // "internal: capability enforcer threw". Post-B8 they fail closed
    // with a clear engine-unavailable reason so callers get a normal
    // PolicyDecision they can route through the same audit path.
    const cedar = policyEngineForManifest({ ...policy, engine_hint: "cedar" } as Policy);
    const cedarDecision = cedar.evaluate({ subject: "tf:actor:human:example.com/u", action: "file.read" });
    expect(cedarDecision.decision).toBe("deny");
    expect(cedarDecision.reason).toContain("cedar adapter not implemented");
    const rego = policyEngineForManifest({ ...policy, engine_hint: "rego" } as Policy);
    const regoDecision = rego.evaluate({ subject: "tf:actor:human:example.com/u", action: "file.read" });
    expect(regoDecision.decision).toBe("deny");
    expect(regoDecision.reason).toContain("rego adapter not implemented");
  });

  test("explicit negative capabilities passed in the query override any rule", () => {
    const d = engine.evaluate({
      subject: "tf:actor:agent:example.com/code-helper",
      action: "file.write",
      target: "src/main.ts",
      negativeCapabilities: [{ name: "file.write", reason: "frozen branch" }],
    });
    expect(d.decision).toBe("deny");
    expect(d.reason).toBe("frozen branch");
  });
});
