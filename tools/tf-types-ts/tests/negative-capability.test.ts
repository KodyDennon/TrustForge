import { describe, expect, test } from "bun:test";
import { readFileSync } from "node:fs";
import { join } from "node:path";
import { parse as parseYAML } from "../src/core/yaml.js";

import { AgentGuard, applyEnforcementLevel } from "../src/index";
import { checkWindow, isExpired, isWithinWindow } from "../src/index";

interface Vector {
  name: string;
  contract: Record<string, unknown>;
  negative_capabilities?: Array<{ name: string; target?: string; reason?: string }>;
  enforcement_level?: "E0" | "E1" | "E2" | "E3" | "E4" | "E5";
  query: { action: string; target?: string };
  expect: "allow" | "deny" | "approval-required" | "escalate" | "log-only";
}

interface VectorFile {
  vectors: Vector[];
}

function loadVectors(): VectorFile {
  const path = join(import.meta.dir, "..", "..", "..", "conformance", "negative-capability-vectors.yaml");
  return parseYAML(readFileSync(path, "utf8")) as VectorFile;
}

describe("Negative capabilities + EnforcementLevel parity vectors", () => {
  for (const v of loadVectors().vectors) {
    test(v.name, () => {
      const guard = AgentGuard.fromContract(v.contract, {
        negativeCapabilities: v.negative_capabilities ?? [],
        enforcementLevel: v.enforcement_level ?? "E4",
      });
      const decision = guard.check(v.query);
      expect(decision.kind).toBe(v.expect);
    });
  }
});

describe("applyEnforcementLevel direct cases", () => {
  test("E0 wraps every non-allow as log-only", () => {
    const denied = applyEnforcementLevel(
      { kind: "deny", reason: "no", danger_tags: [] },
      "E0",
    );
    expect(denied.kind).toBe("log-only");
    const escalated = applyEnforcementLevel(
      { kind: "escalate", reason: "destructive", danger_tags: ["destructive"] },
      "E0",
    );
    expect(escalated.kind).toBe("log-only");
    const approval = applyEnforcementLevel(
      {
        kind: "approval-required",
        approval: "required",
        reason: "requires approval",
        danger_tags: [],
      },
      "E0",
    );
    expect(approval.kind).toBe("log-only");
    const allow = applyEnforcementLevel({ kind: "allow", danger_tags: [] }, "E0");
    expect(allow.kind).toBe("allow");
  });

  test("E1 turns deny into allow with warn tag", () => {
    const adjusted = applyEnforcementLevel(
      { kind: "deny", reason: "blocked", danger_tags: [] },
      "E1",
    );
    expect(adjusted.kind).toBe("allow");
    expect(adjusted.danger_tags).toContain("warn");
  });

  test("E2 tags every decision as proof-log-required", () => {
    const adjusted = applyEnforcementLevel(
      { kind: "allow", danger_tags: [] },
      "E2",
    );
    expect(adjusted.danger_tags).toContain("proof-log-required");
  });

  test("E3 escalates allow with danger tags", () => {
    const adjusted = applyEnforcementLevel(
      { kind: "allow", danger_tags: ["privacy"] },
      "E3",
    );
    expect(adjusted.kind).toBe("escalate");
  });

  test("E4 is identity", () => {
    const adjusted = applyEnforcementLevel(
      { kind: "allow", danger_tags: [] },
      "E4",
    );
    expect(adjusted.kind).toBe("allow");
    expect(adjusted.danger_tags).toEqual([]);
  });

  test("E5 fail-closed converts escalate and approval-required to deny", () => {
    const fromEsc = applyEnforcementLevel(
      { kind: "escalate", reason: "destructive", danger_tags: ["destructive"] },
      "E5",
    );
    expect(fromEsc.kind).toBe("deny");
    const fromApp = applyEnforcementLevel(
      {
        kind: "approval-required",
        approval: "required",
        reason: "x",
        danger_tags: [],
      },
      "E5",
    );
    expect(fromApp.kind).toBe("deny");
    const fromAllowWithTag = applyEnforcementLevel(
      { kind: "allow", danger_tags: ["privacy"] },
      "E5",
    );
    expect(fromAllowWithTag.kind).toBe("deny");
  });
});

describe("Expiration helpers", () => {
  test("checkWindow accepts now inside the window", () => {
    const v = checkWindow(
      { valid_from: "2026-01-01T00:00:00Z", valid_until: "2026-12-31T23:59:59Z" },
      "2026-04-24T12:00:00Z",
    );
    expect(v.ok).toBe(true);
  });

  test("checkWindow rejects now after valid_until", () => {
    const v = checkWindow({ valid_until: "2026-04-23T23:59:59Z" }, "2026-04-24T00:00:00Z");
    expect(v.ok).toBe(false);
    if (!v.ok) {
      expect(v.reason).toBe("expired");
      expect(v.threshold).toBe("2026-04-23T23:59:59Z");
    }
  });

  test("checkWindow rejects now before valid_from", () => {
    const v = checkWindow({ valid_from: "2027-01-01T00:00:00Z" }, "2026-04-24T00:00:00Z");
    expect(v.ok).toBe(false);
    if (!v.ok) expect(v.reason).toBe("not-yet-valid");
  });

  test("checkWindow honors expires_at and not_after as alternates", () => {
    expect(isWithinWindow({ expires_at: "2026-04-25T00:00:00Z" }, "2026-04-24T00:00:00Z")).toBe(
      true,
    );
    expect(isExpired({ not_after: "2026-04-23T00:00:00Z" }, "2026-04-24T00:00:00Z")).toBe(true);
    expect(isExpired({ valid_from: "2027-01-01T00:00:00Z" }, "2026-04-24T00:00:00Z")).toBe(false);
  });

  test("checkWindow with no bounds is always valid", () => {
    expect(isWithinWindow({}, "2026-04-24T00:00:00Z")).toBe(true);
  });
});
