import { describe, expect, test } from "bun:test";
import type { Capability, Constraint, DelegationLink } from "../src/generated/_common";
import type { Revocation } from "../src/generated/revocation";
import { isCapability, constraintsSatisfied, intersectConstraints } from "../src/core/capability";
import { walkChain } from "../src/core/delegation";
import { RevocationIndex } from "../src/core/revocation";
import { validateEnvelopeShape } from "../src/core/envelope";

describe("isCapability", () => {
  test("accepts a minimal capability", () => {
    const c: Capability = { name: "file.read", risk: "R0" };
    expect(isCapability(c)).toBe(true);
  });
  test("rejects non-objects", () => {
    expect(isCapability(null)).toBe(false);
    expect(isCapability("cap")).toBe(false);
  });
});

describe("constraintsSatisfied", () => {
  const now = "2026-04-24T12:00:00Z";
  test("time_window inside range passes", () => {
    const c: Constraint = { kind: "time_window", from: "2026-01-01T00:00:00Z", until: "2026-12-31T00:00:00Z" };
    expect(constraintsSatisfied([c], { now })).toBe(true);
  });
  test("time_window past end fails", () => {
    const c: Constraint = { kind: "time_window", until: "2020-01-01T00:00:00Z" };
    expect(constraintsSatisfied([c], { now })).toBe(false);
  });
  test("target glob matches", () => {
    const c: Constraint = { kind: "target", patterns: ["src/**"] };
    expect(constraintsSatisfied([c], { now, target: "src/main.ts" })).toBe(true);
    expect(constraintsSatisfied([c], { now, target: "other/main.ts" })).toBe(false);
  });
  test("session constraint checks id", () => {
    const c: Constraint = { kind: "session", session_id: "s1" };
    expect(constraintsSatisfied([c], { now, session_id: "s1" })).toBe(true);
    expect(constraintsSatisfied([c], { now, session_id: "s2" })).toBe(false);
  });
  test("quorum requires enough approvers", () => {
    const c: Constraint = {
      kind: "quorum",
      quorum: 2,
      of: ["tf:actor:human:example.com/a", "tf:actor:human:example.com/b"],
    };
    expect(constraintsSatisfied([c], { now, approver_count: 2 })).toBe(true);
    expect(constraintsSatisfied([c], { now, approver_count: 1 })).toBe(false);
  });
});

describe("intersectConstraints", () => {
  test("intersection of time windows is the tighter window", () => {
    const a: Constraint = { kind: "time_window", from: "2026-01-01T00:00:00Z", until: "2026-12-31T00:00:00Z" };
    const b: Constraint = { kind: "time_window", from: "2026-03-01T00:00:00Z", until: "2026-06-30T00:00:00Z" };
    const r = intersectConstraints([a], [b]);
    expect(r).toHaveLength(1);
    expect((r[0] as { kind: "time_window"; from: string; until: string }).from).toBe("2026-03-01T00:00:00Z");
    expect((r[0] as { kind: "time_window"; from: string; until: string }).until).toBe("2026-06-30T00:00:00Z");
  });

  test("intersection of rate limits takes the smaller cap", () => {
    const a: Constraint = { kind: "rate", max_per_window: 100, window_seconds: 60 };
    const b: Constraint = { kind: "rate", max_per_window: 50, window_seconds: 120 };
    const r = intersectConstraints([a], [b]);
    expect((r[0] as { kind: "rate"; max_per_window: number; window_seconds: number }).max_per_window).toBe(50);
    expect((r[0] as { kind: "rate"; max_per_window: number; window_seconds: number }).window_seconds).toBe(60);
  });
});

describe("walkChain", () => {
  test("single-step chain is valid", () => {
    const chain: DelegationLink[] = [
      {
        delegator: "tf:actor:human:example.com/a",
        delegate: "tf:actor:agent:example.com/b",
        capabilities: [{ name: "file.read", risk: "R0" }],
      },
    ];
    const r = walkChain(chain, "2026-04-24T12:00:00Z");
    expect(r.valid).toBe(true);
  });

  test("expired step breaks the chain", () => {
    const chain: DelegationLink[] = [
      {
        delegator: "tf:actor:human:example.com/a",
        delegate: "tf:actor:agent:example.com/b",
        capabilities: [{ name: "file.read", risk: "R0" }],
        expires_at: "2020-01-01T00:00:00Z",
      },
    ];
    const r = walkChain(chain, "2026-04-24T12:00:00Z");
    expect(r.valid).toBe(false);
    expect(r.brokenStep).toBe(0);
  });

  test("no-redelegation blocks the next step", () => {
    const chain: DelegationLink[] = [
      {
        delegator: "tf:actor:human:example.com/root",
        delegate: "tf:actor:organization:example.com",
        capabilities: [{ name: "file.read", risk: "R0" }],
        redelegation: { allowed: false },
      },
      {
        delegator: "tf:actor:organization:example.com",
        delegate: "tf:actor:agent:example.com/a",
        capabilities: [{ name: "file.read", risk: "R0" }],
      },
    ];
    const r = walkChain(chain, "2026-04-24T12:00:00Z");
    expect(r.valid).toBe(false);
    expect(r.brokenStep).toBe(1);
  });

  test("intersects constraints across steps", () => {
    const chain: DelegationLink[] = [
      {
        delegator: "tf:actor:human:example.com/a",
        delegate: "tf:actor:organization:example.com",
        capabilities: [{ name: "file.write", risk: "R2" }],
        constraints: [{ kind: "target", patterns: ["src/**", "tests/**"] }],
        redelegation: { allowed: true },
      },
      {
        delegator: "tf:actor:organization:example.com",
        delegate: "tf:actor:agent:example.com/b",
        capabilities: [{ name: "file.write", risk: "R2" }],
        constraints: [{ kind: "target", patterns: ["src/**"] }],
      },
    ];
    const r = walkChain(chain, "2026-04-24T12:00:00Z");
    expect(r.valid).toBe(true);
    const t = r.effective.find((c) => c.kind === "target") as Extract<Constraint, { kind: "target" }>;
    expect(t.patterns).toEqual(["src/**"]);
  });
});

describe("RevocationIndex", () => {
  const revs: Revocation[] = [
    {
      revocation_version: "1",
      id: "r1",
      target_id: "tok-1",
      target_kind: "capability",
      effective_at: "2026-04-24T15:00:00Z",
      issuer: "tf:actor:organization:example.com",
      signature: {
        algorithm: "ed25519",
        signer: "tf:actor:organization:example.com",
        signature: "AAAA",
      },
    },
  ];

  test("detects revocation after effective time", () => {
    const idx = RevocationIndex.from(revs);
    expect(idx.isRevoked({ id: "tok-1", kind: "capability" }, "2026-04-24T16:00:00Z")).toBe(true);
  });

  test("does not flag before effective time", () => {
    const idx = RevocationIndex.from(revs);
    expect(idx.isRevoked({ id: "tok-1", kind: "capability" }, "2026-04-24T14:00:00Z")).toBe(false);
  });

  test("wrong kind returns false", () => {
    const idx = RevocationIndex.from(revs);
    expect(idx.isRevoked({ id: "tok-1", kind: "actor" }, "2026-04-24T16:00:00Z")).toBe(false);
  });
});

describe("validateEnvelopeShape", () => {
  test("accepts a well-formed envelope", () => {
    const r = validateEnvelopeShape({
      algorithm: "ed25519",
      signer: "tf:actor:organization:example.com",
      signature: "dGVzdC1zaWc=",
    });
    expect(r.ok).toBe(true);
    expect(r.issues.filter((i) => i.code.startsWith("unknown")).length).toBe(0);
  });

  test("flags invalid base64", () => {
    const r = validateEnvelopeShape({
      algorithm: "ed25519",
      signer: "tf:actor:organization:example.com",
      signature: "not base64!!",
    });
    expect(r.ok).toBe(false);
    expect(r.issues.some((i) => i.code === "invalid-base64")).toBe(true);
  });

  test("warns on unknown algorithm but still ok", () => {
    const r = validateEnvelopeShape({
      algorithm: "snake-oil",
      signer: "tf:actor:organization:example.com",
      signature: "AAAA",
    });
    expect(r.ok).toBe(true);
    expect(r.issues.some((i) => i.code === "unknown-algorithm")).toBe(true);
  });
});
