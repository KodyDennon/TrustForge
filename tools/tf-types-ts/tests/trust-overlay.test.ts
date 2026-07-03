import { describe, expect, test } from "bun:test";
import { readFileSync } from "node:fs";
import { join } from "node:path";
import { parse as parseYAML } from "../src/core/yaml.js";

import { composeTrustLevel, type PostureContext } from "../src/index";
import type { ActorIdentity } from "../src/index";

interface VectorFile {
  vectors: Array<{
    name: string;
    identity: ActorIdentity;
    posture: Record<string, unknown>;
    level: string;
  }>;
}

function loadVectors(): VectorFile {
  const path = join(import.meta.dir, "..", "..", "..", "conformance", "trust-overlay-vectors.yaml");
  return parseYAML(readFileSync(path, "utf8")) as VectorFile;
}

function snake(p: Record<string, unknown>): PostureContext {
  // YAML uses snake_case; the TS API uses camelCase.
  const out: Record<string, unknown> = {};
  for (const [k, v] of Object.entries(p)) {
    const camel = k.replace(/_([a-z])/g, (_, c) => c.toUpperCase());
    out[camel] = v;
  }
  return out as PostureContext;
}

describe("Trust overlay parity vectors", () => {
  for (const v of loadVectors().vectors) {
    test(v.name, () => {
      const result = composeTrustLevel(v.identity, snake(v.posture));
      expect(result.level).toBe(v.level as ActorIdentity["trust_levels"][number]);
      expect(Array.isArray(result.reasons)).toBe(true);
      expect(result.reasons[0]).toMatch(/^base=T[0-7]$/);
    });
  }
});

describe("Trust overlay direct cases", () => {
  const baseIdentity: ActorIdentity = {
    identity_version: "1",
    actor_id: "tf:actor:human:example.com/u",
    actor_type: "human",
    public_keys: [
      { key_id: "k", algorithm: "ed25519", public_key: "AA==", purpose: "signing" },
    ],
    trust_levels: ["T2"],
    authority_roots: [{ kind: "organization", id: "example.com" }],
    valid_from: "2026-01-01T00:00:00Z",
  };

  test("untrusted relay path doesn't reduce below T0", () => {
    const r = composeTrustLevel({ ...baseIdentity, trust_levels: ["T0"] }, {
      untrustedRelayPath: true,
    });
    expect(r.level).toBe("T0");
  });

  test("multiple boosts compose so highest applies", () => {
    const r = composeTrustLevel(baseIdentity, {
      hardwareBacked: true,
      quorumApproversAtLeast: 2,
      publiclyAnchored: true,
      complianceAttested: true,
    });
    expect(r.level).toBe("T7");
  });

  test("unknown actor with no levels starts at T0", () => {
    const r = composeTrustLevel({ ...baseIdentity, trust_levels: [] }, {});
    expect(r.level).toBe("T0");
  });

  test("reasons trace records every adjustment", () => {
    const r = composeTrustLevel(baseIdentity, {
      hardwareBacked: true,
      untrustedRelayPath: true,
    });
    expect(r.level).toBe("T3");
    expect(r.reasons).toContain("hardware-backed → ≥T4");
    expect(r.reasons).toContain("untrusted relay path → -1");
  });
});
