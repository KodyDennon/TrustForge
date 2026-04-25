import { describe, expect, test } from "bun:test";
import { mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { BridgesRegistry, BridgesRegistryError, validateBridgesRegistry } from "../src/core/bridges-registry";

const SAMPLE_DOC = `
registry_version: "1"
default_profile: tf-home-compatible
bridges:
  - kind: oauth
    issuer_match: "https://accounts.google.com"
    trust_level: T2
    capability_map:
      openid: auth.openid
      email: user.email.read
  - kind: clerk
    iss_pattern: clerk.dev
    trust_level: T2
  - kind: spiffe
    issuer_match: "spiffe://example.com"
    trust_level: T3
`;

describe("BridgesRegistry", () => {
  test("loads valid registry and exposes entries", () => {
    const r = BridgesRegistry.fromString(SAMPLE_DOC);
    expect(r.registry_version).toBe("1");
    expect(r.default_profile).toBe("tf-home-compatible");
    expect(r.bridges.length).toBe(3);
    expect(r.bridges[0]!.kind).toBe("oauth");
    expect(r.bridges[0]!.issuer_match).toBe("https://accounts.google.com");
    expect(r.bridges[0]!.capability_map?.["openid"]).toBe("auth.openid");
  });

  test("resolveByIssuer returns the right bridge for an exact match", () => {
    const r = BridgesRegistry.fromString(SAMPLE_DOC);
    const hit = r.resolveByIssuer("https://accounts.google.com");
    expect(hit).not.toBeNull();
    expect(hit!.kind).toBe("oauth");
  });

  test("resolveByIssuer falls back to iss_pattern substring match", () => {
    const r = BridgesRegistry.fromString(SAMPLE_DOC);
    const hit = r.resolveByIssuer("https://api.clerk.dev/v1/sessions/abc");
    expect(hit).not.toBeNull();
    expect(hit!.kind).toBe("clerk");
  });

  test("resolveByIssuer returns null for unknown issuer", () => {
    const r = BridgesRegistry.fromString(SAMPLE_DOC);
    expect(r.resolveByIssuer("https://unknown.example/")).toBeNull();
    expect(r.resolveByIssuer("")).toBeNull();
  });

  test("override wins over default for same issuer", () => {
    // The custom registry maps clerk.dev to oauth (instead of clerk).
    // The registry-level mapping always takes precedence over what the
    // resolver would otherwise apply.
    const custom = `
registry_version: "1"
bridges:
  - kind: oauth
    issuer_match: clerk.dev
    trust_level: T1
`;
    const r = BridgesRegistry.fromString(custom);
    const hit = r.resolveByIssuer("clerk.dev");
    expect(hit?.kind).toBe("oauth");
    expect(hit?.trust_level).toBe("T1");
  });

  test("resolveByKind returns first matching entry", () => {
    const r = BridgesRegistry.fromString(SAMPLE_DOC);
    const hit = r.resolveByKind("spiffe");
    expect(hit?.issuer_match).toBe("spiffe://example.com");
  });

  test("missing file resolves to empty registry", () => {
    const dir = mkdtempSync(join(tmpdir(), "tf-bridges-registry-"));
    try {
      const r = BridgesRegistry.load(join(dir, "bridges.yaml"));
      expect(r.bridges.length).toBe(0);
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });

  test("load from disk round-trips", () => {
    const dir = mkdtempSync(join(tmpdir(), "tf-bridges-registry-"));
    try {
      const path = join(dir, "bridges.yaml");
      writeFileSync(path, SAMPLE_DOC);
      const r = BridgesRegistry.load(path);
      expect(r.bridges.length).toBe(3);
      expect(r.resolveByKind("spiffe")?.trust_level).toBe("T3");
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });

  test("rejects malformed registry: missing registry_version", () => {
    expect(() => BridgesRegistry.fromString(`bridges: []`)).toThrow(BridgesRegistryError);
  });

  test("rejects malformed registry: unknown kind", () => {
    expect(() =>
      BridgesRegistry.fromString(`
registry_version: "1"
bridges:
  - kind: futurebridge
`),
    ).toThrow(BridgesRegistryError);
  });

  test("rejects malformed registry: invalid action name in capability_map", () => {
    expect(() =>
      BridgesRegistry.fromString(`
registry_version: "1"
bridges:
  - kind: oauth
    issuer_match: x
    capability_map:
      email: NOT a valid action
`),
    ).toThrow(BridgesRegistryError);
  });

  test("rejects malformed registry: unknown top-level key", () => {
    expect(() =>
      BridgesRegistry.fromString(`
registry_version: "1"
bridges: []
extra_key: 1
`),
    ).toThrow(BridgesRegistryError);
  });

  test("rejects malformed registry: bad profile pattern", () => {
    expect(() =>
      BridgesRegistry.fromString(`
registry_version: "1"
default_profile: nope
bridges: []
`),
    ).toThrow(BridgesRegistryError);
  });

  test("rejects malformed registry: bad trust_level", () => {
    expect(() =>
      BridgesRegistry.fromString(`
registry_version: "1"
bridges:
  - kind: oauth
    issuer_match: x
    trust_level: T9
`),
    ).toThrow(BridgesRegistryError);
  });

  test("validateBridgesRegistry: top-level array is rejected", () => {
    expect(() => validateBridgesRegistry([])).toThrow(BridgesRegistryError);
  });
});
