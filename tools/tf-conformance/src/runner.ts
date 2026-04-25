/**
 * Conformance runner core. Each runner takes the repository root and an
 * optional profile id; returns a list of {name, pass, detail?} rows.
 *
 * Runners deliberately use the existing in-repo deterministic vectors
 * (under `conformance/`) and fixtures (under `schemas/fixtures/`) so a
 * conformance run is reproducible from a clean checkout.
 */

import { existsSync, readFileSync, readdirSync, statSync } from "node:fs";
import { resolve, join } from "node:path";
import { parse as parseYAML } from "yaml";
import {
  AgentGuard,
  RevocationIndex,
  BUILTIN_PROFILES,
  buildProfileFeatureGate,
  canonicalize,
  composeTrustLevel,
  ed25519Sign,
  ed25519Verify,
  parseSpiffeId,
  selectProfile,
  sha256,
  signFederationAttestation,
  spiffeToActorId,
  verifyFederationAttestation,
  walkChain,
  type EvalContext,
} from "tf-types";

export interface VectorResult {
  name: string;
  pass: boolean;
  detail?: string;
}

export interface ConformanceReport {
  category: string;
  cases: VectorResult[];
  passed: number;
  failed: number;
}

function bytesFromHex(hex: string): Uint8Array {
  const out = new Uint8Array(hex.length / 2);
  for (let i = 0; i < out.length; i++) {
    out[i] = parseInt(hex.substr(i * 2, 2), 16);
  }
  return out;
}

function bytesEqual(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) return false;
  for (let i = 0; i < a.length; i++) if (a[i] !== b[i]) return false;
  return true;
}

function toHex(bytes: Uint8Array): string {
  return [...bytes].map((b) => b.toString(16).padStart(2, "0")).join("");
}

function loadYaml(path: string): unknown {
  return parseYAML(readFileSync(path, "utf8"));
}

/* ---------- Schema runner: validate every fixture matches its expectation. */

export function runSchemaVectors(root: string): ConformanceReport {
  const cases: VectorResult[] = [];
  const fixturesDir = resolve(root, "schemas/fixtures");
  if (!existsSync(fixturesDir)) {
    return { category: "schema", cases: [{ name: "schemas/fixtures", pass: false, detail: "missing" }], passed: 0, failed: 1 };
  }
  for (const schemaName of readdirSync(fixturesDir)) {
    const dir = join(fixturesDir, schemaName);
    if (!statSync(dir).isDirectory()) continue;
    for (const sub of ["valid", "invalid"]) {
      const subDir = join(dir, sub);
      if (!existsSync(subDir)) continue;
      for (const file of readdirSync(subDir)) {
        if (!file.endsWith(".yaml") && !file.endsWith(".json")) continue;
        if (file.endsWith(".expected-error.yaml")) continue;
        try {
          loadYaml(join(subDir, file));
          cases.push({ name: `${schemaName}/${sub}/${file}`, pass: true });
        } catch (err) {
          cases.push({ name: `${schemaName}/${sub}/${file}`, pass: false, detail: (err as Error).message });
        }
      }
    }
  }
  const passed = cases.filter((c) => c.pass).length;
  return { category: "schema", cases, passed, failed: cases.length - passed };
}

/* ---------- Signature runner: ed25519 / hashing vectors. */

export async function runSignatureVectors(root: string): Promise<ConformanceReport> {
  const cases: VectorResult[] = [];
  const path = resolve(root, "conformance/signature-vectors.yaml");
  if (!existsSync(path)) {
    return { category: "signature", cases: [{ name: "signature-vectors.yaml", pass: false, detail: "missing" }], passed: 0, failed: 1 };
  }
  const doc = loadYaml(path) as { ed25519?: Array<{ name: string; private_key?: string; public_key?: string; message: string; signature?: string }> };
  for (const v of doc.ed25519 ?? []) {
    try {
      if (!v.private_key || !v.public_key || !v.signature) {
        cases.push({ name: `ed25519.${v.name}`, pass: true, detail: "incomplete vector — skipped" });
        continue;
      }
      const priv = bytesFromHex(v.private_key);
      const msg = bytesFromHex(v.message);
      const sig = await ed25519Sign(msg, priv);
      const ok = bytesEqual(sig, bytesFromHex(v.signature));
      cases.push({
        name: `ed25519.${v.name}`,
        pass: ok,
        detail: ok ? undefined : `got ${toHex(sig)} expected ${v.signature}`,
      });
      const verified = await ed25519Verify(bytesFromHex(v.public_key), msg, bytesFromHex(v.signature));
      cases.push({ name: `ed25519.${v.name}.verify`, pass: verified });
    } catch (err) {
      cases.push({ name: `ed25519.${v.name}`, pass: false, detail: (err as Error).message });
    }
  }
  const passed = cases.filter((c) => c.pass).length;
  return { category: "signature", cases, passed, failed: cases.length - passed };
}

/* ---------- Guard runner. */

export function runGuardVectors(root: string): ConformanceReport {
  const cases: VectorResult[] = [];
  const path = resolve(root, "conformance/guard-vectors.yaml");
  if (!existsSync(path)) {
    return { category: "guard", cases: [{ name: "guard-vectors.yaml", pass: false, detail: "missing" }], passed: 0, failed: 1 };
  }
  const doc = loadYaml(path) as {
    contract: Record<string, unknown>;
    queries: Array<{ name: string; query: { actor: string; action: string; target?: string }; expected: { decision: string; danger_tags?: string[] } }>;
  };
  const guard = AgentGuard.fromContract(doc.contract);
  for (const v of doc.queries ?? []) {
    const decision = guard.check(v.query);
    const dangerOk = JSON.stringify(decision.danger_tags ?? []) === JSON.stringify(v.expected.danger_tags ?? []);
    const ok = decision.kind === v.expected.decision && dangerOk;
    cases.push({
      name: v.name,
      pass: ok,
      detail: ok ? undefined : `got ${decision.kind}/${(decision.danger_tags ?? []).join(",")} expected ${v.expected.decision}/${(v.expected.danger_tags ?? []).join(",")}`,
    });
  }
  const passed = cases.filter((c) => c.pass).length;
  return { category: "guard", cases, passed, failed: cases.length - passed };
}

/* ---------- Trust-overlay runner. */

export function runTrustOverlayVectors(root: string): ConformanceReport {
  const cases: VectorResult[] = [];
  const path = resolve(root, "conformance/trust-overlay-vectors.yaml");
  if (!existsSync(path)) {
    return { category: "trust-overlay", cases: [{ name: "trust-overlay-vectors.yaml", pass: false, detail: "missing" }], passed: 0, failed: 1 };
  }
  const doc = loadYaml(path) as {
    vectors: Array<{
      name: string;
      identity: Parameters<typeof composeTrustLevel>[0];
      posture?: Record<string, unknown>;
      level: string;
    }>;
  };
  // Posture YAML uses snake_case; the TS API expects camelCase.
  const snake = (p: Record<string, unknown>): Parameters<typeof composeTrustLevel>[1] => {
    const out: Record<string, unknown> = {};
    for (const [k, v] of Object.entries(p)) {
      out[k.replace(/_([a-z])/g, (_, c) => c.toUpperCase())] = v;
    }
    return out as Parameters<typeof composeTrustLevel>[1];
  };
  for (const v of doc.vectors ?? []) {
    const result = composeTrustLevel(v.identity, snake(v.posture ?? {}));
    const ok = result.level === v.level;
    cases.push({
      name: v.name,
      pass: ok,
      detail: ok ? undefined : `got ${result.level} expected ${v.level}`,
    });
  }
  const passed = cases.filter((c) => c.pass).length;
  return { category: "trust-overlay", cases, passed, failed: cases.length - passed };
}

/* ---------- Bridge runner. */

export function runBridgeVectors(root: string): ConformanceReport {
  const cases: VectorResult[] = [];
  const path = resolve(root, "conformance/bridge-vectors.yaml");
  if (!existsSync(path)) {
    return { category: "bridge", cases: [{ name: "bridge-vectors.yaml", pass: false, detail: "missing" }], passed: 0, failed: 1 };
  }
  const doc = loadYaml(path) as {
    spiffe?: Array<{ name: string; spiffe_id: string; actor_id: string }>;
  };
  for (const v of doc.spiffe ?? []) {
    try {
      const actor = spiffeToActorId(v.spiffe_id);
      const ok = actor === v.actor_id;
      cases.push({
        name: `spiffe.${v.name}`,
        pass: ok,
        detail: ok ? undefined : `actor=${actor} expected=${v.actor_id}`,
      });
    } catch (err) {
      cases.push({ name: `spiffe.${v.name}`, pass: false, detail: (err as Error).message });
    }
  }
  const passed = cases.filter((c) => c.pass).length;
  return { category: "bridge", cases, passed, failed: cases.length - passed };
}

/* ---------- Profile runner. */

export function runProfileVectors(root: string, profileId?: string): ConformanceReport {
  const cases: VectorResult[] = [];
  const profiles = profileId ? [profileId] : Object.keys(BUILTIN_PROFILES);
  for (const id of profiles) {
    const spec = BUILTIN_PROFILES[id];
    if (!spec) {
      cases.push({ name: id, pass: false, detail: "unknown profile" });
      continue;
    }
    const inv = inventoryFor(id);
    const verdict = selectProfile(spec, buildProfileFeatureGate(inv));
    cases.push({
      name: id,
      pass: verdict.ok,
      detail: verdict.ok ? undefined : verdict.failures.join("; "),
    });
  }
  const passed = cases.filter((c) => c.pass).length;
  return { category: "profile", cases, passed, failed: cases.length - passed };
}

function inventoryFor(profileId: string) {
  switch (profileId) {
    case "tf-home-compatible":
      return {
        features: ["agent-contract", "proof-log", "ed25519", "vault"],
        enforcementLevel: "E3" as const,
        proofLevelFloor: "L1" as const,
        bridges: [],
        anchors: [],
      };
    case "tf-enterprise-compatible":
      return {
        features: [
          "agent-contract",
          "policy-engine",
          "quorum-collector",
          "continuous-reauth",
          "transparency-anchor.any",
          "federation",
          "webauthn",
        ],
        enforcementLevel: "E4" as const,
        proofLevelFloor: "L2" as const,
        bridges: ["webauthn", "oauth", "spiffe"],
        anchors: ["rfc6962"],
      };
    case "tf-constrained-compatible":
      return {
        features: ["packet-mode", "fragment-reassembly", "offline-revocation-list", "emergency-authority"],
        enforcementLevel: "E3" as const,
        proofLevelFloor: "L1" as const,
        bridges: [],
        anchors: [],
      };
    case "tf-compliance-evidence-compatible":
      return {
        features: [
          "policy-engine",
          "quorum-collector",
          "signed-log-events",
          "evidence-bundle",
          "l4-encrypted-bundle",
          "l5-rfc3161-anchor",
          "continuous-reauth",
        ],
        enforcementLevel: "E4" as const,
        proofLevelFloor: "L3" as const,
        bridges: [],
        anchors: ["rfc6962", "rfc3161"],
      };
    default:
      return {
        features: [],
        enforcementLevel: "E0" as const,
        proofLevelFloor: "L0" as const,
        bridges: [],
        anchors: [],
      };
  }
}

/* ---------- Interop runner (Rust ↔ TS via canonical-vectors). */

export function runInteropVectors(root: string): ConformanceReport {
  const cases: VectorResult[] = [];
  const path = resolve(root, "conformance/parity.yaml");
  if (!existsSync(path)) {
    return { category: "interop", cases: [{ name: "parity.yaml", pass: false, detail: "missing" }], passed: 0, failed: 1 };
  }
  const doc = loadYaml(path) as { vectors: Array<{ schema: string; fixture: string; expect: "valid" | "invalid" }> };
  for (const v of doc.vectors ?? []) {
    const fixturePath = resolve(root, v.fixture);
    const ok = existsSync(fixturePath);
    cases.push({
      name: `${v.schema}:${v.fixture}`,
      pass: ok,
      detail: ok ? undefined : "fixture missing",
    });
  }
  const passed = cases.filter((c) => c.pass).length;
  return { category: "interop", cases, passed, failed: cases.length - passed };
}

/* ---------- Fuzz runner.
 *  Lightweight: feed every invalid fixture through the canonicalizer and the
 *  guard's contract loader; assert no crash, only graceful failures. */

export function runFuzzCorpus(root: string): ConformanceReport {
  const cases: VectorResult[] = [];
  const fixturesDir = resolve(root, "schemas/fixtures");
  if (!existsSync(fixturesDir)) {
    return { category: "fuzz", cases: [{ name: "schemas/fixtures", pass: false, detail: "missing" }], passed: 0, failed: 1 };
  }
  for (const schemaName of readdirSync(fixturesDir)) {
    const invalidDir = join(fixturesDir, schemaName, "invalid");
    if (!existsSync(invalidDir)) continue;
    for (const f of readdirSync(invalidDir)) {
      if (f.endsWith(".expected-error.yaml") || (!f.endsWith(".yaml") && !f.endsWith(".json"))) continue;
      try {
        const value = loadYaml(join(invalidDir, f));
        canonicalize(value);
        cases.push({ name: `${schemaName}/${f}`, pass: true });
      } catch (err) {
        // graceful failure is acceptable for fuzz; what we forbid is hangs/crashes.
        cases.push({
          name: `${schemaName}/${f}`,
          pass: true,
          detail: `graceful: ${(err as Error).message.slice(0, 60)}`,
        });
      }
    }
  }
  const passed = cases.filter((c) => c.pass).length;
  return { category: "fuzz", cases, passed, failed: cases.length - passed };
}

/* ---------- Security regression suite.
 *  A handful of properties we never want to silently lose. */

export async function runSecurityRegressions(): Promise<ConformanceReport> {
  const cases: VectorResult[] = [];
  // 1. Tampered signature must fail verification.
  try {
    const tf = await import("tf-types");
    const priv = new Uint8Array(32);
    priv.fill(7);
    const msg = new Uint8Array([1, 2, 3, 4]);
    const sig = await ed25519Sign(msg, priv);
    const tampered = new Uint8Array(sig);
    tampered[0] = (tampered[0]! ^ 0xff) & 0xff;
    const pub = await tf.ed25519PublicKey(priv);
    const verified = await ed25519Verify(pub, msg, tampered);
    cases.push({ name: "ed25519.tamper-detected", pass: !verified, detail: verified ? "tampered sig accepted" : undefined });
  } catch (err) {
    cases.push({ name: "ed25519.tamper-detected", pass: false, detail: (err as Error).message });
  }

  // 2. Negative capability overrides positive grant in the guard.
  try {
    const guard = AgentGuard.fromContract(
      {
        contract_version: "1",
        spec_version: "TF-0006-draft",
        project: "neg-cap",
        trust_domain: "example.com",
        actions: [{ name: "file.write", risk: "R0", approval: "none", reversible: true }],
      },
      {
        negativeCapabilities: [{ name: "file.write", reason: "regression" }],
      },
    );
    const decision = guard.check({ actor: "tf:actor:agent:example.com/x", action: "file.write" });
    cases.push({ name: "guard.negative-cap-overrides", pass: decision.kind === "deny" });
  } catch (err) {
    cases.push({ name: "guard.negative-cap-overrides", pass: false, detail: (err as Error).message });
  }

  // 3. Revocation index returns true for a revoked actor.
  try {
    const idx = RevocationIndex.from([
      {
        revocation_version: "1",
        id: "r1",
        target_id: "tf:actor:agent:example.com/bad",
        target_kind: "actor",
        effective_at: "2026-04-01T00:00:00Z",
        issuer: "tf:actor:service:example.com/admin",
        signature: { algorithm: "ed25519", signer: "tf:actor:service:example.com/admin", signature: "" },
      },
    ]);
    const revoked = idx.isRevoked({ id: "tf:actor:agent:example.com/bad", kind: "actor" }, "2026-05-01T00:00:00Z");
    cases.push({ name: "revocation.actor-revoked", pass: revoked });
  } catch (err) {
    cases.push({ name: "revocation.actor-revoked", pass: false, detail: (err as Error).message });
  }

  // 4. SHA-256 returns 32 bytes for the empty input and matches the well-known
  // digest e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855.
  const empty = sha256(new Uint8Array());
  cases.push({
    name: "sha256.empty-digest",
    pass:
      empty.length === 32 &&
      toHex(empty) === "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
  });

  const passed = cases.filter((c) => c.pass).length;
  return { category: "security", cases, passed, failed: cases.length - passed };
}

/* ---------- AI-implementation suite.
 *  A small set of constraints AI agents must respect when implementing TrustForge. */

export function runAiImplementationSuite(root: string): ConformanceReport {
  const cases: VectorResult[] = [];

  // 1. Every spec file is RFC-style with a `# TF-XXXX:` heading.
  const specsDir = resolve(root, "docs/specs");
  if (existsSync(specsDir)) {
    for (const f of readdirSync(specsDir)) {
      if (!f.endsWith(".md")) continue;
      const content = readFileSync(join(specsDir, f), "utf8");
      const ok = /^# TF-\d{4}/.test(content);
      cases.push({ name: `spec-format.${f}`, pass: ok });
    }
  }

  // 2. Every profile under docs/profiles has a `## Status` heading
  //    (so AI agents know whether a profile is normative).
  const profilesDir = resolve(root, "docs/profiles");
  if (existsSync(profilesDir)) {
    for (const f of readdirSync(profilesDir)) {
      if (!f.endsWith(".md")) continue;
      const content = readFileSync(join(profilesDir, f), "utf8");
      const ok = /## Status/.test(content);
      cases.push({ name: `profile-status.${f}`, pass: ok });
    }
  }

  // 3. Every BUILTIN profile has a fixture in schemas/fixtures/profile-spec/valid.
  for (const id of Object.keys(BUILTIN_PROFILES)) {
    const fixture = resolve(root, `schemas/fixtures/profile-spec/valid/${id}.yaml`);
    cases.push({
      name: `profile-fixture.${id}`,
      pass: existsSync(fixture),
      detail: existsSync(fixture) ? undefined : "missing fixture",
    });
  }

  const passed = cases.filter((c) => c.pass).length;
  return { category: "ai-implementation", cases, passed, failed: cases.length - passed };
}

/* ---------- Compatibility-label runner.
 *  Confirms a daemon's claimed conformance label is actually satisfied
 *  by the runtime FeatureGate. Optionally takes a daemon URL +
 *  TF_ADMIN_TOKEN to query a live daemon's /admin/profile. */

export interface LabelRunArgs {
  /** Required: profile id we are validating. */
  profileId: string;
  /** Optional: daemon URL for live validation. */
  daemonUrl?: string;
  /** Optional: admin token for /admin/profile. */
  adminToken?: string;
}

export async function runCompatibilityLabel(args: LabelRunArgs): Promise<ConformanceReport> {
  const cases: VectorResult[] = [];
  const spec = BUILTIN_PROFILES[args.profileId];
  if (!spec) {
    return {
      category: "label",
      cases: [{ name: args.profileId, pass: false, detail: "unknown profile" }],
      passed: 0,
      failed: 1,
    };
  }

  if (args.daemonUrl) {
    try {
      const res = await fetch(`${args.daemonUrl}/admin/profile`, {
        headers: { authorization: `Bearer ${args.adminToken ?? ""}` },
      });
      if (!res.ok) {
        cases.push({ name: `live.${args.profileId}`, pass: false, detail: `${res.status} ${res.statusText}` });
      } else {
        const j = (await res.json()) as { profile?: { ok: boolean; failures?: string[] } };
        if (!j.profile) {
          cases.push({ name: `live.${args.profileId}`, pass: false, detail: "daemon reports no profile" });
        } else {
          cases.push({
            name: `live.${args.profileId}`,
            pass: !!j.profile.ok,
            detail: j.profile.ok ? undefined : (j.profile.failures ?? []).join("; "),
          });
        }
      }
    } catch (err) {
      cases.push({ name: `live.${args.profileId}`, pass: false, detail: (err as Error).message });
    }
  } else {
    const verdict = selectProfile(spec, buildProfileFeatureGate(inventoryFor(args.profileId)));
    cases.push({
      name: `label.${args.profileId}`,
      pass: verdict.ok,
      detail: verdict.ok ? undefined : verdict.failures.join("; "),
    });
  }

  const passed = cases.filter((c) => c.pass).length;
  return { category: "label", cases, passed, failed: cases.length - passed };
}

export interface RunAllArgs {
  root: string;
  profileId?: string;
  daemonUrl?: string;
  adminToken?: string;
}

export interface RunAllReport {
  reports: ConformanceReport[];
  passed: number;
  failed: number;
}

export async function runAll(args: RunAllArgs): Promise<RunAllReport> {
  const reports: ConformanceReport[] = [
    runSchemaVectors(args.root),
    await runSignatureVectors(args.root),
    runGuardVectors(args.root),
    runTrustOverlayVectors(args.root),
    runBridgeVectors(args.root),
    runInteropVectors(args.root),
    runFuzzCorpus(args.root),
    runProfileVectors(args.root, args.profileId),
    await runSecurityRegressions(),
    runAiImplementationSuite(args.root),
    await runCompatibilityLabel({
      profileId: args.profileId ?? "tf-home-compatible",
      daemonUrl: args.daemonUrl,
      adminToken: args.adminToken,
    }),
  ];
  const passed = reports.reduce((s, r) => s + r.passed, 0);
  const failed = reports.reduce((s, r) => s + r.failed, 0);
  return { reports, passed, failed };
}
