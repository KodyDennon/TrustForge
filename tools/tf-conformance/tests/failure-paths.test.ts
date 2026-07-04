/**
 * Failure-path / negative-test suite for the conformance runners.
 *
 * The pre-existing tests in `runner.test.ts` only exercise the happy path:
 * they confirm a clean repository run reports zero failures. That is
 * insufficient — the runners must ALSO correctly REJECT bad inputs, or
 * a regression that newly accepts malformed data would slip past CI in
 * silence (FIND-001 / FIND-004 / FIND-005 from DECISIONS).
 *
 * This file feeds each runner a synthetic "evil" fixture and asserts
 * `failed > 0` (or, for security regressions, that the listed properties
 * hold). The synthetic fixtures live under
 * `conformance/__failure-fixtures__/<scenario>/` and are committed
 * alongside this file so the test is reproducible from a clean checkout.
 */

import { describe, expect, test } from "bun:test";
import { mkdtempSync, readFileSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import {
  runBridgeVectors,
  runFuzzCorpus,
  runGuardVectors,
  runProfileVectors,
  runSchemaVectors,
  runSecurityRegressions,
  runSignatureVectors,
} from "../src/runner";
import {
  AgentGuard,
  Vault,
  canonicalize,
  chacha20poly1305Decrypt,
  chacha20poly1305Encrypt,
  checkWindow,
  ed25519PublicKey,
  ed25519Sign,
  ed25519Verify,
  isExpired,
  migrateSession,
  selectProfile,
  signFederationAttestation,
  verifyFederationAttestation,
  verifySessionMigration,
} from "@trustforge-protocol/types";

const REPO_ROOT = resolve(import.meta.dir, "..", "..", "..");
const FAIL_ROOT = resolve(REPO_ROOT, "conformance/__failure-fixtures__");

describe("tf-conformance — runners must REJECT bad inputs", () => {
  test("runSchemaVectors rejects a fixture under valid/ that fails its schema", async () => {
    // The synthetic fixture omits the required `project` field — AJV
    // must reject it, and because the file lives under valid/ that
    // rejection is itself a runner failure.
    const r = await runSchemaVectors(resolve(FAIL_ROOT, "schema-malformed"));
    expect(r.failed).toBeGreaterThan(0);
    const bad = r.cases.find((c) => c.name.includes("missing-project"));
    expect(bad).toBeDefined();
    expect(bad!.pass).toBe(false);
    expect(bad!.detail).toMatch(/failed schema validation but lives in valid/);
  });

  test("runSignatureVectors rejects a forged ed25519 signature", async () => {
    // The synthetic vector flips the high byte of an RFC 8032 signature.
    // Both the recompute-and-compare check AND the ed25519Verify check
    // must contribute failures; total failed >= 2.
    const r = await runSignatureVectors(resolve(FAIL_ROOT, "signature-forged"));
    expect(r.failed).toBeGreaterThanOrEqual(2);
    const verifyCase = r.cases.find((c) => c.name.endsWith(".verify"));
    expect(verifyCase).toBeDefined();
    expect(verifyCase!.pass).toBe(false);
  });

  test("runGuardVectors rejects an allow-when-forbidden expectation", () => {
    // The synthetic case asks the guard to ALLOW an action that lives
    // in the contract's `forbidden` list. The guard correctly returns
    // deny, so the expectation mismatches — the runner must surface
    // this as a failure (proves we are no longer in the pre-B10
    // vacuous-pass state, FIND-001).
    const r = runGuardVectors(resolve(FAIL_ROOT, "guard-mismatch"));
    expect(r.failed).toBeGreaterThan(0);
    expect(r.passed).toBe(0);
    const c = r.cases[0]!;
    expect(c.pass).toBe(false);
    expect(c.detail ?? "").toMatch(/got deny.*expected allow/);
  });

  test("runBridgeVectors rejects a SPIFFE entry whose actor_id doesn't match — and silently ignoring an unsupported `madeup:` block must not save it", () => {
    // The synthetic file pairs a real SPIFFE id with a wrong actor_id.
    // The runner ignores the `madeup:` block we tucked at the top
    // level, but the SPIFFE mismatch alone forces failed > 0.
    const r = runBridgeVectors(resolve(FAIL_ROOT, "bridge-bad"));
    expect(r.failed).toBeGreaterThan(0);
    const bad = r.cases.find((c) => c.name.startsWith("spiffe."));
    expect(bad).toBeDefined();
    expect(bad!.pass).toBe(false);
    expect(bad!.detail ?? "").toMatch(/expected=tf:actor:service:WRONG/);
  });

  test("runFuzzCorpus rejects a fixture under invalid/ that AJV in fact accepts", async () => {
    // The synthetic file is a perfectly legal agent-contract sitting
    // under `invalid/`. AJV will accept it; the fuzz runner must
    // surface that acceptance as a failure (FIND-005 regression
    // canary).
    const r = await runFuzzCorpus(resolve(FAIL_ROOT, "fuzz-accepted"));
    expect(r.failed).toBeGreaterThan(0);
    const bad = r.cases.find((c) => c.name.includes("secretly-valid"));
    expect(bad).toBeDefined();
    expect(bad!.pass).toBe(false);
    expect(bad!.detail ?? "").toMatch(/accepted an invalid fixture/);
  });

  test("runProfileVectors rejects an unknown profile id (proxy for MUST-feature mismatch)", () => {
    // runProfileVectors is hard-wired to BUILTIN_PROFILES + a
    // hard-coded inventoryFor table; we cannot inject a synthetic
    // spec through it. The closest reachable failure mode is
    // requesting a profile id the runner does not know about, which
    // exercises the same "profile not satisfied" branch.
    const r = runProfileVectors(REPO_ROOT, "tf-fake-profile-not-real");
    expect(r.failed).toBe(1);
    expect(r.passed).toBe(0);
    expect(r.cases[0]!.detail ?? "").toMatch(/unknown profile/);
  });

  test("runProfileVectors-equivalent: selectProfile rejects a spec whose MUST features are not provided", () => {
    // Direct use of selectProfile to demonstrate the MUST-feature
    // mismatch path explicitly. The synthetic spec demands a feature
    // the gate does not list, so verdict.ok must be false and the
    // failures list must mention the missing feature by name.
    const verdict = selectProfile(
      {
        profile_version: "1",
        profile_id: "tf-synthetic-strict",
        label: "synthetic strict profile",
        must: [{ id: "mandatory-feature-not-supplied" }],
        should: [],
      },
      {
        features: new Set(["only-this-feature"]),
        enforcementLevel: "E0",
        proofLevelFloor: "L0",
        bridges: new Set(),
        anchors: new Set(),
      },
    );
    expect(verdict.ok).toBe(false);
    expect(verdict.failures.join(" ")).toMatch(/mandatory-feature-not-supplied/);
  });
});

/* -------------------------------------------------------------------------- *
 *  Twelve security-regression properties that MUST hold.
 *
 *  Spec source: failure-paths.test.ts task brief. `runSecurityRegressions`
 *  currently only encodes 4 of these directly — the remaining 8 are
 *  enforced here by exercising the underlying tf-types primitives so
 *  that any regression surfaces as a failed test. As `runSecurityRegressions`
 *  grows to cover all 12, the standalone tests below stay valid.
 * -------------------------------------------------------------------------- */

describe("tf-conformance — security regressions (12 properties)", () => {
  test("runSecurityRegressions reports zero failures and at least the four currently-encoded cases", async () => {
    // We do NOT assert >= 12 because that would require modifying the
    // production runner. The intent — "all 12 must hold" — is covered
    // by the dedicated tests below; this assertion guards the runner's
    // current behaviour while leaving room for it to grow.
    const r = await runSecurityRegressions();
    expect(r.failed).toBe(0);
    expect(r.passed).toBeGreaterThanOrEqual(4);
  });

  test("(1) vault opens with wrong passphrase, but read() rejects via AEAD auth-fail", async () => {
    const dir = mkdtempSync(join(tmpdir(), "tf-failpaths-vault-"));
    const path = join(dir, "vault.json");
    const v = await Vault.createAtPath(path, "correct horse battery staple", {
      m_cost: 256,
      t_cost: 1,
      p_cost: 1,
      salt: new Uint8Array(16),
    });
    const key = new Uint8Array(32);
    key.fill(0xab);
    v.store({ id: "signing-key", purpose: "signing", algorithm: "ed25519", key_bytes: key });

    // Wrong passphrase: open succeeds (no integrity check on the
    // header), but read MUST fail because the wrap key disagrees with
    // the AEAD tag.
    const wrong = await Vault.openAtPath(path, "wrong-passphrase");
    expect(() => wrong.read("signing-key")).toThrow(/aead authentication failed|aead/i);
  });

  test("(2) vault tamper on disk is detected on read", async () => {
    const dir = mkdtempSync(join(tmpdir(), "tf-failpaths-vault-tamper-"));
    const path = join(dir, "vault.json");
    const v = await Vault.createAtPath(path, "passphrase", {
      m_cost: 256,
      t_cost: 1,
      p_cost: 1,
      salt: new Uint8Array(16),
    });
    const key = new Uint8Array(32);
    key.fill(0x55);
    v.store({ id: "k1", purpose: "signing", algorithm: "ed25519", key_bytes: key });

    // Flip a byte in the on-disk ciphertext, then reopen and read.
    const obj = JSON.parse(readFileSync(path, "utf8")) as {
      entries: { ciphertext: string }[];
    };
    const ct = Buffer.from(obj.entries[0]!.ciphertext, "base64");
    ct[0] = (ct[0]! ^ 0xff) & 0xff;
    obj.entries[0]!.ciphertext = ct.toString("base64");
    writeFileSync(path, JSON.stringify(obj));

    const reopened = await Vault.openAtPath(path, "passphrase");
    expect(() => reopened.read("k1")).toThrow(/aead authentication failed|aead/i);
  });

  test("(3) ed25519: signature mutation in S-half is rejected (cofactor / malleability resistance)", async () => {
    const priv = new Uint8Array(32);
    priv.fill(0x07);
    const msg = new Uint8Array([1, 2, 3, 4]);
    const sig = await ed25519Sign(msg, priv);
    const pub = await ed25519PublicKey(priv);
    // Mutate a byte inside the S half (bytes 32..63).
    const malleable = new Uint8Array(sig);
    malleable[40] = (malleable[40]! ^ 0x01) & 0xff;
    const verified = await ed25519Verify(pub, msg, malleable);
    expect(verified).toBe(false);
  });

  test("(4) session migration replay: the same generation cannot be accepted twice", async () => {
    const priv = new Uint8Array(32);
    priv.fill(0x11);
    const pub = await ed25519PublicKey(priv);
    const binding = {
      binding_version: "1" as const,
      kind: "tcp" as const,
      endpoint: "127.0.0.1:9000",
    };
    const migration = await migrateSession({
      sessionId: "sess-1",
      generation: 5,
      fromBinding: binding,
      toBinding: { ...binding, endpoint: "127.0.0.1:9001" },
      signer: "tf:actor:agent:example.com/migrator",
      privateKey: priv,
    });
    // First verification at lastGeneration=4 succeeds.
    const first = await verifySessionMigration({
      migration,
      publicKey: pub,
      lastGeneration: 4,
    });
    expect(first.ok).toBe(true);
    // Replay: lastGeneration is now 5, so a second arrival of the
    // SAME generation must be refused as a replay.
    const replay = await verifySessionMigration({
      migration,
      publicKey: pub,
      lastGeneration: 5,
    });
    expect(replay.ok).toBe(false);
    expect(replay.reason ?? "").toMatch(/replay|generation/);
  });

  test("(5) AEAD ciphertext tamper is rejected", () => {
    const key = new Uint8Array(32);
    key.fill(0x21);
    const nonce = new Uint8Array(12);
    nonce.fill(0x33);
    const aad = new TextEncoder().encode("aad");
    const pt = new TextEncoder().encode("the cat is on the mat");
    const ct = chacha20poly1305Encrypt(key, nonce, aad, pt);
    // Flip a byte inside the ciphertext body (not the tag).
    ct[0] = (ct[0]! ^ 0xff) & 0xff;
    expect(() => chacha20poly1305Decrypt(key, nonce, aad, ct)).toThrow(
      /aead authentication failed|aead/i,
    );
  });

  test("(6) AEAD wrong-key is rejected", () => {
    const keyA = new Uint8Array(32);
    keyA.fill(0xa1);
    const keyB = new Uint8Array(32);
    keyB.fill(0xb2);
    const nonce = new Uint8Array(12);
    nonce.fill(0x77);
    const aad = new TextEncoder().encode("aad");
    const pt = new TextEncoder().encode("payload");
    const ct = chacha20poly1305Encrypt(keyA, nonce, aad, pt);
    expect(() => chacha20poly1305Decrypt(keyB, nonce, aad, ct)).toThrow(
      /aead authentication failed|aead/i,
    );
  });

  test("(7) glob escape: `?` in a deny_actors pattern is a literal, not a zero-or-one wildcard", () => {
    // Pre-B8 the `?` was passed through as a regex quantifier and
    // `tf:actor:agent:user?` would have matched `tf:actor:agent:user`
    // via the zero-match branch. After B8 `?` is escaped, so the
    // pattern matches ONLY the literal value containing a literal `?`.
    const guard = AgentGuard.fromContract({
      contract_version: "1",
      spec_version: "TF-0006-draft",
      project: "glob-escape",
      trust_domain: "example.com",
      actions: [
        {
          name: "act",
          risk: "R0",
          approval: "none",
          deny_actors: ["tf:actor:agent:example.com/user?"],
        },
      ],
    });
    // Without `?`: pattern must NOT match (literal `?` in pattern).
    const noQ = guard.check({
      actor: "tf:actor:agent:example.com/user",
      action: "act",
    });
    expect(noQ.kind).not.toBe("deny");
    // With literal `?`: pattern matches → deny.
    const withQ = guard.check({
      actor: "tf:actor:agent:example.com/user?",
      action: "act",
    });
    expect(withQ.kind).toBe("deny");
  });

  test("(8) regex DoS: catastrophic-backtracking-shaped glob completes quickly", () => {
    // A pattern like `**a**a**a**a**` against a 1k-char input is the
    // classic ReDoS shape (nested `.*` after expansion). Modern V8
    // handles it in microseconds, but the assertion bounds execution
    // so a future regex-engine swap or pattern-compiler change cannot
    // silently introduce exponential blow-up.
    const guard = AgentGuard.fromContract({
      contract_version: "1",
      spec_version: "TF-0006-draft",
      project: "regex-dos",
      trust_domain: "example.com",
      actions: [
        {
          name: "act",
          risk: "R0",
          approval: "none",
          allow_actors: ["**a**a**a**a**"],
        },
      ],
    });
    const longInput = "tf:actor:agent:" + "a".repeat(1000) + "b";
    const start = Date.now();
    guard.check({ actor: longInput, action: "act" });
    const elapsedMs = Date.now() - start;
    // Generous 200ms budget — real value <2ms on modern hardware.
    expect(elapsedMs).toBeLessThan(200);
  });

  test("(9) certificate-chain bypass: a federation attestation signed by an untrusted key is rejected", async () => {
    // Stand-in for "self-signed leaf without a trusted root": we sign
    // an attestation with privateA but try to verify against publicB.
    // verifyFederationAttestation must refuse — the chain does not
    // resolve to a trusted root.
    const trustedPriv = new Uint8Array(32);
    trustedPriv.fill(0xaa);
    const attackerPriv = new Uint8Array(32);
    attackerPriv.fill(0xbb);
    const trustedPub = await ed25519PublicKey(trustedPriv);

    const attestation = await signFederationAttestation({
      attestationId: "att-bad",
      issuerDomain: "evil.example.org",
      subjectDomain: "example.com",
      trustBundle: [
        { kind: "ed25519", value: "AA==", key_id: "k1" },
      ],
      issuedAt: "2026-01-01T00:00:00Z",
      validUntil: "2099-01-01T00:00:00Z",
      issuer: "tf:actor:service:evil.example.org/root",
      privateKey: attackerPriv,
    });

    const result = await verifyFederationAttestation({
      attestation,
      issuerPublicKey: trustedPub,
      now: "2026-04-25T00:00:00Z",
    });
    expect(result.ok).toBe(false);
    expect(result.reason ?? "").toMatch(/signature did not verify/);
  });

  test("(10) time-skew: a token whose valid_from is in the far future is rejected as not-yet-valid; a token whose valid_until is in the past is expired", () => {
    const future = checkWindow(
      { valid_from: "2099-01-01T00:00:00Z", valid_until: "2099-12-31T00:00:00Z" },
      "2026-04-25T00:00:00Z",
    );
    expect(future.ok).toBe(false);
    if (!future.ok) {
      expect(future.reason).toBe("not-yet-valid");
    }
    expect(
      isExpired({ valid_until: "2020-01-01T00:00:00Z" }, "2026-04-25T00:00:00Z"),
    ).toBe(true);
  });

  test("(11) canonical-JSON: keys are sorted by UTF-8 bytes, not UTF-16 code units", () => {
    // Pick two keys that disagree under UTF-8 vs UTF-16:
    //   "_pua" — Private Use Area, single UTF-16 unit 0xE000,
    //                  UTF-8 bytes EE 80 80
    //   "\u{1F600}_smp" — Supplementary plane, surrogate pair starting
    //                    0xD83D in UTF-16, UTF-8 bytes F0 9F 98 80
    //
    // UTF-16 sort: \uD83D... <   → SMP key first
    // UTF-8 sort:  EE...     < F0...   → PUA key first
    //
    // canonicalize must emit the PUA key first; if it ever switches
    // back to JS's default `<` (UTF-16) the test fails.
    const out = canonicalize({ "_pua": 1, "\u{1F600}_smp": 2 });
    const idxPua = out.indexOf("_pua");
    const idxSmp = out.indexOf("\u{1F600}_smp");
    expect(idxPua).toBeGreaterThan(-1);
    expect(idxSmp).toBeGreaterThan(-1);
    expect(idxPua).toBeLessThan(idxSmp);
  });

  test("(12) negative capability glob match (NOT exact-string)", () => {
    // Pre-B8 negative-capability matching was `===`, so a pattern of
    // "fs.write*" did not block "fs.write.tmp". After B8 the match is
    // glob-based — we assert that against a wildcard pattern.
    const guard = AgentGuard.fromContract(
      {
        contract_version: "1",
        spec_version: "TF-0006-draft",
        project: "negcap-glob",
        trust_domain: "example.com",
        actions: [
          { name: "fs.write.tmp", risk: "R0", approval: "none", reversible: true },
          { name: "fs.read", risk: "R0", approval: "none", reversible: true },
        ],
      },
      {
        negativeCapabilities: [{ name: "fs.write*", reason: "policy" }],
      },
    );
    // Glob match: "fs.write*" must cover "fs.write.tmp".
    const denied = guard.check({
      actor: "tf:actor:agent:example.com/x",
      action: "fs.write.tmp",
    });
    expect(denied.kind).toBe("deny");
    // Same pattern must NOT cover "fs.read" (different prefix).
    const allowed = guard.check({
      actor: "tf:actor:agent:example.com/x",
      action: "fs.read",
    });
    expect(allowed.kind).not.toBe("deny");
  });
});
