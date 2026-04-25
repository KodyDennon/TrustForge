import { describe, expect, test } from "bun:test";
import { resolve } from "node:path";
import {
  runAiImplementationSuite,
  runAll,
  runBinaryFormatVectors,
  runBridgeVectors,
  runCompatibilityLabel,
  runDecideProtocolVectors,
  runFuzzCorpus,
  runGuardVectors,
  runInteropVectors,
  runProfileVectors,
  runSchemaVectors,
  runSecurityRegressions,
  runSignatureVectors,
  runTrustOverlayVectors,
} from "../src/runner";

const ROOT = resolve(import.meta.dir, "..", "..", "..");

describe("tf-conformance — individual runners", () => {
  test("schema vectors: every fixture parses cleanly", async () => {
    const r = await runSchemaVectors(ROOT);
    expect(r.failed).toBe(0);
    expect(r.passed).toBeGreaterThan(50);
  });

  test("signature vectors: ed25519 RFC 8032 vectors round-trip", async () => {
    const r = await runSignatureVectors(ROOT);
    expect(r.failed).toBe(0);
    expect(r.passed).toBeGreaterThan(2);
  });

  test("guard vectors empty or pass", () => {
    const r = runGuardVectors(ROOT);
    expect(r.failed).toBe(0);
  });

  test("trust-overlay vectors all match", () => {
    const r = runTrustOverlayVectors(ROOT);
    expect(r.failed).toBe(0);
    expect(r.passed).toBeGreaterThan(5);
  });

  test("bridge SPIFFE + MCP + WebAuthn vectors all match", () => {
    const r = runBridgeVectors(ROOT);
    expect(r.failed).toBe(0);
    // Post-B10 the runner consumes spiffe (3) + mcp_normalize (7) +
    // webauthn (2) = 12 cases. Pre-B10 only the 3 spiffe cases ran.
    expect(r.passed).toBe(12);
  });

  test("interop parity manifest references existing fixtures", () => {
    const r = runInteropVectors(ROOT);
    expect(r.failed).toBe(0);
    expect(r.passed).toBeGreaterThan(50);
  });

  test("fuzz corpus: every invalid fixture handles gracefully", async () => {
    const r = await runFuzzCorpus(ROOT);
    expect(r.failed).toBe(0);
  });

  test("profile runner accepts the four built-ins", () => {
    const r = runProfileVectors(ROOT);
    expect(r.failed).toBe(0);
    expect(r.passed).toBe(4);
  });

  test("security regressions all hold", async () => {
    const r = await runSecurityRegressions();
    expect(r.failed).toBe(0);
    expect(r.passed).toBeGreaterThanOrEqual(4);
  });

  test("AI-implementation suite passes", () => {
    const r = runAiImplementationSuite(ROOT);
    expect(r.failed).toBe(0);
  });

  test("compatibility-label runner passes for tf-home-compatible offline", async () => {
    const r = await runCompatibilityLabel({ profileId: "tf-home-compatible" });
    expect(r.failed).toBe(0);
    expect(r.cases.length).toBe(1);
  });

  test("compatibility-label runner rejects unknown profile", async () => {
    const r = await runCompatibilityLabel({ profileId: "tf-not-real-compatible" });
    expect(r.failed).toBe(1);
    expect(r.passed).toBe(0);
  });

  test("runAll: full conformance run is green", async () => {
    const r = await runAll({ root: ROOT });
    expect(r.failed).toBe(0);
    expect(r.passed).toBeGreaterThan(300);
    const categories = new Set(r.reports.map((rr) => rr.category));
    for (const c of [
      "schema",
      "signature",
      "guard",
      "trust-overlay",
      "bridge",
      "interop",
      "fuzz",
      "profile",
      "security",
      "ai-implementation",
      "decide-protocol",
      "binary-format",
      "label",
    ]) {
      expect(categories.has(c)).toBe(true);
    }
  });
});

describe("tf-conformance — decide-protocol parity", () => {
  test("decide-protocol vectors all canonicalize identically", async () => {
    const r = runDecideProtocolVectors(ROOT);
    expect(r.failed).toBe(0);
    expect(r.passed).toBe(24);
  });
});

describe("tf-conformance — binary-format parity", () => {
  test("binary-format vectors round-trip identically", async () => {
    const r = runBinaryFormatVectors(ROOT);
    expect(r.failed).toBe(0);
    expect(r.passed).toBe(8);
  });
});
