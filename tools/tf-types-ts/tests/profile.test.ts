import { describe, expect, test } from "bun:test";
import {
  BUILTIN_PROFILES,
  buildProfileFeatureGate,
  selectProfile,
} from "../src/core/profile";

const HOME_FEATURES = ["agent-contract", "proof-log", "ed25519", "vault"];
const ENT_FEATURES = [
  "policy-engine",
  "quorum-collector",
  "continuous-reauth",
  "transparency-anchor.any",
  "federation",
  "webauthn",
  "agent-contract",
];
const CONST_FEATURES = [
  "packet-mode",
  "fragment-reassembly",
  "offline-revocation-list",
  "emergency-authority",
];
const COMP_FEATURES = [
  "policy-engine",
  "quorum-collector",
  "signed-log-events",
  "evidence-bundle",
  "l4-encrypted-bundle",
  "l5-rfc3161-anchor",
  "continuous-reauth",
];

describe("selectProfile — happy paths for built-in profiles", () => {
  test("tf-home-compatible accepts a fully-featured home daemon", () => {
    const gate = buildProfileFeatureGate({
      features: HOME_FEATURES,
      enforcementLevel: "E3",
      proofLevelFloor: "L1",
      bridges: [],
      anchors: ["memory"],
    });
    const verdict = selectProfile(BUILTIN_PROFILES["tf-home-compatible"]!, gate);
    expect(verdict.ok).toBe(true);
    expect(verdict.failures).toEqual([]);
    expect(verdict.profile).toBe("tf-home-compatible");
  });

  test("tf-enterprise-compatible accepts when bridges + anchors present", () => {
    const gate = buildProfileFeatureGate({
      features: ENT_FEATURES,
      enforcementLevel: "E4",
      proofLevelFloor: "L2",
      bridges: ["webauthn", "oauth", "spiffe"],
      anchors: ["rfc6962"],
    });
    const verdict = selectProfile(BUILTIN_PROFILES["tf-enterprise-compatible"]!, gate);
    expect(verdict.ok).toBe(true);
    expect(verdict.failures).toEqual([]);
  });

  test("tf-constrained-compatible accepts a packet-mode daemon", () => {
    const gate = buildProfileFeatureGate({
      features: CONST_FEATURES,
      enforcementLevel: "E3",
      proofLevelFloor: "L1",
      bridges: [],
      anchors: [],
    });
    const verdict = selectProfile(BUILTIN_PROFILES["tf-constrained-compatible"]!, gate);
    expect(verdict.ok).toBe(true);
  });

  test("tf-compliance-evidence-compatible accepts when both anchors present", () => {
    const gate = buildProfileFeatureGate({
      features: COMP_FEATURES,
      enforcementLevel: "E4",
      proofLevelFloor: "L3",
      bridges: [],
      anchors: ["rfc6962", "rfc3161"],
    });
    const verdict = selectProfile(BUILTIN_PROFILES["tf-compliance-evidence-compatible"]!, gate);
    expect(verdict.ok).toBe(true);
  });
});

describe("selectProfile — MUST rejection", () => {
  test("missing required feature fails with a specific error", () => {
    const gate = buildProfileFeatureGate({
      features: HOME_FEATURES.filter((f) => f !== "vault"),
      enforcementLevel: "E3",
      proofLevelFloor: "L1",
      bridges: [],
      anchors: [],
    });
    const verdict = selectProfile(BUILTIN_PROFILES["tf-home-compatible"]!, gate);
    expect(verdict.ok).toBe(false);
    expect(verdict.failures.some((f) => f.includes('"vault"'))).toBe(true);
  });

  test("multiple missing MUST features are all reported", () => {
    const gate = buildProfileFeatureGate({
      features: ["agent-contract"],
      enforcementLevel: "E4",
      proofLevelFloor: "L2",
      bridges: ["webauthn", "oauth", "spiffe"],
      anchors: ["rfc6962"],
    });
    const verdict = selectProfile(BUILTIN_PROFILES["tf-enterprise-compatible"]!, gate);
    expect(verdict.ok).toBe(false);
    expect(verdict.failures.length).toBeGreaterThanOrEqual(6);
  });
});

describe("selectProfile — MUST_NOT rejection", () => {
  test("forbidden feature fails", () => {
    const gate = buildProfileFeatureGate({
      features: [...CONST_FEATURES, "transport.websocket-only"],
      enforcementLevel: "E3",
      proofLevelFloor: "L1",
      bridges: [],
      anchors: [],
    });
    const verdict = selectProfile(BUILTIN_PROFILES["tf-constrained-compatible"]!, gate);
    expect(verdict.ok).toBe(false);
    expect(verdict.failures.some((f) => f.includes("forbids"))).toBe(true);
  });
});

describe("selectProfile — enforcement floor", () => {
  test("enforcement below floor fails", () => {
    const gate = buildProfileFeatureGate({
      features: HOME_FEATURES,
      enforcementLevel: "E1",
      proofLevelFloor: "L1",
      bridges: [],
      anchors: [],
    });
    const verdict = selectProfile(BUILTIN_PROFILES["tf-home-compatible"]!, gate);
    expect(verdict.ok).toBe(false);
    expect(verdict.failures.some((f) => f.includes("EnforcementLevel"))).toBe(true);
  });

  test("enforcement above floor passes", () => {
    const gate = buildProfileFeatureGate({
      features: HOME_FEATURES,
      enforcementLevel: "E5",
      proofLevelFloor: "L1",
      bridges: [],
      anchors: [],
    });
    const verdict = selectProfile(BUILTIN_PROFILES["tf-home-compatible"]!, gate);
    expect(verdict.ok).toBe(true);
  });
});

describe("selectProfile — proof level floor", () => {
  test("proof floor below requirement fails", () => {
    const gate = buildProfileFeatureGate({
      features: ENT_FEATURES,
      enforcementLevel: "E4",
      proofLevelFloor: "L1",
      bridges: ["webauthn", "oauth", "spiffe"],
      anchors: ["rfc6962"],
    });
    const verdict = selectProfile(BUILTIN_PROFILES["tf-enterprise-compatible"]!, gate);
    expect(verdict.ok).toBe(false);
    expect(verdict.failures.some((f) => f.includes("proof level floor"))).toBe(true);
  });
});

describe("selectProfile — required bridges", () => {
  test("missing bridge fails", () => {
    const gate = buildProfileFeatureGate({
      features: ENT_FEATURES,
      enforcementLevel: "E4",
      proofLevelFloor: "L2",
      bridges: ["webauthn", "oauth"], // missing spiffe
      anchors: ["rfc6962"],
    });
    const verdict = selectProfile(BUILTIN_PROFILES["tf-enterprise-compatible"]!, gate);
    expect(verdict.ok).toBe(false);
    expect(verdict.failures.some((f) => f.includes("bridge spiffe"))).toBe(true);
  });
});

describe("selectProfile — required anchors", () => {
  test("missing anchor fails", () => {
    const gate = buildProfileFeatureGate({
      features: COMP_FEATURES,
      enforcementLevel: "E4",
      proofLevelFloor: "L3",
      bridges: [],
      anchors: ["rfc6962"], // missing rfc3161
    });
    const verdict = selectProfile(BUILTIN_PROFILES["tf-compliance-evidence-compatible"]!, gate);
    expect(verdict.ok).toBe(false);
    expect(verdict.failures.some((f) => f.includes("rfc3161"))).toBe(true);
  });
});

describe("selectProfile — SHOULD warnings", () => {
  test("missing recommended feature is a warning, not a failure", () => {
    const gate = buildProfileFeatureGate({
      features: HOME_FEATURES, // does not include `webauthn` or `shadow-mode`
      enforcementLevel: "E3",
      proofLevelFloor: "L1",
      bridges: [],
      anchors: [],
    });
    const verdict = selectProfile(BUILTIN_PROFILES["tf-home-compatible"]!, gate);
    expect(verdict.ok).toBe(true);
    expect(verdict.warnings.length).toBe(2);
    expect(verdict.warnings.some((w) => w.includes("webauthn"))).toBe(true);
    expect(verdict.warnings.some((w) => w.includes("shadow-mode"))).toBe(true);
  });
});
