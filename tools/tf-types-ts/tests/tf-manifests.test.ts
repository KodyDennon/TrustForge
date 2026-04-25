import { describe, expect, test } from "bun:test";
import { mkdtempSync, mkdirSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { buildFeatureGate, loadTfManifests } from "../src/index";

function project(): string {
  const root = mkdtempSync(join(tmpdir(), "tf-manifests-"));
  mkdirSync(join(root, ".tf"));
  return root;
}

function w(root: string, rel: string, content: string): void {
  writeFileSync(join(root, rel), content);
}

describe("loadTfManifests", () => {
  test("loads every present manifest and skips absent ones", () => {
    const root = project();
    w(root, ".tf/agent-contract.yaml", "contract_version: \"1\"\nspec_version: TF-0006-draft\nproject: x\ntrust_domain: example.com\nactions: []\n");
    w(root, ".tf/policy.yaml", "policy_version: \"1\"\ntrust_domain: example.com\nrules:\n  - id: allow.read\n    effect: allow\n    action: file.read\n");
    w(root, ".tf/proof-profile.yaml", "profile_version: \"1\"\ntrust_domain: example.com\nemit:\n  - event_type: rpc.call\n    level: L1\n    anchor: local\n");
    w(root, ".tf/conformance.json", JSON.stringify({ conformance_version: "1", subject: "tf-svc-1", claimed_profiles: ["tf-core-compatible"], evidence: [{ kind: "test", id: "t1" }] }));
    w(root, ".tf/codegen.toml", "ts_target = \"src/generated\"\nrust_target = \"crates/types/src/generated\"\n");
    const m = loadTfManifests({ rootDir: root });
    expect(m.diagnostics).toEqual([]);
    expect(m.agentContract).toBeDefined();
    expect(m.policy).toBeDefined();
    expect(m.proofProfile).toBeDefined();
    expect(m.conformance).toBeDefined();
    expect(m.codegen).toEqual({
      ts_target: "src/generated",
      rust_target: "crates/types/src/generated",
    });
    expect(m.threatModel).toBeUndefined();
  });

  test("records a diagnostic on parse failure", () => {
    const root = project();
    w(root, ".tf/policy.yaml", "policy_version: \"1\"\nrules: not-a-valid-list\n");
    w(root, ".tf/conformance.json", "this is not json {");
    const m = loadTfManifests({ rootDir: root });
    expect(m.diagnostics.some((d) => d.file.endsWith("conformance.json"))).toBe(true);
    // policy.yaml parses (YAML accepts the string) but the engine layer
    // would reject it; loader still passes the raw value through.
    expect(m.policy).toBeDefined();
  });

  test("buildFeatureGate composes an actionable runtime view", () => {
    const root = project();
    w(
      root,
      ".tf/agent-contract.yaml",
      "contract_version: \"1\"\nspec_version: TF-0006-draft\nproject: x\ntrust_domain: example.com\nactions: []\nforbidden:\n  - action: shell.exec\n    reason: never\n",
    );
    w(
      root,
      ".tf/proof-profile.yaml",
      "proof_profile_version: \"1\"\ntrust_domain: example.com\ndefault_proof_level: L1\nactions:\n  - name: payment.charge\n    level: L4\n    anchor: rfc6962\n",
    );
    w(
      root,
      ".tf/conformance.json",
      JSON.stringify({
        conformance_version: "1",
        subject: "tf-svc-1",
        claimed_profiles: ["tf-core-compatible", "tf-bridge-compatible"],
        evidence: [{ kind: "test", id: "t1" }],
      }),
    );
    const m = loadTfManifests({ rootDir: root });
    const gate = buildFeatureGate(m);
    expect(gate.claimedProfiles).toContain("tf-core-compatible");
    expect(gate.proofLevelForAction("payment.charge")).toBe("L4");
    expect(gate.proofLevelForAction("file.read")).toBeUndefined();
    expect(gate.defaultProofLevel).toBe("L1");
    expect(gate.forbiddenActions.has("shell.exec")).toBe(true);
  });
});
