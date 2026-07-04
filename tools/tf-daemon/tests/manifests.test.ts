import { describe, expect, test } from "bun:test";
import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { ed25519Generate, Vault, type TfFeatureGate } from "@trustforge-protocol/types";
import { runDaemon } from "../src/index";

describe("Daemon loads .tf/ manifests when projectRoot is supplied", () => {
  test("featureGate exposes claimed_profiles + forbidden actions + per-action proof level", async () => {
    const dir = mkdtempSync(join(tmpdir(), "tf-daemon-manifests-"));
    try {
      const vault = await Vault.createAtPath(join(dir, "vault.json"), "dev-pw", {
        m_cost: 256,
        t_cost: 1,
        p_cost: 1,
      });
      const daemonId = await ed25519Generate();
      vault.store({
        id: "daemon-identity",
        purpose: "signing",
        algorithm: "ed25519",
        key_bytes: daemonId.privateKey,
      });

      const projectRoot = join(dir, "project");
      mkdirSync(join(projectRoot, ".tf"), { recursive: true });

      // Contract
      const contract = `
contract_version: "1"
spec_version: TF-0006-draft
project: daemon-manifests
trust_domain: example.com
actions:
  - name: tf.ping
    risk: R0
    approval: none
    reversible: true
forbidden:
  - action: shell.exec
    reason: never
`;
      const contractPath = join(projectRoot, ".tf", "agent-contract.yaml");
      writeFileSync(contractPath, contract);

      writeFileSync(
        join(projectRoot, ".tf", "policy.yaml"),
        `policy_version: "1"
trust_domain: example.com
rules:
  - id: allow.read
    effect: allow
    action: file.read
negative_capabilities:
  - name: shell.exec
    reason: shell is forbidden in this domain
`,
      );

      writeFileSync(
        join(projectRoot, ".tf", "proof-profile.yaml"),
        `proof_profile_version: "1"
trust_domain: example.com
default_proof_level: L1
actions:
  - name: payment.charge
    level: L4
    anchor: rfc6962
`,
      );

      writeFileSync(
        join(projectRoot, ".tf", "conformance.json"),
        JSON.stringify({
          conformance_version: "1",
          subject: "tf-svc-1",
          claimed_profiles: ["tf-core-compatible", "tf-bridge-compatible"],
          evidence: [{ kind: "test", id: "t1" }],
        }),
      );

      const configPath = join(dir, "daemon.yaml");
      const proofLogPath = join(dir, "proof.tflog");
      writeFileSync(
        configPath,
        `daemon_version: "1"
self_actor: "tf:actor:service:example.com/tf-daemon"
listen: { kind: websocket, bind: "127.0.0.1", port: 0 }
vault: { path: "${join(dir, "vault.json")}" }
contract_path: "${contractPath}"
proof_log_path: "${proofLogPath}"
approval_queue: { max_pending: 8, default_timeout_seconds: 30 }
`,
      );

      let gate: TfFeatureGate | undefined;
      const diagnostics: Array<{ file: string; reason: string }> = [];
      const daemon = await runDaemon({
        configPath,
        passphrase: "dev-pw",
        projectRoot,
        onFeatureGate: (g) => {
          gate = g;
        },
        onManifestDiagnostic: (d) => diagnostics.push(d),
      });
      try {
        expect(diagnostics).toEqual([]);
        expect(gate).toBeDefined();
        expect(gate!.claimedProfiles).toContain("tf-core-compatible");
        expect(gate!.forbiddenActions.has("shell.exec")).toBe(true);
        expect(gate!.proofLevelForAction("payment.charge")).toBe("L4");
        expect(gate!.defaultProofLevel).toBe("L1");
      } finally {
        await daemon.stop();
      }
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });
});
