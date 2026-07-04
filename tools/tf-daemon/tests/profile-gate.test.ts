import { describe, expect, test } from "bun:test";
import { mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { Vault, ed25519Generate } from "@trustforge-protocol/types";
import { runDaemon } from "../src/index";

async function setupSkeleton(dir: string, daemonYamlExtras: string) {
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
  const contractPath = join(dir, "contract.yaml");
  writeFileSync(
    contractPath,
    `contract_version: "1"
spec_version: TF-0006-draft
project: profile-gate-e2e
trust_domain: example.com
actions:
  - name: tf.ping
    risk: R0
    approval: none
    reversible: true
`,
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
${daemonYamlExtras}
`,
  );
  return { configPath };
}

describe("daemon profile gate uses the runtime feature inventory", () => {
  test("tf-home-compatible: minimum feature set passes", async () => {
    const dir = mkdtempSync(join(tmpdir(), "tf-daemon-profile-"));
    try {
      const { configPath } = await setupSkeleton(dir, `profile: tf-home-compatible
enforcement_level: E3`);
      let verdictOk = false;
      const daemon = await runDaemon({
        configPath,
        passphrase: "dev-pw",
        onProfileVerdict: (v) => {
          verdictOk = v.ok;
        },
      });
      expect(verdictOk).toBe(true);
      await daemon.stop();
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });

  test("tf-enterprise-compatible: refuses without quorum-collector + bridges + anchors", async () => {
    const dir = mkdtempSync(join(tmpdir(), "tf-daemon-profile-"));
    try {
      const { configPath } = await setupSkeleton(dir, `profile: tf-enterprise-compatible
enforcement_level: E4`);
      // No quorum_default, no plugins/bridges, no proof-profile anchors.
      // Pre-B4 the feature inventory was hardcoded and this would have
      // passed; post-B4 the gate refuses.
      let threw = false;
      try {
        await runDaemon({ configPath, passphrase: "dev-pw" });
      } catch (err) {
        threw = String(err).includes("not satisfied");
      }
      expect(threw).toBe(true);
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });

  test("tf-enterprise-compatible: passes when quorum_default is wired", async () => {
    const dir = mkdtempSync(join(tmpdir(), "tf-daemon-profile-"));
    try {
      const { configPath } = await setupSkeleton(
        dir,
        `profile: tf-enterprise-compatible
enforcement_level: E4
quorum_default:
  min_approvers: 2
  of:
    - "tf:actor:human:example.com/admin-1"
    - "tf:actor:human:example.com/admin-2"
    - "tf:actor:human:example.com/admin-3"`,
      );
      // Still fails the bridges + anchors floors because we haven't wired
      // any. Test asserts the THE PROFILE NOW REJECTS for a *different*
      // reason (quorum present, bridges/anchors absent) — proving the gate
      // sees the runtime change.
      let failures: string[] = [];
      try {
        await runDaemon({
          configPath,
          passphrase: "dev-pw",
          onProfileVerdict: (v) => {
            failures = v.failures;
          },
        });
      } catch {
        /* expected */
      }
      // We see specific bridge / anchor failures, not a generic
      // "quorum-collector missing".
      const joined = failures.join("|");
      expect(joined.includes("quorum-collector")).toBe(false);
      expect(joined.includes("bridge") || joined.includes("anchor")).toBe(true);
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });
});
