import { describe, expect, test } from "bun:test";
import { mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { ed25519Generate, Vault } from "tf-types";
import { runDaemon } from "../../tf-daemon/src/index";
import { startDashboard } from "../src/index";

async function bootDaemonWithAdmin(dir: string, token: string) {
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
project: dashboard-e2e
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
admin: { enabled: true }
`,
  );
  process.env.TF_ADMIN_TOKEN = token;
  return runDaemon({ configPath, passphrase: "dev-pw" });
}

describe("tf-dashboard", () => {
  test("serves the index HTML and proxies /api/admin/* through to the daemon", async () => {
    const dir = mkdtempSync(join(tmpdir(), "tf-dash-"));
    try {
      const token = "dash-token-1";
      const daemon = await bootDaemonWithAdmin(dir, token);
      const dash = startDashboard({
        daemonUrl: `http://127.0.0.1:${daemon.port}`,
        adminToken: token,
      });

      try {
        const indexRes = await fetch(`${dash.url}/`);
        expect(indexRes.status).toBe(200);
        const html = await indexRes.text();
        expect(html).toContain("TrustForge dashboard");
        expect(html).toContain("__TF_DASH__");

        const sessionsRes = await fetch(`${dash.url}/api/admin/sessions`);
        expect(sessionsRes.status).toBe(200);
        const sessionsJson = (await sessionsRes.json()) as { sessions: unknown[] };
        expect(Array.isArray(sessionsJson.sessions)).toBe(true);

        const approvalsRes = await fetch(`${dash.url}/api/admin/approvals`);
        expect(approvalsRes.status).toBe(200);
        const approvalsJson = (await approvalsRes.json()) as { approvals: unknown[] };
        expect(Array.isArray(approvalsJson.approvals)).toBe(true);
      } finally {
        dash.stop();
        await daemon.stop();
      }
    } finally {
      delete process.env.TF_ADMIN_TOKEN;
      rmSync(dir, { recursive: true, force: true });
    }
  });

  test("reports a connection failure when the daemon URL is wrong", async () => {
    const dash = startDashboard({
      daemonUrl: "http://127.0.0.1:1", // unlikely to be listening
      adminToken: "irrelevant",
    });
    try {
      const res = await fetch(`${dash.url}/api/admin/sessions`);
      expect(res.status).toBeGreaterThanOrEqual(500);
    } finally {
      dash.stop();
    }
  });
});
