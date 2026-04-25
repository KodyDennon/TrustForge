import { describe, expect, test } from "bun:test";
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { ed25519Generate, Vault } from "tf-types";
import { runDaemon } from "../src/index";

async function bootDaemon(dir: string, opts: { adminToken?: string } = {}) {
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
project: admin-e2e
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
  const revocationPath = join(dir, "revocations.json");
  writeFileSync(
    configPath,
    `daemon_version: "1"
self_actor: "tf:actor:service:example.com/tf-daemon"
listen: { kind: websocket, bind: "127.0.0.1", port: 0 }
vault: { path: "${join(dir, "vault.json")}" }
contract_path: "${contractPath}"
proof_log_path: "${proofLogPath}"
admin: { enabled: true, revocation_path: "${revocationPath}" }
`,
  );

  if (opts.adminToken) {
    process.env.TF_ADMIN_TOKEN = opts.adminToken;
  }

  return {
    daemon: await runDaemon({ configPath, passphrase: "dev-pw" }),
    revocationPath,
  };
}

describe("tf-daemon admin HTTP", () => {
  test("/healthz returns 200 without a token", async () => {
    const dir = mkdtempSync(join(tmpdir(), "tf-daemon-admin-"));
    try {
      const { daemon } = await bootDaemon(dir, { adminToken: "secret-1" });
      const res = await fetch(`http://127.0.0.1:${daemon.port}/healthz`);
      expect(res.status).toBe(200);
      const j = (await res.json()) as { ok: boolean };
      expect(j.ok).toBe(true);
      await daemon.stop();
    } finally {
      delete process.env.TF_ADMIN_TOKEN;
      rmSync(dir, { recursive: true, force: true });
    }
  });

  test("/admin/* without token returns 403", async () => {
    const dir = mkdtempSync(join(tmpdir(), "tf-daemon-admin-"));
    try {
      const { daemon } = await bootDaemon(dir, { adminToken: "secret-2" });
      const res = await fetch(`http://127.0.0.1:${daemon.port}/admin/sessions`);
      expect(res.status).toBe(403);
      await daemon.stop();
    } finally {
      delete process.env.TF_ADMIN_TOKEN;
      rmSync(dir, { recursive: true, force: true });
    }
  });

  test("/admin/sessions and /admin/approvals return JSON when authenticated", async () => {
    const dir = mkdtempSync(join(tmpdir(), "tf-daemon-admin-"));
    try {
      const token = "secret-3";
      const { daemon } = await bootDaemon(dir, { adminToken: token });
      const headers = { authorization: `Bearer ${token}` };
      const sRes = await fetch(`http://127.0.0.1:${daemon.port}/admin/sessions`, { headers });
      expect(sRes.status).toBe(200);
      const sJson = (await sRes.json()) as { sessions: unknown[] };
      expect(Array.isArray(sJson.sessions)).toBe(true);
      const aRes = await fetch(`http://127.0.0.1:${daemon.port}/admin/approvals`, { headers });
      expect(aRes.status).toBe(200);
      const aJson = (await aRes.json()) as { approvals: unknown[] };
      expect(Array.isArray(aJson.approvals)).toBe(true);
      await daemon.stop();
    } finally {
      delete process.env.TF_ADMIN_TOKEN;
      rmSync(dir, { recursive: true, force: true });
    }
  });

  test("POST /admin/revocations appends to the configured revocation file", async () => {
    const dir = mkdtempSync(join(tmpdir(), "tf-daemon-admin-"));
    try {
      const token = "secret-4";
      const { daemon, revocationPath } = await bootDaemon(dir, { adminToken: token });
      const res = await fetch(`http://127.0.0.1:${daemon.port}/admin/revocations`, {
        method: "POST",
        headers: { authorization: `Bearer ${token}`, "content-type": "application/json" },
        body: JSON.stringify({ kind: "actor", id: "tf:actor:agent:example.com/bad", reason: "test" }),
      });
      expect(res.status).toBe(200);
      const list = JSON.parse(readFileSync(revocationPath, "utf8")) as Array<{ target_id: string; target_kind: string }>;
      expect(list.length).toBe(1);
      expect(list[0]!.target_id).toBe("tf:actor:agent:example.com/bad");
      expect(list[0]!.target_kind).toBe("actor");
      await daemon.stop();
    } finally {
      delete process.env.TF_ADMIN_TOKEN;
      rmSync(dir, { recursive: true, force: true });
    }
  });

  test("POST /admin/approvals/:id/approve resolves a pending approval", async () => {
    const dir = mkdtempSync(join(tmpdir(), "tf-daemon-admin-"));
    try {
      const token = "secret-5";
      const { daemon } = await bootDaemon(dir, { adminToken: token });

      const id = "test-approval-1";
      const promise = daemon.approvalQueue.push({
        request_version: "1",
        id,
        actor: "tf:actor:agent:example.com/x",
        action: "tf.write",
        danger_tags: [],
        reason: "test",
        created_at: new Date().toISOString(),
      });

      const res = await fetch(`http://127.0.0.1:${daemon.port}/admin/approvals/${id}/approve`, {
        method: "POST",
        headers: { authorization: `Bearer ${token}`, "content-type": "application/json" },
        body: JSON.stringify({ note: "ok by test" }),
      });
      expect(res.status).toBe(200);
      const decision = await promise;
      expect(decision.decision).toBe("approve");
      expect(decision.note).toBe("ok by test");
      await daemon.stop();
    } finally {
      delete process.env.TF_ADMIN_TOKEN;
      rmSync(dir, { recursive: true, force: true });
    }
  });

  test("/admin/proofs returns events from the .tflog", async () => {
    const dir = mkdtempSync(join(tmpdir(), "tf-daemon-admin-"));
    try {
      const token = "secret-6";
      const { daemon } = await bootDaemon(dir, { adminToken: token });

      // Push and resolve an approval so an event lands in the .tflog.
      const id = "test-approval-2";
      const promise = daemon.approvalQueue.push({
        request_version: "1",
        id,
        actor: "tf:actor:agent:example.com/x",
        action: "tf.write",
        danger_tags: [],
        reason: "test",
        created_at: new Date().toISOString(),
      });
      daemon.approvalQueue.respond(id, "approve");
      await promise;

      const res = await fetch(`http://127.0.0.1:${daemon.port}/admin/proofs?n=10`, {
        headers: { authorization: `Bearer ${token}` },
      });
      expect(res.status).toBe(200);
      const j = (await res.json()) as { events: Array<Record<string, unknown>> };
      expect(j.events.length).toBeGreaterThan(0);
      await daemon.stop();
    } finally {
      delete process.env.TF_ADMIN_TOKEN;
      rmSync(dir, { recursive: true, force: true });
    }
  });
});
