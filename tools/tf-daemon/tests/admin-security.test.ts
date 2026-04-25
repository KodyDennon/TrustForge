import { describe, expect, test } from "bun:test";
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { ed25519Generate, ed25519Verify, sha256, canonicalize } from "tf-types";
import { Vault } from "tf-types";
import { runDaemon } from "../src/index";

async function bootDaemon(dir: string, opts: {
  adminToken?: string;
  adminBind?: string;
  maxBodyBytes?: number;
} = {}) {
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
project: admin-security-e2e
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
  const adminLine = `admin: { enabled: true, revocation_path: "${revocationPath}"${opts.adminBind ? `, bind: "${opts.adminBind}"` : ""}${opts.maxBodyBytes ? `, max_body_bytes: ${opts.maxBodyBytes}` : ""} }`;
  writeFileSync(
    configPath,
    `daemon_version: "1"
self_actor: "tf:actor:service:example.com/tf-daemon"
listen: { kind: websocket, bind: "127.0.0.1", port: 0 }
vault: { path: "${join(dir, "vault.json")}" }
contract_path: "${contractPath}"
proof_log_path: "${proofLogPath}"
${adminLine}
`,
  );

  if (opts.adminToken) process.env.TF_ADMIN_TOKEN = opts.adminToken;
  const daemon = await runDaemon({ configPath, passphrase: "dev-pw" });
  return { daemon, daemonId, revocationPath, proofLogPath };
}

describe("daemon admin security", () => {
  test("constant-time auth — close-prefix wrong tokens still get 403", async () => {
    const dir = mkdtempSync(join(tmpdir(), "tf-daemon-sec-"));
    try {
      const { daemon } = await bootDaemon(dir, { adminToken: "secret-correct-token" });
      // Off-by-one-byte token must reject identically to a totally-wrong one.
      const wrongClose = await fetch(`http://127.0.0.1:${daemon.port}/admin/sessions`, {
        headers: { authorization: "Bearer secret-correct-tokes" }, // last char differs
      });
      const wrongFar = await fetch(`http://127.0.0.1:${daemon.port}/admin/sessions`, {
        headers: { authorization: "Bearer xxxxxxxxxxxxxxxxxxxxx" },
      });
      expect(wrongClose.status).toBe(403);
      expect(wrongFar.status).toBe(403);
      await daemon.stop();
    } finally {
      delete process.env.TF_ADMIN_TOKEN;
      rmSync(dir, { recursive: true, force: true });
    }
  });

  test("host header check rejects non-loopback host even with valid token", async () => {
    const dir = mkdtempSync(join(tmpdir(), "tf-daemon-sec-"));
    try {
      const token = "secret-host";
      const { daemon } = await bootDaemon(dir, { adminToken: token });
      const res = await fetch(`http://127.0.0.1:${daemon.port}/admin/sessions`, {
        headers: { authorization: `Bearer ${token}`, host: "evil.example.com" },
      });
      expect(res.status).toBe(403);
      await daemon.stop();
    } finally {
      delete process.env.TF_ADMIN_TOKEN;
      rmSync(dir, { recursive: true, force: true });
    }
  });

  test("revocation POST is idempotent on (target_kind,target_id)", async () => {
    const dir = mkdtempSync(join(tmpdir(), "tf-daemon-sec-"));
    try {
      const token = "secret-idem";
      const { daemon, revocationPath } = await bootDaemon(dir, { adminToken: token });
      const headers = { authorization: `Bearer ${token}`, "content-type": "application/json" };
      const body = JSON.stringify({ kind: "actor", id: "tf:actor:agent:example.com/x", reason: "first" });
      const a = await fetch(`http://127.0.0.1:${daemon.port}/admin/revocations`, { method: "POST", headers, body });
      const b = await fetch(`http://127.0.0.1:${daemon.port}/admin/revocations`, { method: "POST", headers, body });
      expect(a.status).toBe(200);
      expect(b.status).toBe(200);
      const aJson = (await a.json()) as { deduped?: boolean };
      const bJson = (await b.json()) as { deduped?: boolean };
      expect(aJson.deduped).toBeUndefined();
      expect(bJson.deduped).toBe(true);
      const list = JSON.parse(readFileSync(revocationPath, "utf8")) as Array<{ target_id: string }>;
      expect(list.length).toBe(1);
      await daemon.stop();
    } finally {
      delete process.env.TF_ADMIN_TOKEN;
      rmSync(dir, { recursive: true, force: true });
    }
  });

  test("revocation is signed by the daemon identity", async () => {
    const dir = mkdtempSync(join(tmpdir(), "tf-daemon-sec-"));
    try {
      const token = "secret-sig";
      const { daemon, daemonId, revocationPath } = await bootDaemon(dir, { adminToken: token });
      const headers = { authorization: `Bearer ${token}`, "content-type": "application/json" };
      await fetch(`http://127.0.0.1:${daemon.port}/admin/revocations`, {
        method: "POST",
        headers,
        body: JSON.stringify({ kind: "actor", id: "tf:actor:agent:example.com/y" }),
      });
      const list = JSON.parse(readFileSync(revocationPath, "utf8")) as Array<{
        revocation_version: string;
        id: string;
        target_id: string;
        target_kind: string;
        effective_at: string;
        reason: string;
        issuer: string;
        signature: { algorithm: string; signer: string; signature: string };
      }>;
      expect(list.length).toBe(1);
      const rev = list[0]!;
      expect(rev.signature.algorithm).toBe("ed25519");
      expect(rev.signature.signature.length).toBeGreaterThan(0);
      // Re-derive the digest the daemon signed and verify against the
      // daemon's public key.
      const baseRev = {
        revocation_version: rev.revocation_version,
        id: rev.id,
        target_id: rev.target_id,
        target_kind: rev.target_kind,
        effective_at: rev.effective_at,
        reason: rev.reason,
        issuer: rev.issuer,
      };
      const digest = sha256(new TextEncoder().encode(canonicalize(baseRev)));
      const sigBytes = new Uint8Array(Buffer.from(rev.signature.signature, "base64"));
      const ok = await ed25519Verify(daemonId.publicKey, digest, sigBytes);
      expect(ok).toBe(true);
      await daemon.stop();
    } finally {
      delete process.env.TF_ADMIN_TOKEN;
      rmSync(dir, { recursive: true, force: true });
    }
  });

  test("oversize POST body returns 413", async () => {
    const dir = mkdtempSync(join(tmpdir(), "tf-daemon-sec-"));
    try {
      const token = "secret-cap";
      const { daemon } = await bootDaemon(dir, { adminToken: token, maxBodyBytes: 256 });
      const headers = {
        authorization: `Bearer ${token}`,
        "content-type": "application/json",
      };
      const big = JSON.stringify({ kind: "actor", id: "x", reason: "x".repeat(1024) });
      const res = await fetch(`http://127.0.0.1:${daemon.port}/admin/revocations`, {
        method: "POST",
        headers,
        body: big,
      });
      expect(res.status).toBe(413);
      await daemon.stop();
    } finally {
      delete process.env.TF_ADMIN_TOKEN;
      rmSync(dir, { recursive: true, force: true });
    }
  });

  test("malformed JSON POST returns 400, not 500", async () => {
    const dir = mkdtempSync(join(tmpdir(), "tf-daemon-sec-"));
    try {
      const token = "secret-bad";
      const { daemon } = await bootDaemon(dir, { adminToken: token });
      const res = await fetch(`http://127.0.0.1:${daemon.port}/admin/revocations`, {
        method: "POST",
        headers: { authorization: `Bearer ${token}`, "content-type": "application/json" },
        body: "{ not json",
      });
      expect(res.status).toBe(400);
      await daemon.stop();
    } finally {
      delete process.env.TF_ADMIN_TOKEN;
      rmSync(dir, { recursive: true, force: true });
    }
  });

  test("invalid revocation kind rejected with 400", async () => {
    const dir = mkdtempSync(join(tmpdir(), "tf-daemon-sec-"));
    try {
      const token = "secret-kind";
      const { daemon } = await bootDaemon(dir, { adminToken: token });
      const res = await fetch(`http://127.0.0.1:${daemon.port}/admin/revocations`, {
        method: "POST",
        headers: { authorization: `Bearer ${token}`, "content-type": "application/json" },
        body: JSON.stringify({ kind: "wat", id: "x" }),
      });
      expect(res.status).toBe(400);
      await daemon.stop();
    } finally {
      delete process.env.TF_ADMIN_TOKEN;
      rmSync(dir, { recursive: true, force: true });
    }
  });

  test("rotated TF_ADMIN_TOKEN takes effect on the next request", async () => {
    const dir = mkdtempSync(join(tmpdir(), "tf-daemon-sec-"));
    try {
      const { daemon } = await bootDaemon(dir, { adminToken: "first-token" });
      const ok1 = await fetch(`http://127.0.0.1:${daemon.port}/admin/sessions`, {
        headers: { authorization: "Bearer first-token" },
      });
      expect(ok1.status).toBe(200);
      // Rotate.
      process.env.TF_ADMIN_TOKEN = "second-token";
      const ok2 = await fetch(`http://127.0.0.1:${daemon.port}/admin/sessions`, {
        headers: { authorization: "Bearer second-token" },
      });
      expect(ok2.status).toBe(200);
      const stale = await fetch(`http://127.0.0.1:${daemon.port}/admin/sessions`, {
        headers: { authorization: "Bearer first-token" },
      });
      expect(stale.status).toBe(403);
      await daemon.stop();
    } finally {
      delete process.env.TF_ADMIN_TOKEN;
      rmSync(dir, { recursive: true, force: true });
    }
  });
});
