import { describe, expect, test } from "bun:test";
import { mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { ed25519Generate, Vault } from "tf-types";
import { runDaemon, type DaemonHandle } from "../src/index";

interface BootedDaemon {
  daemon: DaemonHandle;
  dir: string;
  token: string;
  cleanup: () => void;
}

async function bootDaemon(): Promise<BootedDaemon> {
  const dir = mkdtempSync(join(tmpdir(), "tf-daemon-proof-"));
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
project: proof-e2e
trust_domain: example.com
actions: []
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
`,
  );

  const token = `dev-${Math.random().toString(16).slice(2)}`;
  process.env.TF_ADMIN_TOKEN = token;

  const daemon = await runDaemon({
    configPath,
    passphrase: "dev-pw",
    daemonHttpPort: 0,
    daemonHttpSocket: "",
  });

  return {
    daemon,
    dir,
    token,
    cleanup: () => {
      delete process.env.TF_ADMIN_TOKEN;
      rmSync(dir, { recursive: true, force: true });
    },
  };
}

function urlOf(daemon: DaemonHandle, path: string): string {
  return `http://127.0.0.1:${daemon.httpPort}${path}`;
}

describe("tf-daemon /v1/proof/sign + /v1/proof/verify", () => {
  test("sign + verify round-trip", async () => {
    const ctx = await bootDaemon();
    try {
      const draft = {
        event_version: "1",
        id: "ev-test-1",
        type: "test.event",
        actor_id: "tf:actor:service:example.com/tf-daemon",
        timestamp: new Date().toISOString(),
        level: "L1",
        context: { hello: "world" },
      };
      const signRes = await fetch(urlOf(ctx.daemon, "/v1/proof/sign"), {
        method: "POST",
        headers: {
          authorization: `Bearer ${ctx.token}`,
          "content-type": "application/json",
        },
        body: JSON.stringify(draft),
      });
      expect(signRes.status).toBe(200);
      const signBody = (await signRes.json()) as { event_hash: string; signature: { signature: string; signer: string }; signed_event: Record<string, unknown> };
      expect(signBody.event_hash.startsWith("sha256:")).toBe(true);
      expect(typeof signBody.signature.signature).toBe("string");
      expect(signBody.signature.signer).toBe("tf:actor:service:example.com/tf-daemon");

      const verifyRes = await fetch(urlOf(ctx.daemon, "/v1/proof/verify"), {
        method: "POST",
        headers: {
          authorization: `Bearer ${ctx.token}`,
          "content-type": "application/json",
        },
        body: JSON.stringify(signBody.signed_event),
      });
      expect(verifyRes.status).toBe(200);
      const verifyBody = (await verifyRes.json()) as { ok: boolean; signer_actor: string; trust_level: string };
      expect(verifyBody.ok).toBe(true);
      expect(verifyBody.signer_actor).toBe("tf:actor:service:example.com/tf-daemon");
      expect(verifyBody.trust_level).toBe("T2");
    } finally {
      await ctx.daemon.stop();
      ctx.cleanup();
    }
  });

  test("verify rejects forged signature", async () => {
    const ctx = await bootDaemon();
    try {
      const draft = {
        event_version: "1",
        id: "ev-test-2",
        type: "test.event",
        actor_id: "tf:actor:service:example.com/tf-daemon",
        timestamp: new Date().toISOString(),
        level: "L1",
      };
      const signRes = await fetch(urlOf(ctx.daemon, "/v1/proof/sign"), {
        method: "POST",
        headers: {
          authorization: `Bearer ${ctx.token}`,
          "content-type": "application/json",
        },
        body: JSON.stringify(draft),
      });
      const signBody = (await signRes.json()) as { signed_event: Record<string, unknown> };
      // Tamper with the event by mutating the type field.
      const tampered = {
        ...signBody.signed_event,
        type: "tampered.event",
      };
      const verifyRes = await fetch(urlOf(ctx.daemon, "/v1/proof/verify"), {
        method: "POST",
        headers: {
          authorization: `Bearer ${ctx.token}`,
          "content-type": "application/json",
        },
        body: JSON.stringify(tampered),
      });
      expect(verifyRes.status).toBe(200);
      const verifyBody = (await verifyRes.json()) as { ok: boolean; trust_level: string };
      expect(verifyBody.ok).toBe(false);
      expect(verifyBody.trust_level).toBe("T0");
    } finally {
      await ctx.daemon.stop();
      ctx.cleanup();
    }
  });

  test("verify rejects unknown signer", async () => {
    const ctx = await bootDaemon();
    try {
      // Build a syntactically-valid signed event but with a different
      // signer actor — the daemon only recognizes its own self_actor.
      const event = {
        event_version: "1",
        id: "ev-foreign-1",
        type: "test.event",
        actor_id: "tf:actor:service:other.example/foreign",
        timestamp: new Date().toISOString(),
        level: "L1",
        signature: {
          algorithm: "ed25519",
          signer: "tf:actor:service:other.example/foreign",
          signature: Buffer.from(new Uint8Array(64)).toString("base64"),
        },
      };
      const verifyRes = await fetch(urlOf(ctx.daemon, "/v1/proof/verify"), {
        method: "POST",
        headers: {
          authorization: `Bearer ${ctx.token}`,
          "content-type": "application/json",
        },
        body: JSON.stringify(event),
      });
      expect(verifyRes.status).toBe(200);
      const verifyBody = (await verifyRes.json()) as { ok: boolean };
      expect(verifyBody.ok).toBe(false);
    } finally {
      await ctx.daemon.stop();
      ctx.cleanup();
    }
  });

  test("sign rejects malformed proof draft (missing required fields)", async () => {
    const ctx = await bootDaemon();
    try {
      const res = await fetch(urlOf(ctx.daemon, "/v1/proof/sign"), {
        method: "POST",
        headers: {
          authorization: `Bearer ${ctx.token}`,
          "content-type": "application/json",
        },
        body: JSON.stringify({ event_version: "1", type: "test.event" }),
      });
      expect(res.status).toBe(400);
    } finally {
      await ctx.daemon.stop();
      ctx.cleanup();
    }
  });

  test("missing admin token returns 401 on sign + verify", async () => {
    const ctx = await bootDaemon();
    try {
      const res = await fetch(urlOf(ctx.daemon, "/v1/proof/sign"), {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: "{}",
      });
      expect(res.status).toBe(401);
      const res2 = await fetch(urlOf(ctx.daemon, "/v1/proof/verify"), {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: "{}",
      });
      expect(res2.status).toBe(401);
    } finally {
      await ctx.daemon.stop();
      ctx.cleanup();
    }
  });
});
