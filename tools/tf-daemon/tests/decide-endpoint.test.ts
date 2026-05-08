import { describe, expect, test } from "bun:test";
import { mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { createConnection } from "node:net";
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
  const dir = mkdtempSync(join(tmpdir(), "tf-daemon-decide-"));
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
project: decide-e2e
trust_domain: example.com
actions:
  - name: fs.read
    risk: R0
    approval: none
    reversible: true
  - name: fs.write
    risk: R1
    approval: required
    reversible: true
forbidden:
  - action: fs.delete
    reason: "fs.delete forbidden in test contract"
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

function decideUrl(daemon: DaemonHandle, path: string): string {
  return `http://127.0.0.1:${daemon.httpPort}${path}`;
}

async function requestUnixSocket(
  socketPath: string,
  path: string,
  body: unknown,
  headers: Record<string, string> = {},
): Promise<{ status: number; headers: Record<string, string>; body: string }> {
  const payload = JSON.stringify(body);
  const rawHeaders = [
    `POST ${path} HTTP/1.1`,
    "Host: localhost",
    "Content-Type: application/json",
    `Content-Length: ${Buffer.byteLength(payload)}`,
    ...Object.entries(headers).map(([k, v]) => `${k}: ${v}`),
    "Connection: close",
    "",
    payload,
  ].join("\r\n");

  return await new Promise((resolve, reject) => {
    const chunks: Buffer[] = [];
    let settled = false;
    const socket = createConnection(socketPath);
    socket.setEncoding("utf8");
    socket.on("connect", () => socket.write(rawHeaders));
    socket.setTimeout(2_000, () => {
      if (!settled) {
        settled = true;
        socket.destroy();
        reject(new Error(`timed out waiting for ${path} response over ${socketPath}`));
      }
    });
    socket.on("data", (chunk) => {
      chunks.push(Buffer.from(chunk));
      const raw = Buffer.concat(chunks).toString("utf8");
      const split = raw.indexOf("\r\n\r\n");
      if (split < 0) return;
      const head = raw.slice(0, split);
      const contentLength = Number(/^content-length:\s*(\d+)/im.exec(head)?.[1] ?? 0);
      const responseBody = raw.slice(split + 4);
      if (Buffer.byteLength(responseBody) < contentLength) return;
      if (settled) return;
      settled = true;
      socket.end();
      resolve(parseHttpResponse(raw));
    });
    socket.on("error", (err) => {
      if (!settled) reject(err);
    });
    socket.on("end", () => {
      if (settled) return;
      settled = true;
      const raw = Buffer.concat(chunks).toString("utf8");
      resolve(parseHttpResponse(raw));
    });
  });
}

function parseHttpResponse(raw: string): { status: number; headers: Record<string, string>; body: string } {
  const split = raw.indexOf("\r\n\r\n");
  const head = split >= 0 ? raw.slice(0, split) : raw;
  const responseBody = split >= 0 ? raw.slice(split + 4) : "";
  const lines = head.split("\r\n");
  const status = Number(/^HTTP\/\d(?:\.\d)?\s+(\d+)/.exec(lines[0] ?? "")?.[1] ?? 0);
  const parsedHeaders: Record<string, string> = {};
  for (const line of lines.slice(1)) {
    const i = line.indexOf(":");
    if (i > 0) parsedHeaders[line.slice(0, i).toLowerCase()] = line.slice(i + 1).trim();
  }
  return { status, headers: parsedHeaders, body: responseBody };
}

describe("tf-daemon /v1/decide", () => {
  test("happy path: declared action returns 200 + decision: allow", async () => {
    const ctx = await bootDaemon();
    try {
      const res = await fetch(decideUrl(ctx.daemon, "/v1/decide"), {
        method: "POST",
        headers: {
          authorization: `Bearer ${ctx.token}`,
          "content-type": "application/json",
        },
        body: JSON.stringify({
          actor: "tf:actor:agent:example.com/x",
          action: "fs.read",
          target: null,
          context: {},
          trace_id: "trace-1",
        }),
      });
      expect(res.status).toBe(200);
      const j = (await res.json()) as Record<string, unknown>;
      expect(j.decision).toBe("allow");
      expect(typeof j.proof_id).toBe("string");
      expect((j.proof_id as string).startsWith("sha256:")).toBe(true);
      expect(j.actor_resolved).toBe("tf:actor:agent:example.com/x");
      expect(j.authority_mode).toBe("layered");
      expect(Array.isArray(j.danger_tags)).toBe(true);
    } finally {
      await ctx.daemon.stop();
      ctx.cleanup();
    }
  });

  test("forbidden action returns 200 + decision: deny", async () => {
    const ctx = await bootDaemon();
    try {
      const res = await fetch(decideUrl(ctx.daemon, "/v1/decide"), {
        method: "POST",
        headers: {
          authorization: `Bearer ${ctx.token}`,
          "content-type": "application/json",
        },
        body: JSON.stringify({
          actor: "tf:actor:agent:example.com/x",
          action: "fs.delete",
          target: null,
          context: {},
          trace_id: "trace-2",
        }),
      });
      expect(res.status).toBe(200);
      const j = (await res.json()) as Record<string, unknown>;
      expect(j.decision).toBe("deny");
      expect(typeof j.reason).toBe("string");
    } finally {
      await ctx.daemon.stop();
      ctx.cleanup();
    }
  });

  test("malformed JSON body returns 400", async () => {
    const ctx = await bootDaemon();
    try {
      const res = await fetch(decideUrl(ctx.daemon, "/v1/decide"), {
        method: "POST",
        headers: {
          authorization: `Bearer ${ctx.token}`,
          "content-type": "application/json",
        },
        body: "{not-json",
      });
      expect(res.status).toBe(400);
    } finally {
      await ctx.daemon.stop();
      ctx.cleanup();
    }
  });

  test("missing action returns 400", async () => {
    const ctx = await bootDaemon();
    try {
      const res = await fetch(decideUrl(ctx.daemon, "/v1/decide"), {
        method: "POST",
        headers: {
          authorization: `Bearer ${ctx.token}`,
          "content-type": "application/json",
        },
        body: JSON.stringify({
          actor: "tf:actor:agent:example.com/x",
          target: null,
          context: {},
          trace_id: "trace-bad",
        }),
      });
      expect(res.status).toBe(400);
    } finally {
      await ctx.daemon.stop();
      ctx.cleanup();
    }
  });

  test("missing admin token returns 401", async () => {
    const ctx = await bootDaemon();
    try {
      const res = await fetch(decideUrl(ctx.daemon, "/v1/decide"), {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({
          actor: "tf:actor:agent:example.com/x",
          action: "fs.read",
          target: null,
          context: {},
          trace_id: "trace-noauth",
        }),
      });
      expect(res.status).toBe(401);
    } finally {
      await ctx.daemon.stop();
      ctx.cleanup();
    }
  });

  test("wrong admin token returns 401", async () => {
    const ctx = await bootDaemon();
    try {
      const res = await fetch(decideUrl(ctx.daemon, "/v1/decide"), {
        method: "POST",
        headers: {
          authorization: "Bearer wrong-token",
          "content-type": "application/json",
        },
        body: JSON.stringify({
          actor: "tf:actor:agent:example.com/x",
          action: "fs.read",
          target: null,
          context: {},
          trace_id: "trace-wrongauth",
        }),
      });
      expect(res.status).toBe(401);
    } finally {
      await ctx.daemon.stop();
      ctx.cleanup();
    }
  });

  test("/v1/decide-batch returns array response", async () => {
    const ctx = await bootDaemon();
    try {
      const res = await fetch(decideUrl(ctx.daemon, "/v1/decide-batch"), {
        method: "POST",
        headers: {
          authorization: `Bearer ${ctx.token}`,
          "content-type": "application/json",
        },
        body: JSON.stringify([
          {
            actor: "tf:actor:agent:example.com/x",
            action: "fs.read",
            target: null,
            context: {},
            trace_id: "trace-b1",
          },
          {
            actor: "tf:actor:agent:example.com/x",
            action: "fs.delete",
            target: null,
            context: {},
            trace_id: "trace-b2",
          },
        ]),
      });
      expect(res.status).toBe(200);
      const j = (await res.json()) as Array<Record<string, unknown>>;
      expect(Array.isArray(j)).toBe(true);
      expect(j.length).toBe(2);
      expect(j[0]!.decision).toBe("allow");
      expect(j[1]!.decision).toBe("deny");
    } finally {
      await ctx.daemon.stop();
      ctx.cleanup();
    }
  });

  test("/v1/decide-batch over 100 items rejected with 400", async () => {
    const ctx = await bootDaemon();
    try {
      const items = new Array(101).fill(0).map((_, i) => ({
        actor: "tf:actor:agent:example.com/x",
        action: "fs.read",
        target: null,
        context: {},
        trace_id: `trace-${i}`,
      }));
      const res = await fetch(decideUrl(ctx.daemon, "/v1/decide-batch"), {
        method: "POST",
        headers: {
          authorization: `Bearer ${ctx.token}`,
          "content-type": "application/json",
        },
        body: JSON.stringify(items),
      });
      expect(res.status).toBe(400);
    } finally {
      await ctx.daemon.stop();
      ctx.cleanup();
    }
  });

  test("host_token resolves to actor before policy evaluation", async () => {
    const ctx = await bootDaemon();
    try {
      const res = await fetch(decideUrl(ctx.daemon, "/v1/decide"), {
        method: "POST",
        headers: {
          authorization: `Bearer ${ctx.token}`,
          "content-type": "application/json",
        },
        body: JSON.stringify({
          actor: null,
          host_token: "spiffe://example.com/workload/api",
          host_token_kind: "spiffe-svid",
          action: "fs.read",
          target: null,
          context: {},
          trace_id: "trace-spiffe",
        }),
      });
      expect(res.status).toBe(200);
      const j = (await res.json()) as Record<string, unknown>;
      expect((j.actor_resolved as string).startsWith("tf:actor:service:example.com/")).toBe(true);
      expect(j.decision).toBe("allow");
    } finally {
      await ctx.daemon.stop();
      ctx.cleanup();
    }
  });

  test("TCP /v1/decide requires bearer auth while UDS /v1/decide trusts local socket callers", async () => {
    const ctx = await bootDaemon();
    try {
      const tcp = await fetch(decideUrl(ctx.daemon, "/v1/decide"), {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({
          actor: "tf:actor:agent:example.com/x",
          action: "fs.read",
          target: null,
          context: {},
          trace_id: "trace-tcp-noauth",
        }),
      });
      expect(tcp.status).toBe(401);

      const socketPath = join(ctx.dir, "decide.sock");
      await ctx.daemon.stop();
      ctx.daemon = await runDaemon({
        configPath: join(ctx.dir, "daemon.yaml"),
        passphrase: "dev-pw",
        daemonHttpPort: -1,
        daemonHttpSocket: socketPath,
      });
      expect(ctx.daemon.httpSocketPath).toBe(socketPath);

      const uds = await requestUnixSocket(socketPath, "/v1/decide", {
        actor: "tf:actor:agent:example.com/x",
        action: "fs.read",
        target: null,
        context: {},
        trace_id: "trace-uds-local",
      });
      expect(uds.status).toBe(200);
      const j = JSON.parse(uds.body) as Record<string, unknown>;
      expect(j.decision).toBe("allow");
    } finally {
      await ctx.daemon.stop();
      ctx.cleanup();
    }
  });

  test("UDS local trust does not bypass privileged mutation endpoint bearer auth", async () => {
    const ctx = await bootDaemon();
    try {
      const socketPath = join(ctx.dir, "decide.sock");
      await ctx.daemon.stop();
      ctx.daemon = await runDaemon({
        configPath: join(ctx.dir, "daemon.yaml"),
        passphrase: "dev-pw",
        daemonHttpPort: -1,
        daemonHttpSocket: socketPath,
      });

      const res = await requestUnixSocket(socketPath, "/v1/import-credential", {
        credential: "spiffe://example.com/workload/api",
        hint: "spiffe-svid",
      });
      expect(res.status).toBe(401);
    } finally {
      await ctx.daemon.stop();
      ctx.cleanup();
    }
  });
});
