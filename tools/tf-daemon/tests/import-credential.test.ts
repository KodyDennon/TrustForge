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

async function bootDaemon(opts: { bridgesYaml?: string } = {}): Promise<BootedDaemon> {
  const dir = mkdtempSync(join(tmpdir(), "tf-daemon-import-"));
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
project: import-e2e
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

  let bridgesPath: string | undefined;
  if (opts.bridgesYaml !== undefined) {
    bridgesPath = join(dir, "bridges.yaml");
    writeFileSync(bridgesPath, opts.bridgesYaml);
  }

  const token = `dev-${Math.random().toString(16).slice(2)}`;
  process.env.TF_ADMIN_TOKEN = token;

  const daemon = await runDaemon({
    configPath,
    passphrase: "dev-pw",
    daemonHttpPort: 0,
    daemonHttpSocket: "",
    bridgesRegistryPath: bridgesPath,
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

function importUrl(daemon: DaemonHandle): string {
  return `http://127.0.0.1:${daemon.httpPort}/v1/import-credential`;
}

async function postCredential(daemon: DaemonHandle, token: string, body: Record<string, unknown>): Promise<{ status: number; body: Record<string, unknown> }> {
  const res = await fetch(importUrl(daemon), {
    method: "POST",
    headers: {
      authorization: `Bearer ${token}`,
      "content-type": "application/json",
    },
    body: JSON.stringify(body),
  });
  const text = await res.text();
  return { status: res.status, body: text ? (JSON.parse(text) as Record<string, unknown>) : {} };
}

/** Build a base64url-encoded JWT with a fake signature. */
function makeJwt(claims: Record<string, unknown>, alg = "RS256"): string {
  const b64u = (s: string): string => Buffer.from(s).toString("base64").replace(/=+$/, "").replace(/\+/g, "-").replace(/\//g, "_");
  const header = b64u(JSON.stringify({ alg, typ: "JWT" }));
  const payload = b64u(JSON.stringify(claims));
  const sig = b64u("fake-signature");
  return `${header}.${payload}.${sig}`;
}

describe("tf-daemon /v1/import-credential", () => {
  test("oauth-jwt: detected via prefix; actor + iss + capabilities surface", async () => {
    const ctx = await bootDaemon();
    try {
      const jwt = makeJwt({ iss: "https://accounts.google.com", sub: "user-1", scope: "openid email" });
      const res = await postCredential(ctx.daemon, ctx.token, { credential: jwt, hint: "oauth-jwt" });
      expect(res.status).toBe(200);
      expect(res.body.bridge_kind).toBe("oauth");
      expect((res.body.actor as string).includes("user-1")).toBe(true);
      expect(Array.isArray(res.body.capabilities)).toBe(true);
    } finally {
      await ctx.daemon.stop();
      ctx.cleanup();
    }
  });

  test("next-auth-jwt: HS256 JWT detected via header", async () => {
    const ctx = await bootDaemon();
    try {
      const jwt = makeJwt({ iss: "next-auth", sub: "next-user-1", scope: "" }, "HS256");
      const res = await postCredential(ctx.daemon, ctx.token, { credential: jwt });
      expect(res.status).toBe(200);
      expect(res.body.bridge_kind).toBe("next-auth");
    } finally {
      await ctx.daemon.stop();
      ctx.cleanup();
    }
  });

  test("clerk-session: sess_ prefix detected", async () => {
    const ctx = await bootDaemon();
    try {
      const res = await postCredential(ctx.daemon, ctx.token, {
        credential: "sess_2NvLPq3nCkM3Z9p2Q8X1234567",
      });
      expect(res.status).toBe(200);
      expect(res.body.bridge_kind).toBe("clerk");
    } finally {
      await ctx.daemon.stop();
      ctx.cleanup();
    }
  });

  test("better-auth-session: auth_ prefix detected", async () => {
    const ctx = await bootDaemon();
    try {
      const res = await postCredential(ctx.daemon, ctx.token, {
        credential: "auth_5KpL8mZ4hQwR3yT7sJ9bN2vC",
      });
      expect(res.status).toBe(200);
      expect(res.body.bridge_kind).toBe("better-auth");
    } finally {
      await ctx.daemon.stop();
      ctx.cleanup();
    }
  });

  test("webauthn-assertion: JSON shape detected", async () => {
    const ctx = await bootDaemon();
    try {
      const cred = JSON.stringify({
        credentialId: "abc123",
        response: { clientDataJSON: "AA==", authenticatorData: "BB==", signature: "CC==" },
      });
      const res = await postCredential(ctx.daemon, ctx.token, { credential: cred });
      expect(res.status).toBe(200);
      expect(res.body.bridge_kind).toBe("webauthn");
    } finally {
      await ctx.daemon.stop();
      ctx.cleanup();
    }
  });

  test("mtls-cert-pem: PEM CERTIFICATE marker detected", async () => {
    const ctx = await bootDaemon();
    try {
      const pem = "-----BEGIN CERTIFICATE-----\nMIIB...\n-----END CERTIFICATE-----\n";
      const res = await postCredential(ctx.daemon, ctx.token, { credential: pem });
      expect(res.status).toBe(200);
      expect(res.body.bridge_kind).toBe("tls");
    } finally {
      await ctx.daemon.stop();
      ctx.cleanup();
    }
  });

  test("spiffe-svid: spiffe:// scheme detected", async () => {
    const ctx = await bootDaemon();
    try {
      const res = await postCredential(ctx.daemon, ctx.token, {
        credential: "spiffe://example.com/workload/api",
      });
      expect(res.status).toBe(200);
      expect(res.body.bridge_kind).toBe("spiffe");
      expect((res.body.actor as string).startsWith("tf:actor:service:example.com/")).toBe(true);
    } finally {
      await ctx.daemon.stop();
      ctx.cleanup();
    }
  });

  test("did: did:method:identifier detected", async () => {
    const ctx = await bootDaemon();
    try {
      const res = await postCredential(ctx.daemon, ctx.token, {
        credential: "did:web:example.com",
      });
      expect(res.status).toBe(200);
      expect(res.body.bridge_kind).toBe("did");
    } finally {
      await ctx.daemon.stop();
      ctx.cleanup();
    }
  });

  test("gnap: JSON access_token + subject detected", async () => {
    const ctx = await bootDaemon();
    try {
      const cred = JSON.stringify({
        access_token: { value: "tk-xyz" },
        subject: { sub_ids: [{ id: "user-99" }] },
      });
      const res = await postCredential(ctx.daemon, ctx.token, { credential: cred });
      expect(res.status).toBe(200);
      expect(res.body.bridge_kind).toBe("gnap");
    } finally {
      await ctx.daemon.stop();
      ctx.cleanup();
    }
  });

  test("session-cookie hint forces session-cookie classification", async () => {
    const ctx = await bootDaemon();
    try {
      const res = await postCredential(ctx.daemon, ctx.token, {
        credential: "opaque-cookie-value-1234",
        hint: "session-cookie",
      });
      expect(res.status).toBe(200);
      expect(res.body.bridge_kind).toBe("session-cookie");
    } finally {
      await ctx.daemon.stop();
      ctx.cleanup();
    }
  });

  test("__Secure-next-auth.session-token cookie detected", async () => {
    const ctx = await bootDaemon();
    try {
      const res = await postCredential(ctx.daemon, ctx.token, {
        credential: "__Secure-next-auth.session-token=abcdef.opaque",
      });
      expect(res.status).toBe(200);
      expect(res.body.bridge_kind).toBe("next-auth");
    } finally {
      await ctx.daemon.stop();
      ctx.cleanup();
    }
  });

  test("registry override: clerk.dev iss claim resolves through registry", async () => {
    const ctx = await bootDaemon({
      bridgesYaml: `
registry_version: "1"
bridges:
  - kind: oauth
    iss_pattern: clerk.dev
    trust_level: T3
    capability_map:
      email: user.email.read
`,
    });
    try {
      const jwt = makeJwt({ iss: "https://api.clerk.dev/v1/sessions/abc", sub: "u1", scope: "email" });
      const res = await postCredential(ctx.daemon, ctx.token, { credential: jwt });
      expect(res.status).toBe(200);
      expect(res.body.bridge_kind).toBe("oauth");
      expect(res.body.trust_level).toBe("T3");
      expect((res.body.capabilities as string[]).includes("user.email.read")).toBe(true);
    } finally {
      await ctx.daemon.stop();
      ctx.cleanup();
    }
  });

  test("malformed JWT (3 segments but bad base64) returns 400", async () => {
    const ctx = await bootDaemon();
    try {
      // First segment looks like a JWT (eyJ prefix) but middle is not valid base64url JSON.
      const res = await postCredential(ctx.daemon, ctx.token, {
        credential: "eyJhbGciOiJIUzI1NiJ9.@@@@.zzz",
        hint: "oauth-jwt",
      });
      expect(res.status).toBe(400);
    } finally {
      await ctx.daemon.stop();
      ctx.cleanup();
    }
  });

  test("unknown / opaque credential returns bridge_kind: session-cookie fallback", async () => {
    const ctx = await bootDaemon();
    try {
      const res = await postCredential(ctx.daemon, ctx.token, {
        credential: "totally-opaque-string",
      });
      expect(res.status).toBe(200);
      // Defaults to session-cookie after sniff fails.
      expect(res.body.bridge_kind).toBe("session-cookie");
    } finally {
      await ctx.daemon.stop();
      ctx.cleanup();
    }
  });

  test("missing credential field returns 400", async () => {
    const ctx = await bootDaemon();
    try {
      const res = await postCredential(ctx.daemon, ctx.token, { hint: "oauth-jwt" });
      expect(res.status).toBe(400);
    } finally {
      await ctx.daemon.stop();
      ctx.cleanup();
    }
  });

  test("missing admin token returns 401", async () => {
    const ctx = await bootDaemon();
    try {
      const res = await fetch(importUrl(ctx.daemon), {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ credential: "sess_anything" }),
      });
      expect(res.status).toBe(401);
    } finally {
      await ctx.daemon.stop();
      ctx.cleanup();
    }
  });
});
