import { afterEach, beforeEach, describe, expect, test } from "bun:test";
import { startMockDaemon, type MockDaemonHandle } from "@trustforge/test-utils";
import { TrustForge, TrustForgeError } from "../src/index.ts";

let daemon: MockDaemonHandle;

beforeEach(() => {
  daemon = startMockDaemon({ adminToken: "test-admin-token" });
});

afterEach(async () => {
  await daemon.stop();
});

describe("TrustForge SDK", () => {
  test("constructor throws when daemonUrl missing", () => {
    expect(() => new TrustForge({ daemonUrl: "" })).toThrow(
      /daemonUrl is required/,
    );
  });

  test("decide() forwards canonical-shape request and returns response", async () => {
    const sdk = new TrustForge({
      daemonUrl: daemon.url,
      adminToken: "test-admin-token",
    });
    const resp = await sdk.decide({
      actor: "tf:actor:agent:example.com/x",
      action: "fs.read",
      target: null,
      context: {},
      trace_id: "trace-1",
    });
    expect(resp.decision).toBe("allow");
    expect(resp.actor_resolved).toBe("tf:actor:agent:example.com/x");
    expect(resp.proof_id).toContain("sha256:");
    expect(daemon.callCount()).toBe(1);
    const captured = daemon.calls()[0]!;
    expect(captured.action).toBe("fs.read");
    expect(captured.trace_id).toBe("trace-1");
  });

  test("decide() supports host_token + host_token_kind path", async () => {
    const sdk = new TrustForge({
      daemonUrl: daemon.url,
      adminToken: "test-admin-token",
    });
    const resp = await sdk.decide({
      actor: null,
      host_token: "sess_2NvLPq3nCkM3Z9p2Q8X1234567",
      host_token_kind: "clerk-session",
      action: "billing.read",
      target: null,
      context: {},
      trace_id: "trace-clerk-1",
    });
    expect(resp.decision).toBe("allow");
    const captured = daemon.calls()[0]!;
    expect(captured.host_token_kind).toBe("clerk-session");
    expect(captured.actor).toBeNull();
  });

  test("decide() honours custom decide hook (deny path)", async () => {
    await daemon.stop();
    daemon = startMockDaemon({
      decide: (_req) => ({
        decision: "deny",
        reason: "test deny",
        approval_id: null,
        proof_id: "sha256:deny-1",
        actor_resolved: "tf:actor:agent:example.com/x",
        trust_level: "T1",
        authority_mode: "layered",
        danger_tags: ["test"],
      }),
    });
    const sdk = new TrustForge({ daemonUrl: daemon.url });
    const resp = await sdk.decide({
      actor: "tf:actor:agent:example.com/x",
      action: "fs.read",
      target: "/etc/passwd",
      context: {},
      trace_id: "t",
    });
    expect(resp.decision).toBe("deny");
    expect(resp.danger_tags).toEqual(["test"]);
  });

  test("decide() throws TrustForgeError on 401 unauthorized", async () => {
    const sdk = new TrustForge({
      daemonUrl: daemon.url,
      adminToken: "wrong-token",
    });
    await expect(
      sdk.decide({
        actor: null,
        action: "fs.read",
        target: null,
        context: {},
        trace_id: "t",
      }),
    ).rejects.toBeInstanceOf(TrustForgeError);
  });

  test("decide() rejects on network error / unreachable host", async () => {
    const sdk = new TrustForge({
      daemonUrl: "http://127.0.0.1:1", // closed port
      timeoutMs: 200,
    });
    await expect(
      sdk.decide({
        actor: null,
        action: "fs.read",
        target: null,
        context: {},
        trace_id: "t",
      }),
    ).rejects.toBeDefined();
  });

  test("importCredential() round-trips actor + credential id", async () => {
    const sdk = new TrustForge({
      daemonUrl: daemon.url,
      adminToken: "test-admin-token",
    });
    const r = await sdk.importCredential({
      kind: "clerk-session",
      token: "sess_abc",
      actor_hint: "tf:actor:agent:example.com/x",
    });
    expect(r.credential_id).toBe("cred-mock-1");
    expect(r.trust_level).toBe("T2");
  });

  test("importCredential() surfaces daemon error responses", async () => {
    await daemon.stop();
    // Boot a daemon that returns 500 on /v1/credentials/import.
    const server = Bun.serve({
      port: 0,
      hostname: "127.0.0.1",
      fetch: () =>
        new Response(JSON.stringify({ error: "boom" }), {
          status: 500,
          headers: { "content-type": "application/json" },
        }),
    });
    try {
      const sdk = new TrustForge({ daemonUrl: `http://127.0.0.1:${server.port}` });
      await expect(
        sdk.importCredential({ kind: "clerk-session", token: "x" }),
      ).rejects.toBeInstanceOf(TrustForgeError);
    } finally {
      await server.stop(true);
    }
    daemon = startMockDaemon({ adminToken: "test-admin-token" });
  });

  test("signProof() returns event_hash + signature", async () => {
    const sdk = new TrustForge({
      daemonUrl: daemon.url,
      adminToken: "test-admin-token",
    });
    const r = await sdk.signProof({
      kind: "decision.recorded",
      actor: "tf:actor:agent:example.com/x",
      trace_id: "abc",
    });
    expect(r.event_hash).toBe("sha256:fake-abc");
    expect(r.signature.startsWith("ed25519:")).toBe(true);
  });

  test("verifyProof() returns ok=true for well-formed signed event", async () => {
    const sdk = new TrustForge({
      daemonUrl: daemon.url,
      adminToken: "test-admin-token",
    });
    const r = await sdk.verifyProof({
      kind: "decision.recorded",
      actor: "tf:actor:agent:example.com/x",
      trace_id: "abc",
      event_hash: "sha256:fake-abc",
      signature: "ed25519:fake-sig-abc",
    });
    expect(r.ok).toBe(true);
    expect(r.signer_actor).toBe("tf:actor:agent:example.com/x");
  });

  test("verifyProof() returns ok=false for bad signature", async () => {
    const sdk = new TrustForge({
      daemonUrl: daemon.url,
      adminToken: "test-admin-token",
    });
    const r = await sdk.verifyProof({
      kind: "decision.recorded",
      actor: "tf:actor:agent:example.com/x",
      trace_id: "abc",
      event_hash: "sha256:fake-abc",
      signature: "garbage",
    });
    expect(r.ok).toBe(false);
    expect(r.trust_level).toBe("T0");
  });

  test("decide() trims trailing slash on daemonUrl", async () => {
    const sdk = new TrustForge({
      daemonUrl: `${daemon.url}/`,
      adminToken: "test-admin-token",
    });
    const r = await sdk.decide({
      actor: "tf:actor:agent:example.com/x",
      action: "fs.read",
      target: null,
      context: {},
      trace_id: "trim",
    });
    expect(r.decision).toBe("allow");
  });

  test("decide() respects timeoutMs (aborts long requests)", async () => {
    await daemon.stop();
    const server = Bun.serve({
      port: 0,
      hostname: "127.0.0.1",
      async fetch() {
        await new Promise((r) => setTimeout(r, 1000));
        return new Response("{}");
      },
    });
    try {
      const sdk = new TrustForge({
        daemonUrl: `http://127.0.0.1:${server.port}`,
        timeoutMs: 50,
      });
      await expect(
        sdk.decide({
          actor: null,
          action: "fs.read",
          target: null,
          context: {},
          trace_id: "t",
        }),
      ).rejects.toBeDefined();
    } finally {
      await server.stop(true);
    }
    daemon = startMockDaemon({ adminToken: "test-admin-token" });
  });
});
