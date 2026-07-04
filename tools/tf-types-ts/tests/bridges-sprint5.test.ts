/**
 * Sprint-5 bridge sweep: Matrix, Webhook, gRPC adapter, Service-Mesh,
 * plus the new TLS reauth / revocation / exporter helpers.
 */

import { describe, expect, test } from "bun:test";
import { hmac } from "@noble/hashes/hmac";
import { sha1 } from "@noble/hashes/sha1";
import { sha256 } from "@noble/hashes/sha256";
import {
  GrpcBridge,
  MatrixBridge,
  ServiceMeshBridge,
  TlsBridge,
  WebhookBridge,
  ed25519Generate,
  ed25519Sign,
  type GrpcChannelLike,
} from "../src/index";

function toHex(b: Uint8Array): string {
  let s = "";
  for (const x of b) s += x.toString(16).padStart(2, "0");
  return s;
}

describe("Matrix bridge", () => {
  test("projects an m.room.message into a TrustForge ProofEvent", () => {
    const bridge = new MatrixBridge({ bridgeId: "tf-mx", trustDomain: "example.com" });
    const projected = bridge.matrixEventToProofEvent({
      event_id: "$abc123",
      room_id: "!room:example.com",
      type: "m.room.message",
      sender: "@alice:example.com",
      origin_server_ts: 1745496000000,
      content: { body: "approve firmware push", msgtype: "m.text" },
    });
    expect(projected.fromMessage).toBe(true);
    expect(projected.event.actor_id).toBe("tf:actor:human:example.com/alice");
    expect(projected.event.id).toBe("$abc123");
    expect(projected.event.type).toBe("matrix.message");
  });

  test("projects an m.tf.proof event with the matrix.* prefix", () => {
    const bridge = new MatrixBridge({ bridgeId: "tf-mx", trustDomain: "example.com" });
    const projected = bridge.matrixEventToProofEvent({
      event_id: "$xyz",
      room_id: "!room:example.com",
      type: "m.tf.proof",
      sender: "@alice:example.com",
      origin_server_ts: 1745496000000,
      content: { proof: "..." },
    });
    expect(projected.event.type).toBe("matrix.tf.proof");
  });

  test("rejects malformed senders", () => {
    const bridge = new MatrixBridge({ bridgeId: "tf-mx", trustDomain: "example.com" });
    expect(() =>
      bridge.matrixEventToProofEvent({
        event_id: "$x",
        room_id: "!r",
        type: "m.room.message",
        sender: "not-a-matrix-sender",
        origin_server_ts: 0,
        content: {},
      }),
    ).toThrow();
  });

  test("proofEventToMatrixEvent round-trips id + room", () => {
    const bridge = new MatrixBridge({ bridgeId: "tf-mx", trustDomain: "example.com" });
    const ev = {
      event_version: "1" as const,
      id: "ev-1",
      type: "rpc.call",
      actor_id: "tf:actor:agent:example.com/x",
      timestamp: "2026-04-24T12:00:00Z",
      level: "L1" as const,
      signature: { algorithm: "ed25519", signer: "tf:actor:agent:example.com/x", signature: "AAAA" },
    };
    const matrix = bridge.proofEventToMatrixEvent(ev, { roomId: "!r:example.com", sender: "@bot:example.com" });
    expect(matrix.event_id).toBe("ev-1");
    expect(matrix.room_id).toBe("!r:example.com");
    expect(matrix.type).toBe("m.tf.event");
  });
});

describe("Webhook bridge", () => {
  test("HMAC-SHA256 verifies a Stripe-style signature", async () => {
    const secret = new TextEncoder().encode("whsec_test");
    const body = new TextEncoder().encode(JSON.stringify({ id: "evt_1", type: "charge.succeeded" }));
    const sig = toHex(hmac(sha256, secret, body));
    const bridge = new WebhookBridge({
      bridgeId: "tf-wh",
      trustDomain: "example.com",
      vendor: "stripe",
      scheme: "hmac-sha256",
      secret,
    });
    const result = await bridge.verify({
      body,
      signatureHeader: sig,
      eventType: "charge.succeeded",
      eventId: "evt_1",
      receivedAt: new Date().toISOString(),
    });
    expect(result.event.type).toBe("webhook.stripe.charge.succeeded");
    expect(result.capability.name).toBe("webhook.stripe.charge.succeeded");
  });

  test("HMAC-SHA1 verifies a legacy GitHub-style signature with sha1= prefix", async () => {
    const secret = new TextEncoder().encode("ghp_test");
    const body = new TextEncoder().encode("ping");
    const sig = "sha1=" + toHex(hmac(sha1, secret, body));
    const bridge = new WebhookBridge({
      bridgeId: "tf-wh",
      trustDomain: "example.com",
      vendor: "github",
      scheme: "hmac-sha1",
      secret,
    });
    const result = await bridge.verify({
      body,
      signatureHeader: sig,
      eventType: "ping",
      eventId: "abc",
    });
    expect(result.event.id).toBe("abc");
  });

  test("ed25519 verifies a Discord-style signature", async () => {
    const pair = await ed25519Generate();
    const ts = "1745496000";
    const body = new TextEncoder().encode("{}");
    const message = new TextEncoder().encode(`${ts}.{}`);
    const sig = await ed25519Sign(message, pair.privateKey);
    const bridge = new WebhookBridge({
      bridgeId: "tf-wh",
      trustDomain: "example.com",
      vendor: "discord",
      scheme: "ed25519",
      secret: pair.publicKey,
      maxAgeSeconds: 60 * 60 * 24 * 365 * 10,
    });
    const result = await bridge.verify({
      body,
      signatureHeader: toHex(sig),
      timestampHeader: ts,
      eventType: "INTERACTION_CREATE",
      eventId: "i-1",
    });
    expect(result.event.type).toContain("webhook.discord.");
  });

  test("rejects HMAC mismatch", async () => {
    const bridge = new WebhookBridge({
      bridgeId: "tf-wh",
      trustDomain: "example.com",
      vendor: "vendor",
      scheme: "hmac-sha256",
      secret: new TextEncoder().encode("right"),
    });
    await expect(
      bridge.verify({
        body: new TextEncoder().encode("body"),
        signatureHeader: "deadbeef",
        eventType: "x",
        eventId: "y",
      }),
    ).rejects.toThrow();
  });

  test("rejects payloads older than maxAgeSeconds", async () => {
    const secret = new TextEncoder().encode("secret");
    const body = new TextEncoder().encode("body");
    const sig = toHex(hmac(sha256, secret, body));
    const bridge = new WebhookBridge({
      bridgeId: "tf-wh",
      trustDomain: "example.com",
      vendor: "vendor",
      scheme: "hmac-sha256",
      secret,
      maxAgeSeconds: 60,
    });
    await expect(
      bridge.verify({
        body,
        signatureHeader: sig,
        timestampHeader: "2020-01-01T00:00:00Z",
        eventType: "x",
        eventId: "y",
        receivedAt: "2026-04-24T12:00:00Z",
      }),
    ).rejects.toThrow();
  });
});

describe("gRPC bridge adapter", () => {
  test("asRpcTransport pumps unary frames through the supplied channel", async () => {
    const calls: Array<{ method: string; body: Uint8Array }> = [];
    const channel: GrpcChannelLike = {
      async unary(call, body) {
        calls.push({ method: call.method, body });
        const replyJson = JSON.stringify({ kind: "data", payload: { ok: true, echo: new TextDecoder().decode(body) } });
        return { body: new TextEncoder().encode(replyJson), metadata: {} };
      },
      async *serverStream() {
        yield { body: new Uint8Array(), metadata: {} };
      },
      async close() {},
    };
    const bridge = new GrpcBridge(channel, {
      bridgeId: "tf-grpc",
      trustDomain: "example.com",
      serviceMethod: "trustforge.ProofRpc/Unary",
    });
    const transport = bridge.asRpcTransport();
    const seen: unknown[] = [];
    transport.onFrame((f) => seen.push(f));
    transport.send({ kind: "data", payload: { hello: "world" } });
    // Allow the microtask that pumps the unary reply to settle.
    await new Promise((r) => setTimeout(r, 5));
    expect(calls.length).toBe(1);
    expect(seen.length).toBe(1);
  });
});

describe("Service-mesh bridge", () => {
  test("Envoy XFCC with SPIFFE URI produces a service identity", () => {
    const bridge = new ServiceMeshBridge({ bridgeId: "tf-mesh", trustDomain: "example.com" });
    const result = bridge.acceptEnvoy({ uri: "spiffe://example.com/ns/foo/sa/bar", by: "envoy", hash: "abc" });
    expect(result.identity.actor_type).toBe("service");
    expect(result.identity.actor_id).toBe("tf:actor:service:example.com/ns/foo/sa/bar");
    expect(result.source).toBe("envoy-xfcc");
  });

  test("Istio AuthN context produces a service identity", () => {
    const bridge = new ServiceMeshBridge({ bridgeId: "tf-mesh", trustDomain: "example.com" });
    const result = bridge.acceptIstio({ spiffe_id: "spiffe://cluster.local/ns/default/sa/foo" });
    expect(result.identity.actor_id).toBe("tf:actor:service:cluster.local/ns/default/sa/foo");
    expect(result.source).toBe("istio-authn");
  });

  test("Linkerd l5d-client-id parses cluster/ns/sa", () => {
    const bridge = new ServiceMeshBridge({ bridgeId: "tf-mesh", trustDomain: "example.com" });
    const result = bridge.acceptLinkerd({
      client_id: "myapp.production.serviceaccount.identity.cluster1.cluster.local",
    });
    expect(result.identity.actor_id).toBe("tf:actor:service:cluster1/production/myapp");
  });

  test("rejects malformed Linkerd client_id", () => {
    const bridge = new ServiceMeshBridge({ bridgeId: "tf-mesh", trustDomain: "example.com" });
    expect(() => bridge.acceptLinkerd({ client_id: "garbage" })).toThrow();
  });
});

describe("TLS bridge — Sprint 5 additions", () => {
  test("deriveExporterKey produces a 32-byte deterministic key per (label, context)", () => {
    const transport = new Uint8Array([1, 2, 3, 4, 5, 6, 7, 8]);
    const a = TlsBridge.deriveExporterKey(transport, "@trustforge-protocol/session", new Uint8Array([0xaa]));
    const b = TlsBridge.deriveExporterKey(transport, "@trustforge-protocol/session", new Uint8Array([0xaa]));
    const c = TlsBridge.deriveExporterKey(transport, "@trustforge-protocol/session", new Uint8Array([0xbb]));
    const d = TlsBridge.deriveExporterKey(transport, "different-label", new Uint8Array([0xaa]));
    expect(a.length).toBe(32);
    expect(toHex(a)).toBe(toHex(b));
    expect(toHex(a)).not.toBe(toHex(c));
    expect(toHex(a)).not.toBe(toHex(d));
  });

  test("checkRevocation enforces OCSP / CRL outcomes", async () => {
    // Mint a real self-signed root via @peculiar/x509 so the
    // TlsBridge constructor accepts it.
    const x509 = await import("@peculiar/x509");
    const webcrypto = globalThis.crypto;
    x509.cryptoProvider.set(webcrypto);
    const key = (await webcrypto.subtle.generateKey(
      { name: "ECDSA", namedCurve: "P-256" },
      true,
      ["sign", "verify"],
    )) as CryptoKeyPair;
    const cert = await x509.X509CertificateGenerator.createSelfSigned({
      serialNumber: "01",
      name: "CN=Sprint5 Test Root",
      notBefore: new Date(Date.now() - 60_000),
      notAfter: new Date(Date.now() + 86_400_000),
      signingAlgorithm: { name: "ECDSA", hash: "SHA-256" },
      keys: key,
      extensions: [
        new x509.BasicConstraintsExtension(true, undefined, true),
        new x509.KeyUsagesExtension(
          x509.KeyUsageFlags.keyCertSign | x509.KeyUsageFlags.cRLSign,
          true,
        ),
      ],
    });
    const bridge = new TlsBridge({
      bridgeId: "tf-tls",
      trustDomain: "example.com",
      rootCertificatesPem: [cert.toString("pem")],
    });
    const fakeLeaf = { subject: "CN=fake", serialNumber: "0x01" } as unknown as Parameters<TlsBridge["checkRevocation"]>[0];
    await expect(
      bridge.checkRevocation(fakeLeaf, { ocspStatus: "revoked" }),
    ).rejects.toThrow();
    await expect(
      bridge.checkRevocation(fakeLeaf, { ocspStatus: "unknown" }),
    ).rejects.toThrow();
    await expect(
      bridge.checkRevocation(fakeLeaf, { crlSerials: ["01"] }),
    ).rejects.toThrow();
    await bridge.checkRevocation(fakeLeaf, { ocspStatus: "good", crlSerials: ["02"] });
  });
});
