/**
 * Tests for the GNAP / DPoP bridge. Mints real ES256 access tokens
 * bound to a client key (via cnf.jkt), then has the client present a
 * DPoP proof JWT signed by the same key. The bridge must accept the
 * grant, project a TrustForge identity, and reject every flavor of
 * forged or mismatched proof.
 */

import { describe, expect, test } from "bun:test";
import {
  calculateJwkThumbprint,
  exportJWK,
  generateKeyPair,
  SignJWT,
} from "jose";

import { GnapBridge, type GnapClient, type GnapGrantRequest } from "../src/index";

async function makeAsKey() {
  const { publicKey, privateKey } = await generateKeyPair("ES256");
  const jwk = await exportJWK(publicKey);
  jwk.kid = "as-key-1";
  jwk.alg = "ES256";
  return { jwk, privateKey };
}

async function makeClientKey(): Promise<{
  client: GnapClient;
  jkt: string;
  signKey: any;
  publicJwk: Record<string, unknown>;
}> {
  const { publicKey, privateKey } = await generateKeyPair("ES256");
  const publicJwk = (await exportJWK(publicKey)) as unknown as Record<string, unknown>;
  publicJwk.alg = "ES256";
  const jkt = await calculateJwkThumbprint(publicJwk as never, "sha256");
  return {
    client: { key: { proof: "dpop", jwk: publicJwk } },
    jkt,
    signKey: privateKey,
    publicJwk,
  };
}

async function mintGnapAccessToken(opts: {
  asPrivateKey: any;
  asKid: string;
  issuer: string;
  subject: string;
  jkt: string;
  scope?: string;
}): Promise<string> {
  return new SignJWT({ tf_actor_type: "agent", cnf: { jkt: opts.jkt } })
    .setProtectedHeader({ alg: "ES256", kid: opts.asKid })
    .setIssuer(opts.issuer)
    .setSubject(opts.subject)
    .setIssuedAt()
    .setExpirationTime("5m")
    .sign(opts.asPrivateKey);
}

async function mintDpopProof(opts: {
  signKey: any;
  publicJwk: Record<string, unknown>;
  htm: string;
  htu: string;
  ath?: string;
  iat?: number;
}): Promise<string> {
  const headers = { typ: "dpop+jwt", alg: "ES256", jwk: opts.publicJwk };
  const payload: Record<string, unknown> = {
    htm: opts.htm,
    htu: opts.htu,
    iat: opts.iat ?? Math.floor(Date.now() / 1000),
    jti: crypto.randomUUID(),
  };
  if (opts.ath) payload.ath = opts.ath;
  return new SignJWT(payload)
    .setProtectedHeader(headers as never)
    .sign(opts.signKey);
}

describe("GNAP bridge — buildGrantResponse", () => {
  test("returns a stub grant response with a continue URL when supplied", async () => {
    const { jwk } = await makeAsKey();
    const { client } = await makeClientKey();
    const bridge = new GnapBridge({
      bridgeId: "tf-gnap",
      trustDomain: "example.com",
      issuer: "https://as.example.com",
      allowedAlgorithms: ["ES256"],
      jwks: { keys: [jwk as unknown as Record<string, unknown>] },
    });
    const req: GnapGrantRequest = {
      client,
      access_token: { access: ["files.read"] },
    };
    const resp = bridge.buildGrantResponse(req, { token: "stub-token", finishUri: "https://as.example.com/continue/abc" });
    expect(resp.access_token.value).toBe("stub-token");
    expect(resp.continue?.uri).toBe("https://as.example.com/continue/abc");
  });

  test("rejects requests with no access rights", async () => {
    const { jwk } = await makeAsKey();
    const { client } = await makeClientKey();
    const bridge = new GnapBridge({
      bridgeId: "tf-gnap",
      trustDomain: "example.com",
      issuer: "https://as.example.com",
      allowedAlgorithms: ["ES256"],
      jwks: { keys: [jwk as unknown as Record<string, unknown>] },
    });
    expect(() =>
      bridge.buildGrantResponse(
        { client, access_token: { access: [] } },
        { token: "x" },
      ),
    ).toThrow();
  });
});

describe("GNAP bridge — verifyAccessToken", () => {
  test("verified token + matching cnf.jkt projects a bound identity", async () => {
    const { jwk: asJwk, privateKey } = await makeAsKey();
    const { client, jkt } = await makeClientKey();
    const token = await mintGnapAccessToken({
      asPrivateKey: privateKey,
      asKid: "as-key-1",
      issuer: "https://as.example.com",
      subject: "agent-007",
      jkt,
    });
    const bridge = new GnapBridge({
      bridgeId: "tf-gnap",
      trustDomain: "example.com",
      issuer: "https://as.example.com",
      allowedAlgorithms: ["ES256"],
      jwks: { keys: [asJwk as unknown as Record<string, unknown>] },
    });
    const grant = await bridge.verifyAccessToken(token, {
      client,
      access_token: { access: ["files.read", "files.write"] },
    });
    expect(grant.identity.actor_id).toBe("tf:actor:agent:example.com/agent-007");
    expect(grant.capabilities.map((c) => c.name).sort()).toEqual(["files.read", "files.write"]);
    expect(grant.clientKeyThumbprint).toBe(jkt);
    expect(grant.identity.public_keys[0]!.public_key).not.toBe("AA==");
  });

  test("rejects access token whose cnf.jkt does not match the client key", async () => {
    const { jwk: asJwk, privateKey } = await makeAsKey();
    const { client } = await makeClientKey();
    const wrongJkt = "abc-not-the-real-jkt";
    const token = await mintGnapAccessToken({
      asPrivateKey: privateKey,
      asKid: "as-key-1",
      issuer: "https://as.example.com",
      subject: "agent-007",
      jkt: wrongJkt,
    });
    const bridge = new GnapBridge({
      bridgeId: "tf-gnap",
      trustDomain: "example.com",
      issuer: "https://as.example.com",
      allowedAlgorithms: ["ES256"],
      jwks: { keys: [asJwk as unknown as Record<string, unknown>] },
    });
    await expect(
      bridge.verifyAccessToken(token, {
        client,
        access_token: { access: ["files.read"] },
      }),
    ).rejects.toThrow();
  });
});

describe("GNAP bridge — verifyDpopProof", () => {
  test("accepts a fresh DPoP proof signed by the bound key", async () => {
    const { jwk: asJwk } = await makeAsKey();
    const { jkt, signKey, publicJwk } = await makeClientKey();
    const bridge = new GnapBridge({
      bridgeId: "tf-gnap",
      trustDomain: "example.com",
      issuer: "https://as.example.com",
      allowedAlgorithms: ["ES256"],
      jwks: { keys: [asJwk as unknown as Record<string, unknown>] },
    });
    const proof = await mintDpopProof({
      signKey,
      publicJwk,
      htm: "POST",
      htu: "https://api.example.com/files",
    });
    const result = await bridge.verifyDpopProof(proof, {
      htm: "POST",
      htu: "https://api.example.com/files",
      expectedJkt: jkt,
    });
    expect(result.ok).toBe(true);
  });

  test("rejects DPoP whose jkt does not match", async () => {
    const { jwk: asJwk } = await makeAsKey();
    const { signKey, publicJwk } = await makeClientKey();
    const bridge = new GnapBridge({
      bridgeId: "tf-gnap",
      trustDomain: "example.com",
      issuer: "https://as.example.com",
      allowedAlgorithms: ["ES256"],
      jwks: { keys: [asJwk as unknown as Record<string, unknown>] },
    });
    const proof = await mintDpopProof({
      signKey,
      publicJwk,
      htm: "GET",
      htu: "https://api.example.com/x",
    });
    const result = await bridge.verifyDpopProof(proof, {
      htm: "GET",
      htu: "https://api.example.com/x",
      expectedJkt: "wrong-thumbprint",
    });
    expect(result.ok).toBe(false);
  });

  test("rejects DPoP whose htm or htu mismatches", async () => {
    const { jwk: asJwk } = await makeAsKey();
    const { jkt, signKey, publicJwk } = await makeClientKey();
    const bridge = new GnapBridge({
      bridgeId: "tf-gnap",
      trustDomain: "example.com",
      issuer: "https://as.example.com",
      allowedAlgorithms: ["ES256"],
      jwks: { keys: [asJwk as unknown as Record<string, unknown>] },
    });
    const proof = await mintDpopProof({
      signKey,
      publicJwk,
      htm: "POST",
      htu: "https://api.example.com/files",
    });
    const wrongMethod = await bridge.verifyDpopProof(proof, {
      htm: "GET",
      htu: "https://api.example.com/files",
      expectedJkt: jkt,
    });
    expect(wrongMethod.ok).toBe(false);
    const wrongUrl = await bridge.verifyDpopProof(proof, {
      htm: "POST",
      htu: "https://api.example.com/somewhere-else",
      expectedJkt: jkt,
    });
    expect(wrongUrl.ok).toBe(false);
  });

  test("rejects DPoP whose typ is not dpop+jwt", async () => {
    const { jwk: asJwk } = await makeAsKey();
    const { jkt, signKey, publicJwk } = await makeClientKey();
    const bridge = new GnapBridge({
      bridgeId: "tf-gnap",
      trustDomain: "example.com",
      issuer: "https://as.example.com",
      allowedAlgorithms: ["ES256"],
      jwks: { keys: [asJwk as unknown as Record<string, unknown>] },
    });
    const wrongTyp = await new SignJWT({ htm: "GET", htu: "https://api.example.com", iat: Math.floor(Date.now() / 1000) })
      .setProtectedHeader({ typ: "JWT", alg: "ES256", jwk: publicJwk } as never)
      .sign(signKey);
    const result = await bridge.verifyDpopProof(wrongTyp, {
      htm: "GET",
      htu: "https://api.example.com",
      expectedJkt: jkt,
    });
    expect(result.ok).toBe(false);
  });
});
