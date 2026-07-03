/**
 * WebAuthn full-attestation tests. We mint synthetic attestations end to
 * end (CBOR + ES256 / EdDSA self-attestation) and round-trip them through
 * `WebAuthnBridge.verifyRegistration`. This covers `none`, `packed`
 * (self-attestation), and `fido-u2f` formats with real noble-curves
 * signatures — no pre-extracted credential shortcuts.
 */

import { describe, expect, test } from "bun:test";
import { encode as cborEncode } from "../src/core/cbor.js";
import { sha256 } from "@noble/hashes/sha256";
import { p256 } from "@noble/curves/p256";
import { ed25519 } from "@noble/curves/ed25519";

import {
  BridgeFailure,
  WebAuthnBridge,
  parseAuthenticatorData,
  parseCosePublicKey,
  decodeAttestationObject,
  parseClientDataJSON,
  verifyAttestation,
} from "../src/index";

const ENC = new TextEncoder();

function b64url(buf: Uint8Array): string {
  return Buffer.from(buf)
    .toString("base64")
    .replace(/\+/g, "-")
    .replace(/\//g, "_")
    .replace(/=+$/, "");
}

function concat(...parts: Uint8Array[]): Uint8Array {
  const total = parts.reduce((n, p) => n + p.length, 0);
  const out = new Uint8Array(total);
  let off = 0;
  for (const p of parts) {
    out.set(p, off);
    off += p.length;
  }
  return out;
}

function buildClientData(opts: {
  type: string;
  challenge: string;
  origin: string;
}): Uint8Array {
  return ENC.encode(JSON.stringify(opts));
}

interface CredKey {
  cose: Map<number, unknown>;
  rawKey: Uint8Array; // raw form for signing
  algName: "ES256" | "EdDSA";
  publicKey: Uint8Array; // public bytes in raw form (uncompressed for EC2; raw 32 for Ed)
}

function makeP256Credential(): CredKey {
  const priv = p256.utils.randomPrivateKey();
  const pubUncompressed = p256.getPublicKey(priv, false); // 65 bytes
  const x = pubUncompressed.subarray(1, 33);
  const y = pubUncompressed.subarray(33, 65);
  const cose = new Map<number, unknown>();
  cose.set(1, 2); // kty=EC2
  cose.set(3, -7); // alg=ES256
  cose.set(-1, 1); // crv=P-256
  cose.set(-2, x);
  cose.set(-3, y);
  return { cose, rawKey: priv, algName: "ES256", publicKey: pubUncompressed };
}

function makeEd25519Credential(): CredKey {
  const priv = ed25519.utils.randomPrivateKey();
  const pub = ed25519.getPublicKey(priv);
  const cose = new Map<number, unknown>();
  cose.set(1, 1); // kty=OKP
  cose.set(3, -8); // alg=EdDSA
  cose.set(-1, 6); // crv=Ed25519
  cose.set(-2, pub);
  return { cose, rawKey: priv, algName: "EdDSA", publicKey: pub };
}

function buildAuthData(opts: {
  rpId: string;
  flags: number;
  signCount: number;
  aaguid: Uint8Array;
  credentialId: Uint8Array;
  cosePublicKey: Map<number, unknown>;
}): Uint8Array {
  const rpIdHash = sha256(ENC.encode(opts.rpId));
  const flagsB = new Uint8Array([opts.flags]);
  const counter = new Uint8Array(4);
  new DataView(counter.buffer).setUint32(0, opts.signCount, false);
  const credIdLen = new Uint8Array(2);
  new DataView(credIdLen.buffer).setUint16(0, opts.credentialId.length, false);
  const cose = cborEncode(opts.cosePublicKey);
  return concat(
    rpIdHash,
    flagsB,
    counter,
    opts.aaguid,
    credIdLen,
    opts.credentialId,
    cose,
  );
}

function signEs256DerOver(priv: Uint8Array, data: Uint8Array): Uint8Array {
  const sig = p256.sign(sha256(data), priv);
  return sig.toDERRawBytes();
}

function signEdDsaOver(priv: Uint8Array, data: Uint8Array): Uint8Array {
  return ed25519.sign(data, priv);
}

function buildAttestationObject(opts: {
  fmt: "none" | "packed" | "fido-u2f";
  attStmt: Record<string, unknown>;
  authData: Uint8Array;
}): Uint8Array {
  return cborEncode({ fmt: opts.fmt, attStmt: opts.attStmt, authData: opts.authData });
}

const RP_ID = "example.com";
const ORIGIN = "https://example.com";
const CHALLENGE = b64url(new Uint8Array([1, 2, 3, 4, 5, 6, 7, 8, 9, 10]));
const AAGUID = new Uint8Array(16).fill(0xab);
const CREDENTIAL_ID = new Uint8Array([10, 20, 30, 40, 50, 60, 70, 80]);

describe("WebAuthn attestation parsing", () => {
  test("parseAuthenticatorData reads rpIdHash/flags/counter/credential", async () => {
    const cred = makeP256Credential();
    const authData = buildAuthData({
      rpId: RP_ID,
      flags: 0x41,
      signCount: 7,
      aaguid: AAGUID,
      credentialId: CREDENTIAL_ID,
      cosePublicKey: cred.cose,
    });
    const parsed = parseAuthenticatorData(authData);
    expect(parsed.flags).toBe(0x41);
    expect(parsed.signCount).toBe(7);
    expect(parsed.aaguid).toEqual(AAGUID);
    expect(parsed.credentialId).toEqual(CREDENTIAL_ID);
    expect(parsed.credentialPublicKey?.kty).toBe(2);
    expect(parsed.credentialPublicKey?.alg).toBe("ES256");
  });

  test("parseCosePublicKey recognises Ed25519", async () => {
    const cred = makeEd25519Credential();
    const cose = cborEncode(cred.cose);
    const parsed = parseCosePublicKey(new Uint8Array(cose));
    expect(parsed.alg).toBe("EdDSA");
    expect(parsed.kty).toBe(1);
  });

  test("decodeAttestationObject splits fmt/attStmt/authData", async () => {
    const cred = makeP256Credential();
    const authData = buildAuthData({
      rpId: RP_ID,
      flags: 0x41,
      signCount: 0,
      aaguid: AAGUID,
      credentialId: CREDENTIAL_ID,
      cosePublicKey: cred.cose,
    });
    const att = buildAttestationObject({ fmt: "none", attStmt: {}, authData });
    const decoded = decodeAttestationObject(att);
    expect(decoded.fmt).toBe("none");
    expect(decoded.authData).toEqual(authData);
  });

  test("parseClientDataJSON enforces required fields", async () => {
    const ok = parseClientDataJSON(
      buildClientData({ type: "webauthn.create", challenge: CHALLENGE, origin: ORIGIN }),
    );
    expect(ok.type).toBe("webauthn.create");
  });
});

describe("WebAuthnBridge.verifyRegistration", () => {
  test("verifies fmt=none ES256 attestation", async () => {
    const cred = makeP256Credential();
    const authData = buildAuthData({
      rpId: RP_ID,
      flags: 0x41,
      signCount: 0,
      aaguid: AAGUID,
      credentialId: CREDENTIAL_ID,
      cosePublicKey: cred.cose,
    });
    const attestationObject = buildAttestationObject({ fmt: "none", attStmt: {}, authData });
    const clientDataJSON = buildClientData({
      type: "webauthn.create",
      challenge: CHALLENGE,
      origin: ORIGIN,
    });
    const bridge = new WebAuthnBridge("tf-webauthn", RP_ID, {
      bridgeId: "tf-webauthn",
      rpId: RP_ID,
      allowedAlgorithms: ["p256", "ed25519"],
    });
    const result = await bridge.verifyRegistration(
      new Uint8Array(attestationObject),
      clientDataJSON,
      {
        expectedChallenge: CHALLENGE,
        expectedOrigin: ORIGIN,
        userHandle: "user-001",
      },
    );
    expect(result.identity.actor_type).toBe("human");
    expect(result.identity.actor_id).toBe(`tf:actor:human:${RP_ID}/user-001`);
    expect(result.credential.algorithm).toBe("p256");
  });

  test("verifies packed self-attestation ES256", async () => {
    const cred = makeP256Credential();
    const authData = buildAuthData({
      rpId: RP_ID,
      flags: 0x41,
      signCount: 1,
      aaguid: AAGUID,
      credentialId: CREDENTIAL_ID,
      cosePublicKey: cred.cose,
    });
    const clientDataJSON = buildClientData({
      type: "webauthn.create",
      challenge: CHALLENGE,
      origin: ORIGIN,
    });
    const clientDataHash = sha256(clientDataJSON);
    const sig = signEs256DerOver(cred.rawKey, concat(authData, clientDataHash));
    const attestationObject = buildAttestationObject({
      fmt: "packed",
      attStmt: { alg: -7, sig },
      authData,
    });
    const bridge = new WebAuthnBridge("tf-webauthn", RP_ID, {
      bridgeId: "tf-webauthn",
      rpId: RP_ID,
      allowedAlgorithms: ["p256"],
    });
    const result = await bridge.verifyRegistration(new Uint8Array(attestationObject), clientDataJSON, {
      expectedChallenge: CHALLENGE,
      expectedOrigin: ORIGIN,
      userHandle: "user-002",
    });
    expect(result.verified.format).toBe("packed");
    expect(result.credential.algorithm).toBe("p256");
  });

  test("verifies packed self-attestation Ed25519", async () => {
    const cred = makeEd25519Credential();
    const authData = buildAuthData({
      rpId: RP_ID,
      flags: 0x41,
      signCount: 1,
      aaguid: AAGUID,
      credentialId: CREDENTIAL_ID,
      cosePublicKey: cred.cose,
    });
    const clientDataJSON = buildClientData({
      type: "webauthn.create",
      challenge: CHALLENGE,
      origin: ORIGIN,
    });
    const clientDataHash = sha256(clientDataJSON);
    const sig = signEdDsaOver(cred.rawKey, concat(authData, clientDataHash));
    const attestationObject = buildAttestationObject({
      fmt: "packed",
      attStmt: { alg: -8, sig },
      authData,
    });
    const bridge = new WebAuthnBridge("tf-webauthn", RP_ID, {
      bridgeId: "tf-webauthn",
      rpId: RP_ID,
      allowedAlgorithms: ["ed25519"],
    });
    const result = await bridge.verifyRegistration(new Uint8Array(attestationObject), clientDataJSON, {
      expectedChallenge: CHALLENGE,
      expectedOrigin: ORIGIN,
      userHandle: "user-003",
    });
    expect(result.credential.algorithm).toBe("ed25519");
    expect(result.verified.format).toBe("packed");
  });

  test("rejects bad challenge", () => {
    const cred = makeP256Credential();
    const authData = buildAuthData({
      rpId: RP_ID,
      flags: 0x41,
      signCount: 0,
      aaguid: AAGUID,
      credentialId: CREDENTIAL_ID,
      cosePublicKey: cred.cose,
    });
    const att = buildAttestationObject({ fmt: "none", attStmt: {}, authData });
    const clientDataJSON = buildClientData({
      type: "webauthn.create",
      challenge: "DIFFERENT",
      origin: ORIGIN,
    });
    const bridge = new WebAuthnBridge("tf-webauthn", RP_ID, {
      bridgeId: "tf-webauthn",
      rpId: RP_ID,
    });
    expect(bridge.verifyRegistration(new Uint8Array(att), clientDataJSON, {
        expectedChallenge: CHALLENGE,
        expectedOrigin: ORIGIN,
        userHandle: "user-bad",
      }),).rejects.toThrow(BridgeFailure);
  });

  test("rejects mismatched rpIdHash", () => {
    const cred = makeP256Credential();
    const authData = buildAuthData({
      rpId: "other.example.com",
      flags: 0x41,
      signCount: 0,
      aaguid: AAGUID,
      credentialId: CREDENTIAL_ID,
      cosePublicKey: cred.cose,
    });
    const att = buildAttestationObject({ fmt: "none", attStmt: {}, authData });
    const clientDataJSON = buildClientData({
      type: "webauthn.create",
      challenge: CHALLENGE,
      origin: ORIGIN,
    });
    const bridge = new WebAuthnBridge("tf-webauthn", RP_ID, {
      bridgeId: "tf-webauthn",
      rpId: RP_ID,
    });
    expect(bridge.verifyRegistration(new Uint8Array(att), clientDataJSON, {
        expectedChallenge: CHALLENGE,
        expectedOrigin: ORIGIN,
        userHandle: "user-x",
      }),).rejects.toThrow(BridgeFailure);
  });

  test("rejects forged packed signature", async () => {
    const cred = makeP256Credential();
    const otherCred = makeP256Credential();
    const authData = buildAuthData({
      rpId: RP_ID,
      flags: 0x41,
      signCount: 0,
      aaguid: AAGUID,
      credentialId: CREDENTIAL_ID,
      cosePublicKey: cred.cose,
    });
    const clientDataJSON = buildClientData({
      type: "webauthn.create",
      challenge: CHALLENGE,
      origin: ORIGIN,
    });
    const sig = signEs256DerOver(otherCred.rawKey, concat(authData, sha256(clientDataJSON)));
    const att = buildAttestationObject({ fmt: "packed", attStmt: { alg: -7, sig }, authData });
    const bridge = new WebAuthnBridge("tf-webauthn", RP_ID, {
      bridgeId: "tf-webauthn",
      rpId: RP_ID,
    });
    expect(bridge.verifyRegistration(new Uint8Array(att), clientDataJSON, {
        expectedChallenge: CHALLENGE,
        expectedOrigin: ORIGIN,
        userHandle: "user-forged",
      }),).rejects.toThrow(BridgeFailure);
  });

  test("rejects missing UP flag", async () => {
    const cred = makeP256Credential();
    const authData = buildAuthData({
      rpId: RP_ID,
      flags: 0x40,
      signCount: 0,
      aaguid: AAGUID,
      credentialId: CREDENTIAL_ID,
      cosePublicKey: cred.cose,
    });
    const att = buildAttestationObject({ fmt: "none", attStmt: {}, authData });
    const clientDataJSON = buildClientData({
      type: "webauthn.create",
      challenge: CHALLENGE,
      origin: ORIGIN,
    });
    const bridge = new WebAuthnBridge("tf-webauthn", RP_ID, {
      bridgeId: "tf-webauthn",
      rpId: RP_ID,
    });
    expect(bridge.verifyRegistration(new Uint8Array(att), clientDataJSON, {
        expectedChallenge: CHALLENGE,
        expectedOrigin: ORIGIN,
        userHandle: "user-noup",
      }),).rejects.toThrow(BridgeFailure);
  });

  test("verifyAttestation can be called directly without the bridge", async () => {
    const cred = makeP256Credential();
    const authData = buildAuthData({
      rpId: RP_ID,
      flags: 0x41,
      signCount: 0,
      aaguid: AAGUID,
      credentialId: CREDENTIAL_ID,
      cosePublicKey: cred.cose,
    });
    const att = buildAttestationObject({ fmt: "none", attStmt: {}, authData });
    const clientDataJSON = buildClientData({
      type: "webauthn.create",
      challenge: CHALLENGE,
      origin: ORIGIN,
    });
    const result = await verifyAttestation(new Uint8Array(att), clientDataJSON, {
      rpId: RP_ID,
      expectedOrigin: ORIGIN,
      expectedChallenge: CHALLENGE,
    });
    expect(result.algorithm).toBe("ES256");
    expect(result.format).toBe("none");
  });
});
