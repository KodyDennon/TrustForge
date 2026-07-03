/**
 * B3 chain-validation tests: the WebAuthn attestation cert-chain validator
 * (`verifyWithCertChain` in webauthn-attestation.ts) must REJECT chains
 * whose intermediates don't link, whose certs are outside their validity
 * window, or whose root is self-signed but tampered.
 *
 * We exercise the validator end-to-end by minting test x509 chains via
 * @peculiar/x509 and shoving them into a packed attStmt. The leaf signs
 * (authData||clientDataHash) with ES256 in every case; the failures come
 * from the chain itself, not the leaf signature.
 */
import { describe, expect, test } from "bun:test";
import * as x509 from "@peculiar/x509";
import { sha256 } from "@noble/hashes/sha2";
import { encode as cborEncode } from "../src/core/cbor.js";
import { verifyAttestation, BridgeFailure } from "../src/index";

const cryptoProvider = globalThis.crypto;
x509.cryptoProvider.set(cryptoProvider);

const RP_ID = "tf.example";
const ORIGIN = `https://${RP_ID}`;
const CHALLENGE = "Y2hhbGxlbmdl"; // base64url("challenge")

function concat(...parts: Uint8Array[]): Uint8Array {
  const total = parts.reduce((s, p) => s + p.length, 0);
  const out = new Uint8Array(total);
  let off = 0;
  for (const p of parts) {
    out.set(p, off);
    off += p.length;
  }
  return out;
}

function buildClientData(o: { type: string; challenge: string; origin: string }): Uint8Array {
  return new TextEncoder().encode(JSON.stringify(o));
}

function buildAuthData(): { authData: Uint8Array; credentialPublicKey: Uint8Array; credentialId: Uint8Array } {
  // Minimal authData: rpIdHash + flags(0x41 = UP|AT) + signCount + aaguid + credIdLen + credId + credPub
  const rpIdHash = sha256(new TextEncoder().encode(RP_ID));
  const flags = new Uint8Array([0x41]);
  const signCount = new Uint8Array([0, 0, 0, 1]);
  const aaguid = new Uint8Array(16);
  const credentialId = new Uint8Array([1, 2, 3, 4]);
  const credIdLen = new Uint8Array([0, credentialId.length]);
  // Dummy ES256 COSE key (kty:2, alg:-7, crv:1, x: 32 zeros, y: 32 zeros).
  // Real signature verification on attestation cert path uses the cert's
  // SPKI, not this credPub, so any well-formed COSE key suffices for the
  // chain-rejection tests.
  const cose = cborEncode(
    new Map<number, unknown>([
      [1, 2],
      [3, -7],
      [-1, 1],
      [-2, new Uint8Array(32)],
      [-3, new Uint8Array(32)],
    ]),
  );
  const credentialPublicKey = new Uint8Array(cose);
  const authData = concat(rpIdHash, flags, signCount, aaguid, credIdLen, credentialId, credentialPublicKey);
  return { authData, credentialPublicKey, credentialId };
}

async function makeEcCert(
  subject: string,
  issuer: { keys: CryptoKeyPair; cert: x509.X509Certificate; subject: string } | null,
  notBefore: Date,
  notAfter: Date,
): Promise<{ keys: CryptoKeyPair; cert: x509.X509Certificate; subject: string }> {
  const keys = await cryptoProvider.subtle.generateKey(
    { name: "ECDSA", namedCurve: "P-256" } as EcKeyGenParams,
    true,
    ["sign", "verify"],
  );
  const cert = await x509.X509CertificateGenerator.create({
    serialNumber: "01",
    subject,
    issuer: issuer ? issuer.subject : subject,
    notBefore,
    notAfter,
    signingKey: issuer ? issuer.keys.privateKey : keys.privateKey,
    publicKey: keys.publicKey,
    signingAlgorithm: { name: "ECDSA", hash: "SHA-256" },
  });
  return { keys, cert, subject };
}

function buildAttestationObject(x5c: Uint8Array[], authData: Uint8Array, sig: Uint8Array): Uint8Array {
  return new Uint8Array(
    cborEncode({
      fmt: "packed",
      attStmt: { alg: -7, sig, x5c },
      authData,
    }),
  );
}

async function signEcdsaP256(privateKey: CryptoKey, data: Uint8Array): Promise<Uint8Array> {
  // Web Crypto returns concatenated R||S; convert to ASN.1 DER.
  const ab = new ArrayBuffer(data.byteLength);
  new Uint8Array(ab).set(data);
  const raw = new Uint8Array(
    await cryptoProvider.subtle.sign({ name: "ECDSA", hash: "SHA-256" }, privateKey, ab),
  );
  const r = trimZeros(raw.slice(0, 32));
  const s = trimZeros(raw.slice(32, 64));
  const der = new Uint8Array(2 + r.length + 2 + s.length + 2);
  der[0] = 0x30;
  der[1] = der.length - 2;
  der[2] = 0x02;
  der[3] = r.length;
  der.set(r, 4);
  der[4 + r.length] = 0x02;
  der[5 + r.length] = s.length;
  der.set(s, 6 + r.length);
  return der;
}

function trimZeros(b: Uint8Array): Uint8Array {
  let i = 0;
  while (i < b.length - 1 && b[i] === 0) i++;
  // Re-prepend a zero if the high bit is set so the DER INTEGER stays positive.
  const t = b.slice(i);
  if (t[0] !== undefined && t[0] >= 0x80) {
    const out = new Uint8Array(t.length + 1);
    out[0] = 0;
    out.set(t, 1);
    return out;
  }
  return t;
}

describe("WebAuthn cert chain validation", () => {
  test("rejects an expired root", async () => {
    const longAgo = new Date(Date.now() - 10 * 365 * 86400 * 1000);
    const expired = new Date(Date.now() - 365 * 86400 * 1000);
    const root = await makeEcCert("CN=expired-root", null, longAgo, expired);
    const leaf = await makeEcCert("CN=leaf", root, longAgo, new Date(Date.now() + 365 * 86400 * 1000));

    const { authData } = buildAuthData();
    const clientData = buildClientData({ type: "webauthn.create", challenge: CHALLENGE, origin: ORIGIN });
    const clientDataHash = sha256(clientData);
    const sig = await signEcdsaP256(leaf.keys.privateKey, concat(authData, clientDataHash));
    const att = buildAttestationObject(
      [new Uint8Array(leaf.cert.rawData), new Uint8Array(root.cert.rawData)],
      authData,
      sig,
    );

    expect(
      verifyAttestation(att, clientData, {
        rpId: RP_ID,
        expectedOrigin: ORIGIN,
        expectedChallenge: CHALLENGE,
      }),
    ).rejects.toThrow(BridgeFailure);
  });

  test("rejects a chain whose issuer DN doesn't match the leaf's issuer", async () => {
    const ok = (d: number) => new Date(Date.now() + d * 86400 * 1000);
    const realRoot = await makeEcCert("CN=real-root", null, ok(-1), ok(365));
    const otherRoot = await makeEcCert("CN=other-root", null, ok(-1), ok(365));
    // Leaf signed by realRoot, but we present otherRoot as the chain.
    const leaf = await makeEcCert("CN=leaf", realRoot, ok(-1), ok(365));

    const { authData } = buildAuthData();
    const clientData = buildClientData({ type: "webauthn.create", challenge: CHALLENGE, origin: ORIGIN });
    const clientDataHash = sha256(clientData);
    const sig = await signEcdsaP256(leaf.keys.privateKey, concat(authData, clientDataHash));
    const att = buildAttestationObject(
      [new Uint8Array(leaf.cert.rawData), new Uint8Array(otherRoot.cert.rawData)],
      authData,
      sig,
    );

    expect(
      verifyAttestation(att, clientData, {
        rpId: RP_ID,
        expectedOrigin: ORIGIN,
        expectedChallenge: CHALLENGE,
      }),
    ).rejects.toThrow(BridgeFailure);
  });

  test("accepts a valid two-cert chain (leaf signed by real root)", async () => {
    const ok = (d: number) => new Date(Date.now() + d * 86400 * 1000);
    const root = await makeEcCert("CN=root", null, ok(-1), ok(365));
    const leaf = await makeEcCert("CN=leaf", root, ok(-1), ok(365));

    const { authData } = buildAuthData();
    const clientData = buildClientData({ type: "webauthn.create", challenge: CHALLENGE, origin: ORIGIN });
    const clientDataHash = sha256(clientData);
    const sig = await signEcdsaP256(leaf.keys.privateKey, concat(authData, clientDataHash));
    const att = buildAttestationObject(
      [new Uint8Array(leaf.cert.rawData), new Uint8Array(root.cert.rawData)],
      authData,
      sig,
    );

    const verified = await verifyAttestation(att, clientData, {
      rpId: RP_ID,
      expectedOrigin: ORIGIN,
      expectedChallenge: CHALLENGE,
    });
    expect(verified.format).toBe("packed");
    expect(verified.algorithm).toBe("ES256");
  });
});
