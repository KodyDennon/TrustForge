import { describe, expect, test } from "bun:test";
import {
  FederatedTrustStore,
  attestationFromSpiffeBundle,
  attestationSigningBytes,
  ed25519Generate,
  ed25519Sign,
  signFederationAttestation,
  verifyFederationAttestation,
} from "../src/index";

describe("FederationAttestation", () => {
  test("signed attestation round-trips through verify", async () => {
    const issuer = await ed25519Generate();
    const att = await signFederationAttestation({
      attestationId: "fed-1",
      issuerDomain: "example.com",
      subjectDomain: "partner.example.org",
      subjectActor: "tf:actor:agent:partner.example.org/code-helper",
      scope: ["file.read", "file.write"],
      trustLevelsGranted: ["T3"],
      trustBundle: [
        {
          kind: "ed25519",
          key_id: "partner-root",
          value: Buffer.from(new Uint8Array(32).fill(1)).toString("base64"),
        },
      ],
      issuedAt: "2026-04-24T11:00:00Z",
      validUntil: "2026-12-31T23:59:59Z",
      issuer: "tf:actor:service:example.com/tf-daemon",
      privateKey: issuer.privateKey,
    });
    expect(att.attestation_id).toBe("fed-1");
    expect(att.signature.signature.length).toBeGreaterThan(0);
    const v = await verifyFederationAttestation({
      attestation: att,
      issuerPublicKey: issuer.publicKey,
      now: "2026-04-24T12:00:00Z",
    });
    expect(v.ok).toBe(true);
  });

  test("verify rejects tampered scope", async () => {
    const issuer = await ed25519Generate();
    const att = await signFederationAttestation({
      attestationId: "fed-1",
      issuerDomain: "example.com",
      subjectDomain: "partner.example.org",
      trustBundle: [
        { kind: "ed25519", value: Buffer.from(new Uint8Array(32)).toString("base64") },
      ],
      validUntil: "2026-12-31T23:59:59Z",
      issuer: "tf:actor:service:example.com/tf-daemon",
      privateKey: issuer.privateKey,
    });
    att.scope = ["payment.charge"];
    const v = await verifyFederationAttestation({ attestation: att, issuerPublicKey: issuer.publicKey });
    expect(v.ok).toBe(false);
  });

  test("verify rejects expired attestation", async () => {
    const issuer = await ed25519Generate();
    const att = await signFederationAttestation({
      attestationId: "fed-old",
      issuerDomain: "example.com",
      subjectDomain: "partner.example.org",
      trustBundle: [
        { kind: "ed25519", value: Buffer.from(new Uint8Array(32)).toString("base64") },
      ],
      issuedAt: "2024-01-01T00:00:00Z",
      validUntil: "2024-12-31T23:59:59Z",
      issuer: "tf:actor:service:example.com/tf-daemon",
      privateKey: issuer.privateKey,
    });
    const v = await verifyFederationAttestation({
      attestation: att,
      issuerPublicKey: issuer.publicKey,
      now: "2026-04-24T12:00:00Z",
    });
    expect(v.ok).toBe(false);
    expect(v.reason).toContain("window");
  });

  test("attestationSigningBytes is stable", async () => {
    const issuer = await ed25519Generate();
    const att = await signFederationAttestation({
      attestationId: "fed-stable",
      issuerDomain: "example.com",
      subjectDomain: "partner.example.org",
      trustBundle: [
        { kind: "ed25519", value: Buffer.from(new Uint8Array(32)).toString("base64") },
      ],
      validUntil: "2030-01-01T00:00:00Z",
      issuer: "tf:actor:service:example.com/tf-daemon",
      privateKey: issuer.privateKey,
    });
    const a = attestationSigningBytes(att);
    const b = attestationSigningBytes({ ...att });
    expect(Buffer.from(a).toString("hex")).toBe(Buffer.from(b).toString("hex"));
  });
});

describe("FederatedTrustStore", () => {
  test("verifyForeign succeeds when peer signature matches a bundle key", async () => {
    const issuer = await ed25519Generate();
    const partner = await ed25519Generate();
    const att = await signFederationAttestation({
      attestationId: "fed-1",
      issuerDomain: "example.com",
      subjectDomain: "partner.example.org",
      subjectActor: "tf:actor:agent:partner.example.org/code-helper",
      scope: ["file.read"],
      trustLevelsGranted: ["T3"],
      trustBundle: [
        {
          kind: "ed25519",
          key_id: "partner-root",
          value: Buffer.from(partner.publicKey).toString("base64"),
        },
      ],
      validUntil: "2030-12-31T23:59:59Z",
      issuer: "tf:actor:service:example.com/tf-daemon",
      privateKey: issuer.privateKey,
    });
    const store = new FederatedTrustStore();
    store.addUnverified(att);

    const message = new TextEncoder().encode("partner-signed payload");
    const sig = await ed25519Sign(message, partner.privateKey);
    const result = await store.verifyForeign({
      actor: "tf:actor:agent:partner.example.org/code-helper",
      subjectDomain: "partner.example.org",
      signed: { message, signature: sig },
    });
    expect(result.ok).toBe(true);
    expect(result.matchedAttestationId).toBe("fed-1");
    expect(result.trustLevels).toEqual(["T3"]);
    expect(result.scope).toEqual(["file.read"]);
    expect(result.capabilities?.[0]?.name).toBe("file.read");
  });

  test("verifyForeign rejects when no bundle key matches", async () => {
    const issuer = await ed25519Generate();
    const partner = await ed25519Generate();
    const stranger = await ed25519Generate();
    const att = await signFederationAttestation({
      attestationId: "fed-2",
      issuerDomain: "example.com",
      subjectDomain: "partner.example.org",
      trustBundle: [
        { kind: "ed25519", value: Buffer.from(partner.publicKey).toString("base64") },
      ],
      validUntil: "2030-01-01T00:00:00Z",
      issuer: "tf:actor:service:example.com/tf-daemon",
      privateKey: issuer.privateKey,
    });
    const store = new FederatedTrustStore();
    store.addUnverified(att);
    const message = new TextEncoder().encode("intruder");
    const sig = await ed25519Sign(message, stranger.privateKey);
    const result = await store.verifyForeign({
      actor: "tf:actor:agent:partner.example.org/x",
      subjectDomain: "partner.example.org",
      signed: { message, signature: sig },
    });
    expect(result.ok).toBe(false);
  });

  test("verifyForeign rejects when no attestation exists for the domain", async () => {
    const store = new FederatedTrustStore();
    const result = await store.verifyForeign({
      actor: "tf:actor:agent:rogue.example.com/x",
      subjectDomain: "rogue.example.com",
    });
    expect(result.ok).toBe(false);
  });

  test("attestationFromSpiffeBundle wraps OKP Ed25519 keys into a TrustForge attestation draft", () => {
    const draft = attestationFromSpiffeBundle(
      {
        trust_domain: "partner.example.org",
        keys: [
          { kty: "OKP", crv: "Ed25519", kid: "k1", x: "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8" },
          { kty: "RSA", n: "x", e: "AQAB" },
        ],
      },
      {
        issuerDomain: "example.com",
        issuer: "tf:actor:service:example.com/tf-daemon",
        validUntil: "2030-01-01T00:00:00Z",
      },
    );
    expect(draft.subject_domain).toBe("partner.example.org");
    expect(draft.trust_bundle.length).toBe(1);
    expect(draft.trust_bundle[0]!.kind).toBe("ed25519");
  });
});
