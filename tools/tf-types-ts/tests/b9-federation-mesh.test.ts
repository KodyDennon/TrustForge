/**
 * B9 federation hardening + mesh-bridge cleanup:
 *   - FederatedTrustStore.add verifies before insert (was unverified)
 *   - findFor returns the latest-issued attestation, not first-by-
 *     insertion-order
 *   - non-ed25519 bundle entries surface as verification_warnings
 *     instead of being silently dropped
 *   - service-mesh bridges no longer fabricate `public_key:"AA=="`
 *     ed25519 keys; they emit `algorithm:"external-attestation"`
 *     with a real sha256 fingerprint of the SVID / client_id.
 */
import { describe, expect, test } from "bun:test";
import {
  ed25519Generate,
  FederatedTrustStore,
  ServiceMeshBridge,
  signFederationAttestation,
  type FederationAttestation,
} from "../src/index";

async function buildAttestation(args: {
  issuerDomain: string;
  subjectDomain: string;
  attestationId: string;
  validUntil: string;
  issuedAt?: string;
  trustBundleKeyValue?: string;
  bundleKind?: string;
}): Promise<{ attestation: FederationAttestation; issuerPub: Uint8Array; issuerPriv: Uint8Array }> {
  const issuer = await ed25519Generate();
  const responder = await ed25519Generate();
  const att = await signFederationAttestation({
    attestationId: args.attestationId,
    issuerDomain: args.issuerDomain,
    subjectDomain: args.subjectDomain,
    issuer: `tf:actor:service:${args.issuerDomain}/auditor`,
    privateKey: issuer.privateKey,
    validUntil: args.validUntil,
    issuedAt: args.issuedAt,
    trustBundle: [
      {
        kind: (args.bundleKind ?? "ed25519") as "ed25519",
        key_id: "k1",
        value: args.trustBundleKeyValue ?? Buffer.from(responder.publicKey).toString("base64"),
      },
    ],
    scope: ["fs.read"],
  });
  return { attestation: att, issuerPub: issuer.publicKey, issuerPriv: issuer.privateKey };
}

describe("B9 — FederatedTrustStore.add verifies before insert", () => {
  test("an attestation with a tampered scope is rejected by add()", async () => {
    const { attestation, issuerPub } = await buildAttestation({
      issuerDomain: "example.com",
      subjectDomain: "partner.example.com",
      attestationId: "a-tamper",
      validUntil: "2027-01-01T00:00:00Z",
    });
    // Tamper with scope after signing.
    attestation.scope = ["fs.write"];
    const store = new FederatedTrustStore();
    let threw: Error | undefined;
    try {
      await store.add(attestation, issuerPub);
    } catch (err) {
      threw = err as Error;
    }
    expect(threw).toBeDefined();
    expect(threw!.message).toContain("refusing to add");
  });

  test("addUnverified inserts unconditionally for replay tooling", async () => {
    const { attestation } = await buildAttestation({
      issuerDomain: "example.com",
      subjectDomain: "partner.example.com",
      attestationId: "a-unverified",
      validUntil: "2027-01-01T00:00:00Z",
    });
    const store = new FederatedTrustStore();
    store.addUnverified(attestation);
    expect(store.list()).toHaveLength(1);
  });
});

describe("B9 — findFor returns latest-issued attestation", () => {
  test("a newer attestation supersedes an older one for the same subject", async () => {
    const store = new FederatedTrustStore();
    const old = await buildAttestation({
      issuerDomain: "example.com",
      subjectDomain: "partner.example.com",
      attestationId: "old",
      validUntil: "2027-01-01T00:00:00Z",
      issuedAt: "2025-01-01T00:00:00Z",
    });
    const recent = await buildAttestation({
      issuerDomain: "example.com",
      subjectDomain: "partner.example.com",
      attestationId: "recent",
      validUntil: "2027-01-01T00:00:00Z",
      issuedAt: "2026-04-01T00:00:00Z",
    });
    store.addUnverified(old.attestation);
    store.addUnverified(recent.attestation);
    const got = store.findFor("tf:actor:service:partner.example.com/x", "partner.example.com");
    expect(got).toBeDefined();
    expect(got!.attestation_id).toBe("recent");
  });
});

describe("B9 — non-ed25519 bundle keys surface as warnings, not silent drops", () => {
  test("an attestation with a non-ed25519 entry produces a verification_warning", async () => {
    const responder = await ed25519Generate();
    const issuer = await ed25519Generate();
    const att = await signFederationAttestation({
      attestationId: "mixed-bundle",
      issuerDomain: "example.com",
      subjectDomain: "partner.example.com",
      issuer: "tf:actor:service:example.com/auditor",
      privateKey: issuer.privateKey,
      validUntil: "2027-01-01T00:00:00Z",
      trustBundle: [
        {
          kind: "rsa-pkcs1-v1_5" as "ed25519", // wrong kind on purpose
          key_id: "rsa-1",
          value: "Zm9vYmFy",
        },
        {
          kind: "ed25519",
          key_id: "ed-1",
          value: Buffer.from(responder.publicKey).toString("base64"),
        },
      ],
      scope: ["fs.read"],
    });
    const store = new FederatedTrustStore();
    store.addUnverified(att);

    // Sign a small message with the ed25519 responder so verifyForeign
    // matches the real key.
    const msg = new TextEncoder().encode("hello");
    const tf = await import("../src/index");
    const sig = await tf.ed25519Sign(msg, responder.privateKey);

    const result = await store.verifyForeign({
      actor: "tf:actor:service:partner.example.com/x",
      subjectDomain: "partner.example.com",
      signed: { message: msg, signature: sig },
    });
    expect(result.ok).toBe(true);
    expect(result.verification_warnings).toBeDefined();
    expect(result.verification_warnings!.some((w) => w.includes("rsa-pkcs1-v1_5"))).toBe(true);
  });
});

describe("B9 — mesh bridges no longer fabricate ed25519 keys", () => {
  test("Istio + Linkerd projections emit external-attestation pseudo-keys", () => {
    const bridge = new ServiceMeshBridge({ bridgeId: "tf-mesh", trustDomain: "example.com" });
    const istio = bridge.acceptIstio({
      spiffe_id: "spiffe://example.org/ns/prod/sa/api",
    });
    expect(istio.identity.public_keys[0]!.algorithm).toBe("external-attestation");
    expect(istio.identity.public_keys[0]!.public_key).toMatch(/^sha256:[0-9a-f]{64}$/);

    const linkerd = bridge.acceptLinkerd({
      client_id: "api.prod.serviceaccount.identity.example.cluster.local",
    });
    expect(linkerd.identity.public_keys[0]!.algorithm).toBe("external-attestation");
    expect(linkerd.identity.public_keys[0]!.public_key).toMatch(/^sha256:[0-9a-f]{64}$/);
  });
});
