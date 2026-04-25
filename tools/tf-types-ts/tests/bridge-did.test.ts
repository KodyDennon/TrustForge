import { describe, expect, test } from "bun:test";
import {
  DidBridge,
  ed25519Generate,
  ed25519PublicKeyToDidKey,
  ed25519Sign,
} from "../src/index";

describe("DID bridge", () => {
  test("did:key resolves to a DID document with one Ed25519 verification method", async () => {
    const pair = await ed25519Generate();
    const did = `did:key:${ed25519PublicKeyToDidKey(pair.publicKey).slice(1)}`;
    // Above produces "did:key:zXX..." — the helper already prefixes "z".
    const correctDid = `did:key:${ed25519PublicKeyToDidKey(pair.publicKey)}`;
    const bridge = new DidBridge({ bridgeId: "tf-did", trustDomain: "example.com" });
    const doc = await bridge.resolve(correctDid);
    expect(doc.id).toBe(correctDid);
    expect(doc.verificationMethod?.length).toBe(1);
    expect(doc.verificationMethod![0]!.type).toBe("Ed25519VerificationKey2020");
    void did;
  });

  test("accept projects a DID into an ActorIdentity bound to the trust domain", async () => {
    const pair = await ed25519Generate();
    const did = `did:key:${ed25519PublicKeyToDidKey(pair.publicKey)}`;
    const bridge = new DidBridge({ bridgeId: "tf-did", trustDomain: "example.com" });
    const result = await bridge.accept(did);
    expect(result.identity.actor_type).toBe("human");
    expect(result.identity.actor_id.startsWith("tf:actor:human:example.com/")).toBe(true);
    expect(result.identity.public_keys[0]!.algorithm).toBe("ed25519");
  });

  test("verifySignature accepts an ed25519 signature backed by the resolved DID", async () => {
    const pair = await ed25519Generate();
    const did = `did:key:${ed25519PublicKeyToDidKey(pair.publicKey)}`;
    const bridge = new DidBridge({ bridgeId: "tf-did", trustDomain: "example.com" });
    const msg = new TextEncoder().encode("hello did");
    const sig = await ed25519Sign(msg, pair.privateKey);
    expect(await bridge.verifySignature(did, msg, sig)).toBe(true);
    expect(await bridge.verifySignature(did, msg, new Uint8Array(64))).toBe(false);
  });

  test("rejects DID methods outside the allow-list", async () => {
    const bridge = new DidBridge({
      bridgeId: "tf-did",
      trustDomain: "example.com",
      allowedMethods: ["web"],
    });
    await expect(bridge.resolve("did:key:zINVALID")).rejects.toThrow();
  });

  test("delegates non-key DIDs to the user-supplied resolver", async () => {
    const bridge = new DidBridge({
      bridgeId: "tf-did",
      trustDomain: "example.com",
      resolver: async (didUrl) => ({
        id: didUrl,
        verificationMethod: [
          {
            id: `${didUrl}#k1`,
            type: "JsonWebKey2020",
            controller: didUrl,
            publicKeyJwk: { kty: "OKP", crv: "Ed25519", x: "iK6N1RFEFdfPhFoCa2RoBb37rLqPmvwzM6jcfGAyD7w" },
          },
        ],
      }),
    });
    const doc = await bridge.resolve("did:web:example.com");
    expect(doc.id).toBe("did:web:example.com");
  });
});
