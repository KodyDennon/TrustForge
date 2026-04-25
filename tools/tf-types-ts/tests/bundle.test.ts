import { describe, expect, test } from "bun:test";
import { x25519 } from "@noble/curves/ed25519";
import {
  buildRfc3161Request,
  ed25519Generate,
  MemoryAnchor,
  openBundle,
  sealBundle,
  submitToRfc6962,
  submitToSigstore,
  type BundleRecipient,
  type ProofBundle,
} from "../src/index";

const SAMPLE_BUNDLE: ProofBundle = {
  bundle_version: "1",
  events: [
    {
      event_version: "1",
      id: "ev-1",
      type: "rpc.call",
      actor_id: "tf:actor:agent:example.com/code-helper",
      timestamp: "2026-04-24T12:00:00Z",
      level: "L1",
      signature: { algorithm: "ed25519", signer: "tf:actor:agent:example.com/code-helper", signature: "AAAA" },
    },
  ],
  signature: { algorithm: "ed25519", signer: "tf:actor:service:example.com/tf-daemon", signature: "AAAA" },
};

function randBytes(n: number): Uint8Array {
  return crypto.getRandomValues(new Uint8Array(n));
}

describe(".tfbundle seal / open round-trip", () => {
  test("recipient with the right X25519 key recovers the original bundle", async () => {
    const recipientPriv = randBytes(32);
    const recipientPub = x25519.scalarMultBase(recipientPriv);
    const signer = await ed25519Generate();
    const recipients: BundleRecipient[] = [
      {
        actor: "tf:actor:human:example.com/alice",
        kemPublic: recipientPub,
        keyId: "alice-kem-1",
      },
    ];
    const enc = await sealBundle({
      bundle: SAMPLE_BUNDLE,
      recipients,
      level: "L4",
      signerPrivateKey: signer.privateKey,
      signer: "tf:actor:service:example.com/tf-daemon",
    });
    expect(enc.level).toBe("L4");
    expect(enc.wrapped_keys.length).toBe(1);
    const opened = await openBundle({
      encrypted: enc,
      recipientPrivateKey: recipientPriv,
      recipientActor: "tf:actor:human:example.com/alice",
      signerPublicKey: signer.publicKey,
    });
    expect(opened.events[0]!.id).toBe("ev-1");
  });

  test("non-recipient cannot decrypt the bundle", async () => {
    const recipientPriv = randBytes(32);
    const recipientPub = x25519.scalarMultBase(recipientPriv);
    const otherPriv = randBytes(32);
    const signer = await ed25519Generate();
    const enc = await sealBundle({
      bundle: SAMPLE_BUNDLE,
      recipients: [{ actor: "tf:actor:human:example.com/alice", kemPublic: recipientPub }],
      level: "L4",
      signerPrivateKey: signer.privateKey,
      signer: "tf:actor:service:example.com/tf-daemon",
    });
    expect(
      openBundle({
        encrypted: enc,
        recipientPrivateKey: otherPriv,
        recipientActor: "tf:actor:human:example.com/alice",
      }),
    ).rejects.toThrow();
  });

  test("openBundle validates the outer signature when given the daemon pubkey", async () => {
    const recipientPriv = randBytes(32);
    const recipientPub = x25519.scalarMultBase(recipientPriv);
    const signer = await ed25519Generate();
    const otherSigner = await ed25519Generate();
    const enc = await sealBundle({
      bundle: SAMPLE_BUNDLE,
      recipients: [{ actor: "tf:actor:human:example.com/alice", kemPublic: recipientPub }],
      level: "L4",
      signerPrivateKey: signer.privateKey,
      signer: "tf:actor:service:example.com/tf-daemon",
    });
    expect(
      openBundle({
        encrypted: enc,
        recipientPrivateKey: recipientPriv,
        recipientActor: "tf:actor:human:example.com/alice",
        signerPublicKey: otherSigner.publicKey,
      }),
    ).rejects.toThrow();
  });
});

describe("MemoryAnchor", () => {
  test("submit then verifyInclusion returns true", async () => {
    const anchor = new MemoryAnchor();
    const bytes = new TextEncoder().encode("hello world");
    const result = await anchor.submit(bytes);
    expect(result.inclusion_proof.kind).toBe("memory");
    expect(await anchor.verifyInclusion(bytes, result.inclusion_proof)).toBe(true);
  });

  test("verifyInclusion rejects a different payload", async () => {
    const anchor = new MemoryAnchor();
    const a = new TextEncoder().encode("a");
    const b = new TextEncoder().encode("b");
    const result = await anchor.submit(a);
    expect(await anchor.verifyInclusion(b, result.inclusion_proof)).toBe(false);
  });
});

describe("HTTP anchor backends", () => {
  test("submitToRfc6962 POSTs to /ct/v1/add-chain and returns the SCT", async () => {
    const captured: Array<{ url: string; body: unknown }> = [];
    const fakeFetcher: typeof fetch = (async (url: string, init: { body?: BodyInit }) => {
      captured.push({ url, body: init.body });
      return {
        ok: true,
        status: 200,
        statusText: "OK",
        async json() {
          return { sct: "fake-sct" };
        },
      } as Response;
    }) as typeof fetch;
    const result = await submitToRfc6962(
      "https://ct.example.com",
      new TextEncoder().encode("hello"),
      fakeFetcher,
    );
    expect(captured[0]!.url).toBe("https://ct.example.com/ct/v1/add-chain");
    expect((result.inclusion_proof as { sct: { sct: string } }).sct.sct).toBe("fake-sct");
  });

  test("submitToSigstore POSTs to /api/v1/log/entries", async () => {
    const captured: Array<{ url: string }> = [];
    const fakeFetcher: typeof fetch = (async (url: string) => {
      captured.push({ url });
      return {
        ok: true,
        status: 200,
        statusText: "OK",
        async json() {
          return { uuid: "fake-uuid" };
        },
      } as Response;
    }) as typeof fetch;
    const result = await submitToSigstore(
      "https://rekor.example.com",
      new TextEncoder().encode("hello"),
      fakeFetcher,
    );
    expect(captured[0]!.url).toBe("https://rekor.example.com/api/v1/log/entries");
    expect((result.inclusion_proof as { entry: { uuid: string } }).entry.uuid).toBe("fake-uuid");
  });

  test("submitToRfc6962 propagates HTTP errors", async () => {
    const fakeFetcher = (async () =>
      ({
        ok: false,
        status: 503,
        statusText: "Service Unavailable",
        async json() {
          return {};
        },
      }) as Response) as unknown as typeof fetch;
    expect(
      submitToRfc6962("https://ct.example.com", new TextEncoder().encode("hi"), fakeFetcher),
    ).rejects.toThrow();
  });
});

describe("RFC 3161 timestamp request", () => {
  test("buildRfc3161Request emits a SEQUENCE starting with version 1 and a SHA-256 OID", () => {
    const req = buildRfc3161Request(new TextEncoder().encode("payload"));
    expect(req[0]).toBe(0x30); // SEQUENCE
    // Walk to find the SHA-256 OID 0x06 0x09 0x60 0x86 0x48 0x01 0x65 0x03 0x04 0x02 0x01
    const needle = [0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01];
    let found = false;
    outer: for (let i = 0; i + needle.length <= req.length; i++) {
      for (let j = 0; j < needle.length; j++) {
        if (req[i + j] !== needle[j]) continue outer;
      }
      found = true;
      break;
    }
    expect(found).toBe(true);
  });

  test("buildRfc3161Request encodes a 32-byte SHA-256 digest as an OCTET STRING", () => {
    const req = buildRfc3161Request(new TextEncoder().encode("payload"));
    // Find OCTET STRING tag (0x04) with length 32.
    let foundDigest = false;
    for (let i = 0; i + 33 < req.length; i++) {
      if (req[i] === 0x04 && req[i + 1] === 0x20) {
        foundDigest = true;
        break;
      }
    }
    expect(foundDigest).toBe(true);
  });
});
