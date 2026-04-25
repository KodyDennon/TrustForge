import { describe, expect, test } from "bun:test";
import { readFileSync } from "node:fs";
import { join } from "node:path";
import { parse as parseYAML } from "yaml";
import {
  ed25519Generate,
  RelayHandler,
  RelayPolicyError,
  signRelayAuthority,
  verifyRelayAuthority,
  type RelayAuthority,
  type RelayForwardedEvent,
  type RelayFrame,
} from "../src/index";

interface Vector {
  name: string;
  authority: {
    relay: string;
    kinds: string[];
    max_hop_count: number;
    valid_from: string;
    valid_until: string;
  };
  frame: {
    destination: string;
    hop_count: number;
    size_bytes: number;
    expires_at?: string;
  };
  expect: "forward" | "reject";
  expect_hop_count_out?: number;
  reason_substring?: string;
}

interface VectorFile {
  now: string;
  vectors: Vector[];
}

function loadVectors(): VectorFile {
  const path = join(import.meta.dir, "..", "..", "..", "conformance", "relay-forwarding-vectors.yaml");
  return parseYAML(readFileSync(path, "utf8")) as VectorFile;
}

async function buildAuthority(
  template: Vector["authority"],
  issuerPriv: Uint8Array,
  issuer: string,
): Promise<RelayAuthority> {
  return signRelayAuthority({
    authority: {
      relay_authority_version: "1",
      relay: template.relay,
      trust_domain: "example.com",
      kinds: template.kinds as RelayAuthority["kinds"],
      max_hop_count: template.max_hop_count,
      valid_from: template.valid_from,
      valid_until: template.valid_until,
      issuer,
    },
    privateKey: issuerPriv,
    signer: issuer,
  });
}

describe("Relay forwarding parity vectors", () => {
  const vectors = loadVectors();
  for (const v of vectors.vectors) {
    test(v.name, async () => {
      const issuer = await ed25519Generate();
      const authority = await buildAuthority(
        v.authority,
        issuer.privateKey,
        "tf:actor:service:example.com/tf-daemon",
      );
      const events: RelayForwardedEvent[] = [];
      const handler = new RelayHandler({
        authority,
        issuerPublicKey: issuer.publicKey,
        onForwarded: (ev) => events.push(ev),
        now: () => vectors.now,
      });
      const frame: RelayFrame = {
        ciphertext: new Uint8Array(v.frame.size_bytes),
        destination: v.frame.destination as RelayFrame["destination"],
        hop_count: v.frame.hop_count,
        expires_at: v.frame.expires_at,
      };
      if (v.expect === "forward") {
        const out = await handler.forward(frame);
        expect(out.hop_count).toBe(v.expect_hop_count_out!);
        expect(events.length).toBe(1);
      } else {
        await expect(handler.forward(frame)).rejects.toThrow(RelayPolicyError);
        expect(events.length).toBe(0);
      }
    });
  }
});

describe("Relay model invariants", () => {
  test("RelayHandler does not expose decrypt or execute methods", () => {
    const fakeAuthority: RelayAuthority = {
      relay_authority_version: "1",
      relay: "tf:actor:relay:example.com/edge",
      trust_domain: "example.com",
      kinds: ["forward-only"],
      valid_from: "2026-04-24T00:00:00Z",
      issuer: "tf:actor:service:example.com/tf-daemon",
      signature: { algorithm: "ed25519", signer: "tf:actor:service:example.com/tf-daemon", signature: "" },
    };
    const handler = new RelayHandler({
      authority: fakeAuthority,
      issuerPublicKey: new Uint8Array(32),
    });
    expect((handler as unknown as Record<string, unknown>).decrypt).toBeUndefined();
    expect((handler as unknown as Record<string, unknown>).execute).toBeUndefined();
  });

  test("verifyRelayAuthority detects tampered max_hop_count", async () => {
    const issuer = await ed25519Generate();
    const authority = await signRelayAuthority({
      authority: {
        relay_authority_version: "1",
        relay: "tf:actor:relay:example.com/edge",
        trust_domain: "example.com",
        kinds: ["forward-only"],
        max_hop_count: 4,
        valid_from: "2026-04-24T00:00:00Z",
        issuer: "tf:actor:service:example.com/tf-daemon",
      },
      privateKey: issuer.privateKey,
      signer: "tf:actor:service:example.com/tf-daemon",
    });
    authority.max_hop_count = 99;
    const v = await verifyRelayAuthority(authority, issuer.publicKey);
    expect(v.ok).toBe(false);
  });

  test("rate limit is enforced per-minute", async () => {
    const issuer = await ed25519Generate();
    const authority = await signRelayAuthority({
      authority: {
        relay_authority_version: "1",
        relay: "tf:actor:relay:example.com/edge",
        trust_domain: "example.com",
        kinds: ["forward-only"],
        max_hop_count: 8,
        rate_limit_per_minute: 2,
        valid_from: "2026-04-24T00:00:00Z",
        valid_until: "2030-01-01T00:00:00Z",
        issuer: "tf:actor:service:example.com/tf-daemon",
      },
      privateKey: issuer.privateKey,
      signer: "tf:actor:service:example.com/tf-daemon",
    });
    const handler = new RelayHandler({
      authority,
      issuerPublicKey: issuer.publicKey,
      now: () => "2026-04-24T12:00:00Z",
    });
    const frame: RelayFrame = {
      ciphertext: new Uint8Array(16),
      destination: "tf:actor:agent:example.com/code-helper",
      hop_count: 0,
    };
    await handler.forward(frame);
    await handler.forward({ ...frame });
    await expect(handler.forward({ ...frame })).rejects.toThrow(RelayPolicyError);
  });
});
