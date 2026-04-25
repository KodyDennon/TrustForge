import { describe, expect, test } from "bun:test";
import {
  AgentGuard,
  derivePeerActor,
  Initiator,
  Responder,
  ed25519Generate,
} from "../src/index";

const KEY_A = Uint8Array.from([
  0x9d, 0x61, 0xb1, 0x9d, 0xef, 0xfd, 0x5a, 0x60, 0xba, 0x84, 0x4a, 0xf4, 0x92, 0xec, 0x2c, 0xc4,
  0x44, 0x49, 0xc5, 0x69, 0x7b, 0x32, 0x69, 0x19, 0x70, 0x3b, 0xac, 0x03, 0x1c, 0xae, 0x7f, 0x60,
]);
// Public key derived from KEY_A (well-known RFC 8032 vector 1).
const PUB_A = Uint8Array.from([
  0xd7, 0x5a, 0x98, 0x01, 0x82, 0xb1, 0x0a, 0xb7, 0xd5, 0x4b, 0xfe, 0xd3, 0xc9, 0x64, 0x07, 0x3a,
  0x0e, 0xe1, 0x72, 0xf3, 0xda, 0xa6, 0x23, 0x25, 0xaf, 0x02, 0x1a, 0x68, 0xf7, 0x07, 0x51, 0x1a,
]);

describe("derivePeerActor", () => {
  test("returns canonical tf:actor:process:key/<thumbprint> URI", () => {
    const uri = derivePeerActor(PUB_A);
    expect(uri).toMatch(/^tf:actor:process:key\/[0-9a-f]{16}$/);
  });

  test("is deterministic for the same public key", () => {
    expect(derivePeerActor(PUB_A)).toBe(derivePeerActor(PUB_A));
  });

  test("differs for different public keys", () => {
    const otherPub = new Uint8Array(32);
    for (let i = 0; i < 32; i++) otherPub[i] = (i * 7) & 0xff;
    expect(derivePeerActor(otherPub)).not.toBe(derivePeerActor(PUB_A));
  });

  test("rejects keys that aren't 32 bytes", () => {
    expect(() => derivePeerActor(new Uint8Array(16))).toThrow();
  });
});

describe("Session handshake propagates derived peer actor + claim", () => {
  test("responder sees the initiator's key-derived actor", async () => {
    const initId = await ed25519Generate();
    const respId = await ed25519Generate();

    const initiator = new Initiator({
      selfActor: "tf:actor:agent:example.com/the-claim",
      peerHint: "tf:actor:service:example.com/the-server",
      identityPriv: initId.privateKey,
      identityPub: initId.publicKey,
    });
    const responder = new Responder({
      selfActor: "tf:actor:service:example.com/the-server",
      identityPriv: respId.privateKey,
      identityPub: respId.publicKey,
    });

    const helloI = initiator.start();
    const helloR = await responder.processHelloI(helloI);
    const { auth, session: initSession } = await initiator.processHelloR(helloR);
    const respSession = await responder.processAuth(auth);

    // Responder sees the initiator's KEY-DERIVED URI as peerActor — never
    // the literal "(unknown)" or the unverified peer_hint.
    expect(respSession.peerActor).toBe(derivePeerActor(initId.publicKey));
    // Self-claim plumbing arrives in B2 (HelloI shape change). For B1, the
    // claim is undefined on both sides; downstream code tolerates that.
    expect(respSession.peerActorClaim).toBeUndefined();

    // Initiator sees the responder's key-derived URI.
    expect(initSession.peerActor).toBe(derivePeerActor(respId.publicKey));
    expect(initSession.peerActorClaim).toBeUndefined();
  });
});

describe("AgentGuard enforces allow_actors / deny_actors", () => {
  const contract = {
    contract_version: "1",
    spec_version: "TF-0006-draft",
    project: "actor-scope",
    trust_domain: "example.com",
    actions: [
      {
        name: "fs.write",
        risk: "R0",
        approval: "none",
        reversible: true,
        allow_actors: ["tf:actor:process:key/*"],
      },
      {
        name: "fs.read",
        risk: "R0",
        approval: "none",
        reversible: true,
        deny_actors: ["tf:actor:agent:evil.example/*"],
      },
      {
        name: "admin.shutdown",
        risk: "R5",
        approval: "quorum",
        reversible: false,
        allow_actors: ["tf:actor:human:example.com/admin-1"],
      },
    ],
  };

  test("allow_actors permits a matching actor", () => {
    const guard = AgentGuard.fromContract(contract);
    const decision = guard.check({
      actor: "tf:actor:process:key/abcdef0123456789",
      action: "fs.write",
    });
    expect(decision.kind).toBe("allow");
  });

  test("allow_actors denies a non-matching actor", () => {
    const guard = AgentGuard.fromContract(contract);
    const decision = guard.check({
      actor: "tf:actor:agent:other.example/x",
      action: "fs.write",
    });
    expect(decision.kind).toBe("deny");
    if (decision.kind === "deny") {
      expect(decision.reason).toContain("allow_actors");
    }
  });

  test("deny_actors blocks even when allow_actors would permit", () => {
    const guard = AgentGuard.fromContract(contract);
    const decision = guard.check({
      actor: "tf:actor:agent:evil.example/scout",
      action: "fs.read",
    });
    expect(decision.kind).toBe("deny");
    if (decision.kind === "deny") {
      expect(decision.reason).toContain("deny_actors");
    }
  });

  test("matches against actor_claim as well as the canonical actor", () => {
    const guard = AgentGuard.fromContract(contract);
    const decision = guard.check({
      actor: "tf:actor:process:key/0011223344556677",
      actor_claim: "tf:actor:human:example.com/admin-1",
      action: "admin.shutdown",
    });
    expect(decision.kind).toBe("approval-required");
  });

  test("missing actor for an allow_actors-restricted action fails closed", () => {
    const guard = AgentGuard.fromContract(contract);
    const decision = guard.check({
      action: "admin.shutdown",
    });
    expect(decision.kind).toBe("deny");
    if (decision.kind === "deny") {
      expect(decision.reason).toContain("authenticated actor");
    }
  });

  test("actions without allow_actors / deny_actors stay open (backwards compat)", () => {
    const open = {
      contract_version: "1",
      spec_version: "TF-0006-draft",
      project: "open",
      trust_domain: "example.com",
      actions: [{ name: "tf.ping", risk: "R0", approval: "none", reversible: true }],
    };
    const guard = AgentGuard.fromContract(open);
    const decision = guard.check({
      actor: "tf:actor:process:key/anything",
      action: "tf.ping",
    });
    expect(decision.kind).toBe("allow");
  });
});
