import { describe, expect, test } from "bun:test";
import {
  BridgeFailure,
  WebAuthnBridge,
  actorIdentityToWebauthn,
  webauthnToActorIdentity,
  type WebAuthnCredential,
} from "../src/index";

const baseCredential: WebAuthnCredential = {
  credential_id: "credential-identifier-01",
  public_key: "MCowBQYDK2VwAyEA8wHnF5mJ+0c5KqyGxWXcJ+7p3qGzlHcQmL5ZhqQvJ1o=",
  algorithm: "ed25519",
  rp_id: "example.com",
  user_handle: "dXNlci0xMjM",
  aaguid: "aaaa-bbbb",
};

describe("WebAuthn bridge", () => {
  test("produces a well-formed actor-identity", () => {
    const identity = webauthnToActorIdentity(baseCredential);
    expect(identity.identity_version).toBe("1");
    expect(identity.actor_id).toBe("tf:actor:human:example.com/dXNlci0xMjM");
    expect(identity.actor_type).toBe("human");
    expect(identity.trust_levels).toEqual(["T4"]);
    expect(identity.authority_roots[0]!.kind).toBe("hardware-key");
    expect(identity.authority_roots[0]!.id).toBe("aaaa-bbbb");
    expect(identity.public_keys[0]!.algorithm).toBe("ed25519");
  });

  test("reverse projection round-trips a credential", () => {
    const identity = webauthnToActorIdentity(baseCredential);
    const back = actorIdentityToWebauthn(identity);
    expect(back.credential_id).toBe(baseCredential.credential_id);
    expect(back.public_key).toBe(baseCredential.public_key);
    expect(back.algorithm).toBe(baseCredential.algorithm);
    expect(back.rp_id).toBe(baseCredential.rp_id);
    expect(back.user_handle).toBe(baseCredential.user_handle);
    expect(back.aaguid).toBe(baseCredential.aaguid);
  });

  test("bridge config rejects mismatched rp_id", () => {
    const bridge = new WebAuthnBridge("tf-webauthn-bridge", "example.com", {
      bridgeId: "tf-webauthn-bridge",
      rpId: "example.com",
    });
    expect(() => bridge.accept({ ...baseCredential, rp_id: "other.com" })).toThrow(BridgeFailure);
  });

  test("bridge config enforces allowed algorithms", () => {
    const bridge = new WebAuthnBridge("tf-webauthn-bridge", "example.com", {
      bridgeId: "tf-webauthn-bridge",
      rpId: "example.com",
      allowedAlgorithms: ["p256"],
    });
    expect(() => bridge.accept(baseCredential)).toThrow(BridgeFailure);
  });

  test("reverse rejects non-human actors and non-hardware roots", () => {
    const identity = webauthnToActorIdentity(baseCredential);
    const swapped = { ...identity, actor_type: "agent" } as any;
    expect(() => actorIdentityToWebauthn(swapped)).toThrow(BridgeFailure);
    const noHardware = {
      ...identity,
      authority_roots: [{ kind: "organization" as const, id: "x" }],
    };
    expect(() => actorIdentityToWebauthn(noHardware)).toThrow(BridgeFailure);
  });
});
