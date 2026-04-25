import { describe, expect, test } from "bun:test";
import {
  Initiator,
  Responder,
  ed25519Generate,
  mldsaGenerate,
  SESSION_SUITE_HYBRID_ED25519_MLDSA65,
} from "../src/index";

describe("hybrid handshake", () => {
  async function makeHybridPair() {
    const initEd = await ed25519Generate();
    const respEd = await ed25519Generate();
    const initPq = mldsaGenerate("ml-dsa-65");
    const respPq = mldsaGenerate("ml-dsa-65");
    return {
      initiator: new Initiator({
        selfActor: "tf:actor:agent:example.com/i",
        peerHint: "tf:actor:service:example.com/r",
        identityPriv: initEd.privateKey,
        identityPub: initEd.publicKey,
        preferredSuite: SESSION_SUITE_HYBRID_ED25519_MLDSA65,
        identityMldsaPriv: initPq.privateKey,
        identityMldsaPub: initPq.publicKey,
      }),
      responder: new Responder({
        selfActor: "tf:actor:service:example.com/r",
        identityPriv: respEd.privateKey,
        identityPub: respEd.publicKey,
        identityMldsaPriv: respPq.privateKey,
        identityMldsaPub: respPq.publicKey,
      }),
    };
  }

  test("round-trips with both ed25519 and ml-dsa-65 signatures", async () => {
    const { initiator, responder } = await makeHybridPair();
    const helloI = initiator.start();
    expect(helloI.suite).toBe(SESSION_SUITE_HYBRID_ED25519_MLDSA65);

    const helloR = await responder.processHelloI(helloI);
    expect(helloR.selected_suite).toBe(SESSION_SUITE_HYBRID_ED25519_MLDSA65);
    expect(helloR.signature_mldsa).toBeDefined();
    expect(helloR.ident_pub_mldsa).toBeDefined();

    const { auth, session: initSession } = await initiator.processHelloR(helloR);
    expect(auth.signature_mldsa).toBeDefined();
    expect(auth.ident_pub_mldsa).toBeDefined();

    const respSession = await responder.processAuth(auth);
    expect(initSession.peerActor).toMatch(/^tf:actor:process:key\//);
    expect(respSession.peerActor).toMatch(/^tf:actor:process:key\//);
  });

  test("rejects when the responder's ml-dsa signature is tampered", async () => {
    const { initiator, responder } = await makeHybridPair();
    const helloI = initiator.start();
    const helloR = await responder.processHelloI(helloI);
    // Tamper one byte of the mldsa signature; ed25519 still verifies but
    // the initiator MUST refuse the handshake.
    const sig = Buffer.from(helloR.signature_mldsa!, "base64");
    sig[0] = (sig[0] ?? 0) ^ 0x01;
    helloR.signature_mldsa = sig.toString("base64");
    expect(initiator.processHelloR(helloR)).rejects.toThrow();
  });

  test("rejects when the responder lacks ml-dsa keys but suite was hybrid", async () => {
    const initEd = await ed25519Generate();
    const respEd = await ed25519Generate();
    const initPq = mldsaGenerate("ml-dsa-65");
    const initiator = new Initiator({
      selfActor: "tf:actor:agent:example.com/i",
      identityPriv: initEd.privateKey,
      identityPub: initEd.publicKey,
      preferredSuite: SESSION_SUITE_HYBRID_ED25519_MLDSA65,
      identityMldsaPriv: initPq.privateKey,
      identityMldsaPub: initPq.publicKey,
    });
    // Responder has NO ml-dsa keys → rejects when it sees the hybrid suite chosen.
    const responder = new Responder({
      selfActor: "tf:actor:service:example.com/r",
      identityPriv: respEd.privateKey,
      identityPub: respEd.publicKey,
    });
    const helloI = initiator.start();
    expect(responder.processHelloI(helloI)).rejects.toThrow();
  });
});
