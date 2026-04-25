import { describe, expect, test } from "bun:test";
import { ed25519Generate } from "../src/core/crypto";
import {
  Initiator,
  Responder,
  SessionError,
  type SessionState,
} from "../src/core/session";

async function makePair(): Promise<{
  initiator: Initiator;
  responder: Responder;
  iId: { privateKey: Uint8Array; publicKey: Uint8Array };
  rId: { privateKey: Uint8Array; publicKey: Uint8Array };
}> {
  const iId = await ed25519Generate();
  const rId = await ed25519Generate();
  const initiator = new Initiator({
    selfActor: "tf:actor:agent:example.com/i",
    peerHint: "tf:actor:agent:example.com/r",
    identityPriv: iId.privateKey,
    identityPub: iId.publicKey,
  });
  const responder = new Responder({
    selfActor: "tf:actor:agent:example.com/r",
    identityPriv: rId.privateKey,
    identityPub: rId.publicKey,
  });
  return { initiator, responder, iId, rId };
}

async function shakeHands(): Promise<{ iSession: SessionState; rSession: SessionState }> {
  const { initiator, responder } = await makePair();
  const helloI = initiator.start();
  const helloR = await responder.processHelloI(helloI);
  const { auth, session: iSession } = await initiator.processHelloR(helloR);
  const rSession = await responder.processAuth(auth);
  return { iSession, rSession };
}

describe("handshake", () => {
  test("completes and yields matching sessions", async () => {
    const { iSession, rSession } = await shakeHands();
    expect(iSession.generation).toBe(0);
    expect(rSession.generation).toBe(0);
    // The initiator's send_key is the responder's recv_key and vice versa.
    expect(Array.from(iSession.sendKey)).toEqual(Array.from(rSession.recvKey));
    expect(Array.from(iSession.recvKey)).toEqual(Array.from(rSession.sendKey));
    expect(Array.from(iSession.sessionId)).toEqual(Array.from(rSession.sessionId));
    expect(iSession.sessionId.length).toBe(16);
  });

  test("rejects bad version", async () => {
    const { initiator, responder } = await makePair();
    const helloI = initiator.start();
    helloI.version = 99;
    expect(responder.processHelloI(helloI)).rejects.toThrow(SessionError);
  });

  test("rejects bad suite", async () => {
    const { initiator, responder } = await makePair();
    const helloI = initiator.start();
    // Force BOTH the preferred suite and the supported_suites list to a
    // value the responder can't speak; suite negotiation must reject.
    helloI.suite = "snake-oil-suite";
    helloI.supported_suites = ["snake-oil-suite"];
    expect(responder.processHelloI(helloI)).rejects.toThrow(SessionError);
  });

  test("rejects forged responder signature", async () => {
    const { initiator, responder } = await makePair();
    const helloI = initiator.start();
    const helloR = await responder.processHelloI(helloI);
    helloR.signature = "AAAA";
    expect(initiator.processHelloR(helloR)).rejects.toThrow(SessionError);
  });

  test("rejects forged initiator signature", async () => {
    const { initiator, responder } = await makePair();
    const helloI = initiator.start();
    const helloR = await responder.processHelloI(helloI);
    const { auth } = await initiator.processHelloR(helloR);
    auth.signature = "AAAA";
    expect(responder.processAuth(auth)).rejects.toThrow(SessionError);
  });
});

describe("frames", () => {
  test("encrypted data frame round-trips", async () => {
    const { iSession, rSession } = await shakeHands();
    const framed = iSession.encrypt({ kind: "data", payload: { hello: "world" } });
    const decoded = rSession.decrypt(framed);
    expect(decoded).toEqual({ kind: "data", payload: { hello: "world" } });
  });

  test("monotonic sequence numbers across frames", async () => {
    const { iSession, rSession } = await shakeHands();
    for (let i = 0; i < 5; i++) {
      const framed = iSession.encrypt({ kind: "data", payload: i });
      const decoded = rSession.decrypt(framed);
      expect(decoded).toEqual({ kind: "data", payload: i });
    }
    expect(iSession.sendSeq).toBe(5n);
    expect(rSession.recvSeq).toBe(5n);
  });

  test("out-of-order delivery is rejected", async () => {
    const { iSession, rSession } = await shakeHands();
    const f1 = iSession.encrypt({ kind: "data", payload: 1 });
    const f2 = iSession.encrypt({ kind: "data", payload: 2 });
    rSession.decrypt(f2 ? f1 : f1);
    expect(() => rSession.decrypt(f1)).toThrow(SessionError);
    void f2;
  });

  test("tampered frame fails authentication", async () => {
    const { iSession, rSession } = await shakeHands();
    const framed = iSession.encrypt({ kind: "data", payload: "abc" });
    framed[framed.length - 1]! ^= 0xff;
    expect(() => rSession.decrypt(framed)).toThrow(SessionError);
  });

  test("bidirectional traffic uses opposite keys", async () => {
    const { iSession, rSession } = await shakeHands();
    const fromI = iSession.encrypt({ kind: "data", payload: "i->r" });
    expect(rSession.decrypt(fromI)).toEqual({ kind: "data", payload: "i->r" });
    const fromR = rSession.encrypt({ kind: "data", payload: "r->i" });
    expect(iSession.decrypt(fromR)).toEqual({ kind: "data", payload: "r->i" });
  });
});

describe("rekey", () => {
  test("rekey rotates keys and resets seqs", async () => {
    const { iSession, rSession } = await shakeHands();
    const keyBefore = Array.from(iSession.sendKey);

    // Send a few frames first.
    for (let i = 0; i < 3; i++) {
      rSession.decrypt(iSession.encrypt({ kind: "data", payload: i }));
    }

    // Initiator requests rekey.
    const rekeyReqFrame = iSession.requestRekey();
    const decodedReq = rSession.decrypt(rekeyReqFrame);
    if (decodedReq.kind !== "rekey-req") throw new Error("expected rekey-req");
    const ackFrame = rSession.processRekeyReq(decodedReq);
    const decodedAck = iSession.decrypt(ackFrame);
    if (decodedAck.kind !== "rekey-ack") throw new Error("expected rekey-ack");
    iSession.processRekeyAck(decodedAck);

    expect(iSession.generation).toBe(1);
    expect(rSession.generation).toBe(1);
    expect(iSession.sendSeq).toBe(0n);
    expect(rSession.recvSeq).toBe(0n);
    expect(Array.from(iSession.sendKey)).not.toEqual(keyBefore);
    // Direction parity preserved.
    expect(Array.from(iSession.sendKey)).toEqual(Array.from(rSession.recvKey));
    expect(Array.from(iSession.recvKey)).toEqual(Array.from(rSession.sendKey));

    // Post-rekey traffic still works.
    const f = iSession.encrypt({ kind: "data", payload: "after-rekey" });
    expect(rSession.decrypt(f)).toEqual({ kind: "data", payload: "after-rekey" });
  });
});
