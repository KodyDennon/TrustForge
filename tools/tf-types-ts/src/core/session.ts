/**
 * Session protocol — Phase 3 prototype.
 *
 * 3-message handshake:
 *   I → R   HelloI  { version, suite, session_id, peer_hint, eph_pub }
 *   R → I   HelloR  { eph_pub, ident_pub, signature }
 *   I → R   Auth    { ident_pub, signature }
 *
 * After the handshake, frames are length-prefixed AEAD ciphertexts:
 *   length:u32 BE | seq:u64 BE | ciphertext+tag
 * AAD = length || seq, nonce = 4 zero bytes || seq big-endian.
 */

import { canonicalize } from "./canonical.js";
import {
  AeadError,
  b64decode,
  b64encode,
  CryptoError,
  ed25519PublicKey,
  ed25519Sign,
  ed25519Verify,
  hkdfSha256,
  toHex,
  utf8encode,
  x25519DiffieHellman,
  x25519Generate,
  chacha20poly1305Decrypt,
  chacha20poly1305Encrypt,
} from "./crypto.js";
import { sha256 } from "@noble/hashes/sha2";

export const SESSION_VERSION = 0;
export const SESSION_SUITE = "x25519-hkdf-sha256-chacha20poly1305-ed25519";

/** Suite identifiers a peer can offer. The default classical suite is
 *  always supported; the hybrid variant adds an ML-DSA signature alongside
 *  ed25519 so the handshake survives a future quantum break of either. */
export const SESSION_SUITE_HYBRID_ED25519_MLDSA65 =
  "x25519-hkdf-sha256-chacha20poly1305-ed25519+ml-dsa-65";

/** All suites the runtime knows how to honour. Order is preference. */
export const KNOWN_SESSION_SUITES = [
  SESSION_SUITE,
  SESSION_SUITE_HYBRID_ED25519_MLDSA65,
] as const;

export type SessionSuite = (typeof KNOWN_SESSION_SUITES)[number];

export class SessionError extends Error {}

export interface HelloI {
  kind: "hello-i";
  version: number;
  /** Selected suite (must be present in `supported_suites`). */
  suite: string;
  /** Suite preference list. Earlier entries are preferred. The default
   *  classical suite is always implicit so existing peers continue to
   *  interoperate. */
  supported_suites?: string[];
  session_id: string; // base64, 16 bytes
  peer_hint: string;
  eph_pub: string; // base64, 32 bytes
}

export interface HelloR {
  kind: "hello-r";
  eph_pub: string; // base64
  ident_pub: string; // base64
  signature: string; // base64
}

export interface Auth {
  kind: "auth";
  ident_pub: string; // base64
  signature: string; // base64
}

export type SessionFrame =
  | { kind: "data"; payload: unknown }
  | { kind: "rekey-req"; eph_pub: string }
  | { kind: "rekey-ack"; eph_pub: string }
  | { kind: "close"; reason?: string }
  | { kind: "ping"; nonce: string }
  | { kind: "pong"; nonce: string };

export interface SessionConfig {
  selfActor: string;
  peerHint?: string;
  identityPriv: Uint8Array;
  identityPub: Uint8Array;
  /** Preferred session suite. Default: SESSION_SUITE. The handshake
   *  advertises this and `supportedSuites` to the peer. */
  preferredSuite?: SessionSuite;
  /** Suite list the initiator is willing to fall back to. Defaults to
   *  `KNOWN_SESSION_SUITES`. */
  supportedSuites?: SessionSuite[];
  // Test-only: deterministic ephemeral / session_id.
  ephSeed?: Uint8Array;
  sessionIdSeed?: Uint8Array;
}

interface InitiatorPending {
  helloI: HelloI;
  ephPriv: Uint8Array;
}

export class Initiator {
  private state: "fresh" | "awaiting-hello-r" | "awaiting-auth-send" | "established" = "fresh";
  private helloI?: HelloI;
  private helloR?: HelloR;
  private ephPriv?: Uint8Array;
  private session?: SessionState;

  constructor(private cfg: SessionConfig) {}

  start(): HelloI {
    if (this.state !== "fresh") throw new SessionError("initiator already started");
    const eph = x25519Generate(this.cfg.ephSeed);
    const sessionIdBytes = this.cfg.sessionIdSeed ?? crypto.getRandomValues(new Uint8Array(16));
    if (sessionIdBytes.length !== 16) throw new SessionError("session_id must be 16 bytes");
    this.ephPriv = eph.privateKey;
    const preferred = (this.cfg.preferredSuite ?? SESSION_SUITE) as SessionSuite;
    const supported = this.cfg.supportedSuites ?? Array.from(KNOWN_SESSION_SUITES);
    if (!supported.includes(preferred)) supported.unshift(preferred);
    this.helloI = {
      kind: "hello-i",
      version: SESSION_VERSION,
      suite: preferred,
      supported_suites: supported,
      session_id: b64encode(sessionIdBytes),
      peer_hint: this.cfg.peerHint ?? "",
      eph_pub: b64encode(eph.publicKey),
    };
    this.state = "awaiting-hello-r";
    return this.helloI;
  }

  async processHelloR(msg: HelloR): Promise<{ auth: Auth; session: SessionState }> {
    if (this.state !== "awaiting-hello-r") throw new SessionError("not awaiting hello-r");
    if (!this.helloI || !this.ephPriv) throw new SessionError("missing initiator state");

    // Verify responder's identity signature over (HelloI || HelloR_without_sig).
    const helloRUnsigned: HelloR = { ...msg, signature: "" };
    const transcript = utf8encode(canonicalize(this.helloI) + canonicalize(helloRUnsigned));
    const transcriptHash = sha256(transcript);
    const identPub = b64decode(msg.ident_pub);
    const sig = b64decode(msg.signature);
    const ok = await ed25519Verify(identPub, transcriptHash, sig);
    if (!ok) throw new SessionError("responder identity signature invalid");

    // Derive shared secret + session keys.
    const peerEph = b64decode(msg.eph_pub);
    const shared = x25519DiffieHellman(this.ephPriv, peerEph);
    const sessionIdBytes = b64decode(this.helloI.session_id);

    // Build Auth (initiator's identity signature over the post-HelloR transcript +
    // Auth_without_signature).
    const authUnsigned: Auth = {
      kind: "auth",
      ident_pub: b64encode(this.cfg.identityPub),
      signature: "",
    };
    const fullTranscript = utf8encode(
      canonicalize(this.helloI) + canonicalize(msg) + canonicalize(authUnsigned),
    );
    const fullTranscriptHash = sha256(fullTranscript);
    const authSig = await ed25519Sign(fullTranscriptHash, this.cfg.identityPriv);
    const auth: Auth = { ...authUnsigned, signature: b64encode(authSig) };

    const session = SessionState.derive({
      role: "initiator",
      sharedSecret: shared,
      sessionId: sessionIdBytes,
      transcriptHash: fullTranscriptHash,
      selfActor: this.cfg.selfActor,
      peerActor: this.cfg.peerHint ?? "(unknown)",
    });
    this.session = session;
    this.helloR = msg;
    this.state = "established";
    return { auth, session };
  }

  established(): SessionState {
    if (!this.session) throw new SessionError("session not established");
    return this.session;
  }
}

export class Responder {
  private state: "fresh" | "awaiting-auth" | "established" = "fresh";
  private helloI?: HelloI;
  private helloR?: HelloR;
  private ephPriv?: Uint8Array;
  private sharedSecret?: Uint8Array;
  private session?: SessionState;

  constructor(private cfg: SessionConfig) {}

  async processHelloI(msg: HelloI): Promise<HelloR> {
    if (this.state !== "fresh") throw new SessionError("responder already engaged");
    if (msg.version !== SESSION_VERSION) throw new SessionError(`unsupported version ${msg.version}`);
    if (!(KNOWN_SESSION_SUITES as readonly string[]).includes(msg.suite)) {
      throw new SessionError(`unsupported suite ${msg.suite}`);
    }
    const sessionIdBytes = b64decode(msg.session_id);
    if (sessionIdBytes.length !== 16) throw new SessionError("session_id must be 16 bytes");

    const eph = x25519Generate(this.cfg.ephSeed);
    this.ephPriv = eph.privateKey;
    this.sharedSecret = x25519DiffieHellman(eph.privateKey, b64decode(msg.eph_pub));

    const helloRUnsigned: HelloR = {
      kind: "hello-r",
      eph_pub: b64encode(eph.publicKey),
      ident_pub: b64encode(this.cfg.identityPub),
      signature: "",
    };
    const transcript = utf8encode(canonicalize(msg) + canonicalize(helloRUnsigned));
    const transcriptHash = sha256(transcript);
    const sig = await ed25519Sign(transcriptHash, this.cfg.identityPriv);
    const helloR: HelloR = { ...helloRUnsigned, signature: b64encode(sig) };

    this.helloI = msg;
    this.helloR = helloR;
    this.state = "awaiting-auth";
    return helloR;
  }

  async processAuth(msg: Auth): Promise<SessionState> {
    if (this.state !== "awaiting-auth") throw new SessionError("not awaiting auth");
    if (!this.helloI || !this.helloR || !this.sharedSecret) throw new SessionError("missing responder state");

    const authUnsigned: Auth = { ...msg, signature: "" };
    const fullTranscript = utf8encode(
      canonicalize(this.helloI) + canonicalize(this.helloR) + canonicalize(authUnsigned),
    );
    const fullTranscriptHash = sha256(fullTranscript);
    const ok = await ed25519Verify(b64decode(msg.ident_pub), fullTranscriptHash, b64decode(msg.signature));
    if (!ok) throw new SessionError("initiator identity signature invalid");

    const session = SessionState.derive({
      role: "responder",
      sharedSecret: this.sharedSecret,
      sessionId: b64decode(this.helloI.session_id),
      transcriptHash: fullTranscriptHash,
      selfActor: this.cfg.selfActor,
      peerActor: this.cfg.peerHint ?? "(unknown)",
    });
    this.session = session;
    this.state = "established";
    return session;
  }
}

interface DeriveArgs {
  role: "initiator" | "responder";
  sharedSecret: Uint8Array;
  sessionId: Uint8Array;
  transcriptHash: Uint8Array;
  selfActor: string;
  peerActor: string;
}

export class SessionState {
  selfActor: string;
  peerActor: string;
  sessionId: Uint8Array;
  generation: number;
  sendKey: Uint8Array;
  recvKey: Uint8Array;
  sendSeq: bigint;
  recvSeq: bigint;
  closed: boolean;

  // Pending rekey (initiator side: new ephemeral private waiting for ack).
  private pendingRekeyPriv?: Uint8Array;
  // Receiver-side: most recent prev keys to derive next-gen keys.
  private prevKeysHash?: Uint8Array;

  private constructor(init: {
    selfActor: string;
    peerActor: string;
    sessionId: Uint8Array;
    sendKey: Uint8Array;
    recvKey: Uint8Array;
    generation: number;
  }) {
    this.selfActor = init.selfActor;
    this.peerActor = init.peerActor;
    this.sessionId = init.sessionId;
    this.sendKey = init.sendKey;
    this.recvKey = init.recvKey;
    this.generation = init.generation;
    this.sendSeq = 0n;
    this.recvSeq = 0n;
    this.closed = false;
  }

  static derive(args: DeriveArgs): SessionState {
    const info = concatBytes(utf8encode("tf-session/v0/keys"), args.transcriptHash);
    const ikm = hkdfSha256(args.sharedSecret, args.sessionId, info, 64);
    const i_to_r = ikm.slice(0, 32);
    const r_to_i = ikm.slice(32, 64);
    const isInitiator = args.role === "initiator";
    return new SessionState({
      selfActor: args.selfActor,
      peerActor: args.peerActor,
      sessionId: args.sessionId,
      sendKey: isInitiator ? i_to_r : r_to_i,
      recvKey: isInitiator ? r_to_i : i_to_r,
      generation: 0,
    });
  }

  encrypt(frame: SessionFrame): Uint8Array {
    if (this.closed) throw new SessionError("session is closed");
    const plaintext = utf8encode(canonicalize(frame));
    const seq = this.sendSeq;
    const nonce = nonceFor(seq);
    const length = 8 + plaintext.length + 16; // seq + ct + tag
    const aad = makeAad(length, seq);
    const ct = chacha20poly1305Encrypt(this.sendKey, nonce, aad, plaintext);
    const out = new Uint8Array(4 + length);
    writeU32BE(out, 0, length);
    writeU64BE(out, 4, seq);
    out.set(ct, 12);
    this.sendSeq = seq + 1n;
    return out;
  }

  decrypt(bytes: Uint8Array): SessionFrame {
    if (this.closed) throw new SessionError("session is closed");
    if (bytes.length < 12 + 16) throw new SessionError("frame too short");
    const length = readU32BE(bytes, 0);
    if (4 + length !== bytes.length) throw new SessionError("length mismatch");
    const seq = readU64BE(bytes, 4);
    if (seq !== this.recvSeq) throw new SessionError(`out-of-order frame: got ${seq}, expected ${this.recvSeq}`);
    const aad = makeAad(length, seq);
    const nonce = nonceFor(seq);
    const ct = bytes.slice(12);
    let pt: Uint8Array;
    try {
      pt = chacha20poly1305Decrypt(this.recvKey, nonce, aad, ct);
    } catch (e) {
      if (e instanceof AeadError) throw new SessionError(`aead failure at seq ${seq}`);
      throw e;
    }
    const text = new TextDecoder().decode(pt);
    const frame = JSON.parse(text) as SessionFrame;
    this.recvSeq = seq + 1n;
    return frame;
  }

  /** Build a rekey-req. Stores a fresh ephemeral private key for derivation
   *  once the peer responds. The session must NOT send `data` frames until
   *  processRekeyAck() returns. */
  requestRekey(seed?: Uint8Array): Uint8Array {
    const eph = x25519Generate(seed);
    this.pendingRekeyPriv = eph.privateKey;
    return this.encrypt({ kind: "rekey-req", eph_pub: b64encode(eph.publicKey) });
  }

  /** Respond to an incoming rekey-req. Generates a new ephemeral, derives the
   *  next-generation keys, and emits a rekey-ack frame. After the ack, the
   *  side that sent rekey-ack rolls its keys and resets seqs immediately;
   *  the side that sent rekey-req rolls only after receiving the ack. */
  processRekeyReq(frame: { kind: "rekey-req"; eph_pub: string }, seed?: Uint8Array): Uint8Array {
    const eph = x25519Generate(seed);
    const peerEph = b64decode(frame.eph_pub);
    const shared = x25519DiffieHellman(eph.privateKey, peerEph);
    const ack = this.encrypt({ kind: "rekey-ack", eph_pub: b64encode(eph.publicKey) });
    this.rotateKeys(shared);
    return ack;
  }

  processRekeyAck(frame: { kind: "rekey-ack"; eph_pub: string }): void {
    if (!this.pendingRekeyPriv) throw new SessionError("no pending rekey");
    const peerEph = b64decode(frame.eph_pub);
    const shared = x25519DiffieHellman(this.pendingRekeyPriv, peerEph);
    this.pendingRekeyPriv = undefined;
    this.rotateKeys(shared);
  }

  private rotateKeys(shared: Uint8Array): void {
    // The two sides hold (send, recv) in opposite order. Concatenate them in
    // a canonical (sorted by hex) order so prev_hash is symmetric.
    const sendHex = toHex(this.sendKey);
    const recvHex = toHex(this.recvKey);
    const sendIsLower = sendHex < recvHex;
    const lo = sendIsLower ? this.sendKey : this.recvKey;
    const hi = sendIsLower ? this.recvKey : this.sendKey;
    const prevHash = sha256(concatBytes(lo, hi));
    const info = concatBytes(
      utf8encode(`tf-session/v0/keys/g${this.generation + 1}`),
      prevHash,
    );
    const ikm = hkdfSha256(shared, this.sessionId, info, 64);
    const k1 = ikm.slice(0, 32);
    const k2 = ikm.slice(32, 64);
    // Direction picker: whichever half of OLD keys was "lower-hex" was the
    // i→r direction; preserve that role across the rotation.
    this.sendKey = sendIsLower ? k1 : k2;
    this.recvKey = sendIsLower ? k2 : k1;
    this.sendSeq = 0n;
    this.recvSeq = 0n;
    this.generation += 1;
    this.prevKeysHash = prevHash;
  }
}

function nonceFor(seq: bigint): Uint8Array {
  const out = new Uint8Array(12);
  writeU64BE(out, 4, seq);
  return out;
}

function makeAad(length: number, seq: bigint): Uint8Array {
  const out = new Uint8Array(12);
  writeU32BE(out, 0, length);
  writeU64BE(out, 4, seq);
  return out;
}

function writeU32BE(buf: Uint8Array, off: number, n: number): void {
  buf[off] = (n >>> 24) & 0xff;
  buf[off + 1] = (n >>> 16) & 0xff;
  buf[off + 2] = (n >>> 8) & 0xff;
  buf[off + 3] = n & 0xff;
}

function writeU64BE(buf: Uint8Array, off: number, n: bigint): void {
  for (let i = 7; i >= 0; i--) {
    buf[off + i] = Number(n & 0xffn);
    n >>= 8n;
  }
}

function readU32BE(buf: Uint8Array, off: number): number {
  return ((buf[off]! << 24) | (buf[off + 1]! << 16) | (buf[off + 2]! << 8) | buf[off + 3]!) >>> 0;
}

function readU64BE(buf: Uint8Array, off: number): bigint {
  let n = 0n;
  for (let i = 0; i < 8; i++) {
    n = (n << 8n) | BigInt(buf[off + i]!);
  }
  return n;
}

function concatBytes(...arrs: Uint8Array[]): Uint8Array {
  let total = 0;
  for (const a of arrs) total += a.length;
  const out = new Uint8Array(total);
  let off = 0;
  for (const a of arrs) {
    out.set(a, off);
    off += a.length;
  }
  return out;
}
