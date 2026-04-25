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
  mldsaSign,
  mldsaVerify,
  toHex,
  utf8encode,
  x25519DiffieHellman,
  x25519Generate,
  chacha20poly1305Decrypt,
  chacha20poly1305Encrypt,
} from "./crypto.js";
import { derivePeerActor } from "./actor-id.js";
import { sha256 } from "@noble/hashes/sha2";

function isHybridSuite(suite: string): boolean {
  return suite.endsWith("+ml-dsa-65");
}

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
  /** Initiator's preferred suite (must be in `supported_suites`). */
  suite: string;
  /** Suite preference list. Earlier entries are preferred. The classical
   *  suite is always implicit so existing peers continue to interoperate. */
  supported_suites?: string[];
  session_id: string; // base64, 16 bytes
  /** Initiator's belief about the responder's actor URI; used for
   *  wrong-peer detection. Not a self-claim. */
  peer_hint: string;
  /** Initiator's self-claimed actor URI (advisory; not key-bound). */
  self_hint?: string;
  eph_pub: string; // base64, 32 bytes
}

export interface HelloR {
  kind: "hello-r";
  eph_pub: string; // base64
  ident_pub: string; // base64
  /** Suite the responder selected from the initiator's supported list. */
  selected_suite?: string;
  /** Responder's self-claimed actor URI (advisory). */
  self_hint?: string;
  /** Hybrid-PQ companion signature; required when negotiated suite is the
   *  hybrid `*+ml-dsa-65` variant. Both signatures cover the same
   *  transcript_hash; both must verify. */
  signature_mldsa?: string;
  ident_pub_mldsa?: string;
  signature: string; // base64
}

export interface Auth {
  kind: "auth";
  ident_pub: string; // base64
  signature_mldsa?: string;
  ident_pub_mldsa?: string;
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
  /** Self-claimed actor URI advertised in HelloI / HelloR `self_hint`. */
  selfHint?: string;
  identityPriv: Uint8Array;
  identityPub: Uint8Array;
  /** Preferred session suite. Default: SESSION_SUITE. The handshake
   *  advertises this and `supportedSuites` to the peer. */
  preferredSuite?: SessionSuite;
  /** Suite list the initiator is willing to fall back to. Defaults to
   *  `KNOWN_SESSION_SUITES`. */
  supportedSuites?: SessionSuite[];
  /** Optional hybrid-PQ ml-dsa-65 secret key. When present and the
   *  negotiated suite includes the hybrid variant, the peer signs the
   *  handshake transcript with both ed25519 and ml-dsa-65. */
  identityMldsaPriv?: Uint8Array;
  identityMldsaPub?: Uint8Array;
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
    let supported = (this.cfg.supportedSuites ?? Array.from(KNOWN_SESSION_SUITES)) as SessionSuite[];
    // Move preferred to the front so the responder's first-match negotiation
    // honours the initiator's preference.
    supported = supported.filter((s) => s !== preferred);
    supported.unshift(preferred);
    this.helloI = {
      kind: "hello-i",
      version: SESSION_VERSION,
      suite: preferred,
      supported_suites: supported,
      self_hint: this.cfg.selfHint,
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
    // For the hybrid suite both ed25519 AND ml-dsa-65 must verify (parallel
    // composition: a break of either algorithm leaves the other intact).
    const helloRUnsigned: HelloR = {
      ...msg,
      signature: "",
      signature_mldsa: undefined,
    };
    const transcript = utf8encode(canonicalize(this.helloI) + canonicalize(helloRUnsigned));
    const transcriptHash = sha256(transcript);
    const identPub = b64decode(msg.ident_pub);
    const sig = b64decode(msg.signature);
    const ok = await ed25519Verify(identPub, transcriptHash, sig);
    if (!ok) throw new SessionError("responder identity signature invalid");

    const negotiatedSuite = msg.selected_suite ?? this.helloI.suite;
    if (isHybridSuite(negotiatedSuite)) {
      if (!msg.signature_mldsa || !msg.ident_pub_mldsa) {
        throw new SessionError(
          `negotiated hybrid suite ${negotiatedSuite} but HelloR missing signature_mldsa / ident_pub_mldsa`,
        );
      }
      const pqOk = mldsaVerify(
        "ml-dsa-65",
        b64decode(msg.ident_pub_mldsa),
        transcriptHash,
        b64decode(msg.signature_mldsa),
      );
      if (!pqOk) throw new SessionError("responder ml-dsa-65 signature invalid");
    }

    // Derive shared secret + session keys.
    const peerEph = b64decode(msg.eph_pub);
    const shared = x25519DiffieHellman(this.ephPriv, peerEph);
    const sessionIdBytes = b64decode(this.helloI.session_id);

    // Build Auth (initiator's identity signature over the post-HelloR transcript +
    // Auth_without_signature). Hybrid suite: sign with both keys.
    const authUnsigned: Auth = {
      kind: "auth",
      ident_pub: b64encode(this.cfg.identityPub),
      ident_pub_mldsa: isHybridSuite(negotiatedSuite) && this.cfg.identityMldsaPub
        ? b64encode(this.cfg.identityMldsaPub)
        : undefined,
      signature: "",
    };
    const fullTranscript = utf8encode(
      canonicalize(this.helloI) + canonicalize(msg) + canonicalize(authUnsigned),
    );
    const fullTranscriptHash = sha256(fullTranscript);
    const authSig = await ed25519Sign(fullTranscriptHash, this.cfg.identityPriv);
    let authPqSig: Uint8Array | undefined;
    if (isHybridSuite(negotiatedSuite)) {
      if (!this.cfg.identityMldsaPriv || !this.cfg.identityMldsaPub) {
        throw new SessionError(
          `negotiated hybrid suite ${negotiatedSuite} but initiator is missing identity_mldsa_{priv,pub}`,
        );
      }
      authPqSig = mldsaSign("ml-dsa-65", this.cfg.identityMldsaPriv, fullTranscriptHash);
    }
    const auth: Auth = {
      ...authUnsigned,
      signature: b64encode(authSig),
      signature_mldsa: authPqSig ? b64encode(authPqSig) : undefined,
    };

    const peerActor = derivePeerActor(identPub);
    // peer_hint on HelloI was the initiator's belief about the responder;
    // the responder advertises its own actor URI in HelloR.self_hint.
    const peerClaim = msg.self_hint && msg.self_hint.length > 0 ? msg.self_hint : undefined;
    const session = SessionState.derive({
      role: "initiator",
      sharedSecret: shared,
      sessionId: sessionIdBytes,
      transcriptHash: fullTranscriptHash,
      selfActor: this.cfg.selfActor,
      peerActor,
      peerActorClaim: peerClaim,
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
    const ourSupported = (this.cfg.supportedSuites ?? KNOWN_SESSION_SUITES) as readonly string[];
    let chosen: string;
    if (msg.supported_suites && msg.supported_suites.length > 0) {
      const match = msg.supported_suites.find((s) => ourSupported.includes(s));
      if (!match) {
        throw new SessionError(
          `no mutually-supported suite (peer offered ${msg.supported_suites.join(",")}, we support ${ourSupported.join(",")})`,
        );
      }
      chosen = match;
    } else {
      if (!ourSupported.includes(msg.suite)) throw new SessionError(`unsupported suite ${msg.suite}`);
      chosen = msg.suite;
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
      selected_suite: chosen,
      self_hint: this.cfg.selfHint,
      ident_pub_mldsa: isHybridSuite(chosen) && this.cfg.identityMldsaPub
        ? b64encode(this.cfg.identityMldsaPub)
        : undefined,
      signature: "",
    };
    const transcript = utf8encode(canonicalize(msg) + canonicalize(helloRUnsigned));
    const transcriptHash = sha256(transcript);
    const sig = await ed25519Sign(transcriptHash, this.cfg.identityPriv);
    let pqSig: Uint8Array | undefined;
    if (isHybridSuite(chosen)) {
      if (!this.cfg.identityMldsaPriv || !this.cfg.identityMldsaPub) {
        throw new SessionError(
          `negotiated hybrid suite ${chosen} but responder is missing identity_mldsa_{priv,pub}`,
        );
      }
      pqSig = mldsaSign("ml-dsa-65", this.cfg.identityMldsaPriv, transcriptHash);
    }
    const helloR: HelloR = {
      ...helloRUnsigned,
      signature: b64encode(sig),
      signature_mldsa: pqSig ? b64encode(pqSig) : undefined,
    };

    this.helloI = msg;
    this.helloR = helloR;
    this.state = "awaiting-auth";
    return helloR;
  }

  async processAuth(msg: Auth): Promise<SessionState> {
    if (this.state !== "awaiting-auth") throw new SessionError("not awaiting auth");
    if (!this.helloI || !this.helloR || !this.sharedSecret) throw new SessionError("missing responder state");

    const authUnsigned: Auth = { ...msg, signature: "", signature_mldsa: undefined };
    const fullTranscript = utf8encode(
      canonicalize(this.helloI) + canonicalize(this.helloR) + canonicalize(authUnsigned),
    );
    const fullTranscriptHash = sha256(fullTranscript);
    const ok = await ed25519Verify(b64decode(msg.ident_pub), fullTranscriptHash, b64decode(msg.signature));
    if (!ok) throw new SessionError("initiator identity signature invalid");

    const negotiatedSuite = this.helloR.selected_suite ?? this.helloI.suite;
    if (isHybridSuite(negotiatedSuite)) {
      if (!msg.signature_mldsa || !msg.ident_pub_mldsa) {
        throw new SessionError(
          `negotiated hybrid suite ${negotiatedSuite} but Auth missing signature_mldsa / ident_pub_mldsa`,
        );
      }
      const pqOk = mldsaVerify(
        "ml-dsa-65",
        b64decode(msg.ident_pub_mldsa),
        fullTranscriptHash,
        b64decode(msg.signature_mldsa),
      );
      if (!pqOk) throw new SessionError("initiator ml-dsa-65 signature invalid");
    }

    const peerIdentPub = b64decode(msg.ident_pub);
    const peerActor = derivePeerActor(peerIdentPub);
    // peer_hint is the initiator's belief about the responder (wrong-peer
    // detection). The initiator's own self-claim travels in HelloI.self_hint.
    const peerClaim =
      this.helloI.self_hint && this.helloI.self_hint.length > 0
        ? this.helloI.self_hint
        : undefined;
    const session = SessionState.derive({
      role: "responder",
      sharedSecret: this.sharedSecret,
      sessionId: b64decode(this.helloI.session_id),
      transcriptHash: fullTranscriptHash,
      selfActor: this.cfg.selfActor,
      peerActor,
      peerActorClaim: peerClaim,
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
  peerActorClaim?: string;
}

export class SessionState {
  selfActor: string;
  /** Key-derived canonical peer actor URI (`tf:actor:process:key/<thumbprint>`).
   *  This is the cryptographic identity of the peer — bound to the public key
   *  used in the handshake. AgentGuard authority is anchored here. */
  peerActor: string;
  /** Self-claimed actor URI carried in `peer_hint` of HelloI. Advisory only:
   *  not verified against any PKI. Guards may match against this for
   *  human-readable allow/deny lists. */
  peerActorClaim?: string;
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
    peerActorClaim?: string;
    sessionId: Uint8Array;
    sendKey: Uint8Array;
    recvKey: Uint8Array;
    generation: number;
  }) {
    this.selfActor = init.selfActor;
    this.peerActor = init.peerActor;
    this.peerActorClaim = init.peerActorClaim;
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
      peerActorClaim: args.peerActorClaim,
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
