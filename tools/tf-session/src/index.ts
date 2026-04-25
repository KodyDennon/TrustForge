/**
 * WebSocket carrier for the TrustForge session protocol.
 *
 * Each WebSocket binary message carries exactly one protocol frame:
 *   - During the handshake, the canonical-JSON of HelloI / HelloR / Auth.
 *   - After the handshake, the AEAD-framed bytes from SessionState.encrypt().
 */

import {
  Initiator,
  Responder,
  type Auth,
  type HelloI,
  type HelloR,
  type SessionFrame,
  type SessionState,
  utf8encode,
  utf8decode,
} from "tf-types";

export interface PeerIdentity {
  selfActor: string;
  peerHint?: string;
  identityPriv: Uint8Array;
  identityPub: Uint8Array;
}

export interface SessionEndpoint {
  send(frame: SessionFrame): void;
  onFrame(listener: (frame: SessionFrame) => void): void;
  onClose(listener: () => void): void;
  close(reason?: string): void;
  state(): SessionState;
}

interface WireSink {
  send(bytes: Uint8Array): void;
  close(): void;
}

interface WireSource {
  onMessage(listener: (bytes: Uint8Array) => void): void;
  onClose(listener: () => void): void;
}

function jsonBytes<T>(value: T): Uint8Array {
  return utf8encode(JSON.stringify(value));
}

function parseJson<T>(bytes: Uint8Array): T {
  return JSON.parse(utf8decode(bytes)) as T;
}

/**
 * Drive the initiator side of the handshake over a wire transport, then
 * return a SessionEndpoint that pushes / pulls SessionFrames.
 */
export async function attachInitiator(
  identity: PeerIdentity,
  sink: WireSink,
  source: WireSource,
): Promise<SessionEndpoint> {
  const initiator = new Initiator(identity);
  const helloI = initiator.start();
  sink.send(jsonBytes(helloI));

  const session = await new Promise<SessionState>((resolve, reject) => {
    let stage: "awaiting-hello-r" | "established" = "awaiting-hello-r";
    source.onMessage(async (bytes) => {
      try {
        if (stage === "awaiting-hello-r") {
          const helloR = parseJson<HelloR>(bytes);
          const { auth, session } = await initiator.processHelloR(helloR);
          sink.send(jsonBytes(auth));
          stage = "established";
          resolve(session);
        }
      } catch (err) {
        reject(err);
      }
    });
    source.onClose(() => {
      if (stage === "awaiting-hello-r") reject(new Error("peer closed before handshake"));
    });
  });

  return wrapSession(session, sink, source);
}

/**
 * Drive the responder side of the handshake, returning a SessionEndpoint.
 */
export async function attachResponder(
  identity: PeerIdentity,
  sink: WireSink,
  source: WireSource,
): Promise<SessionEndpoint> {
  const responder = new Responder(identity);

  const session = await new Promise<SessionState>((resolve, reject) => {
    let stage: "awaiting-hello-i" | "awaiting-auth" | "established" = "awaiting-hello-i";
    source.onMessage(async (bytes) => {
      try {
        if (stage === "awaiting-hello-i") {
          const helloI = parseJson<HelloI>(bytes);
          const helloR = await responder.processHelloI(helloI);
          sink.send(jsonBytes(helloR));
          stage = "awaiting-auth";
          return;
        }
        if (stage === "awaiting-auth") {
          const auth = parseJson<Auth>(bytes);
          const session = await responder.processAuth(auth);
          stage = "established";
          resolve(session);
        }
      } catch (err) {
        reject(err);
      }
    });
    source.onClose(() => {
      if (stage !== "established") reject(new Error("peer closed before handshake"));
    });
  });

  return wrapSession(session, sink, source);
}

function wrapSession(
  session: SessionState,
  sink: WireSink,
  source: WireSource,
): SessionEndpoint {
  const frameListeners = new Set<(frame: SessionFrame) => void>();
  const closeListeners = new Set<() => void>();

  source.onMessage((bytes) => {
    if (session.closed) return;
    let frame: SessionFrame;
    try {
      frame = session.decrypt(bytes);
    } catch {
      session.closed = true;
      sink.close();
      for (const listener of closeListeners) listener();
      return;
    }
    for (const listener of frameListeners) listener(frame);
  });
  source.onClose(() => {
    if (!session.closed) {
      session.closed = true;
      for (const listener of closeListeners) listener();
    }
  });

  return {
    send(frame: SessionFrame) {
      if (session.closed) throw new Error("session closed");
      sink.send(session.encrypt(frame));
    },
    onFrame(listener) {
      frameListeners.add(listener);
    },
    onClose(listener) {
      closeListeners.add(listener);
    },
    close(reason?: string) {
      if (!session.closed) {
        try {
          sink.send(session.encrypt({ kind: "close", reason }));
        } catch {
          // best-effort
        }
        session.closed = true;
        sink.close();
        for (const listener of closeListeners) listener();
      }
    },
    state: () => session,
  };
}

// ---------- WebSocket adapters ----------

export interface WebSocketLike {
  send(data: ArrayBuffer | Uint8Array): void;
  close(): void;
  addEventListener(
    type: "message",
    listener: (e: { data: ArrayBuffer | Uint8Array | string }) => void,
  ): void;
  addEventListener(type: "close", listener: () => void): void;
  addEventListener(type: "open", listener: () => void): void;
}

export function wireFromWebSocket(ws: WebSocketLike): { sink: WireSink; source: WireSource } {
  const messageListeners = new Set<(b: Uint8Array) => void>();
  const closeListeners = new Set<() => void>();

  ws.addEventListener("message", (e) => {
    const data = e.data;
    let bytes: Uint8Array;
    if (data instanceof ArrayBuffer) bytes = new Uint8Array(data);
    else if (data instanceof Uint8Array) bytes = data;
    else if (typeof data === "string") bytes = new TextEncoder().encode(data);
    else return;
    for (const l of messageListeners) l(bytes);
  });
  ws.addEventListener("close", () => {
    for (const l of closeListeners) l();
  });

  return {
    sink: {
      send(bytes: Uint8Array) {
        ws.send(bytes);
      },
      close() {
        ws.close();
      },
    },
    source: {
      onMessage(listener: (b: Uint8Array) => void) {
        messageListeners.add(listener);
      },
      onClose(listener: () => void) {
        closeListeners.add(listener);
      },
    },
  };
}
