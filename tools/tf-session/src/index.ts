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
  type RpcTransport,
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

/**
 * Adapt a SessionEndpoint into an RpcTransport so tf-types' RpcClient /
 * RpcServer can run on top of a live session.
 */
export function rpcTransportFromEndpoint(endpoint: SessionEndpoint): RpcTransport {
  return {
    send: (frame) => endpoint.send(frame),
    onFrame: (listener) => endpoint.onFrame(listener),
  };
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

  const frameListeners = new Set<(frame: SessionFrame) => void>();
  const closeListeners = new Set<() => void>();
  let session: SessionState | undefined;
  let stage: "awaiting-hello-r" | "established" = "awaiting-hello-r";
  const queue: Uint8Array[] = [];
  let processing = false;
  let handshakeReject: ((err: Error) => void) | null = null;

  const established = new Promise<SessionState>((resolve, reject) => {
    handshakeReject = reject;
    source.onMessage(async (bytes) => {
      queue.push(bytes);
      if (processing) return;
      processing = true;
      try {
        while (queue.length > 0) {
          const b = queue.shift()!;
          if (stage === "awaiting-hello-r") {
            try {
              const helloR = parseJson<HelloR>(b);
              const { auth, session: s } = await initiator.processHelloR(helloR);
              sink.send(jsonBytes(auth));
              stage = "established";
              session = s;
              resolve(s);
              await new Promise<void>((r) => setTimeout(r, 0));
            } catch (err) {
              reject(err as Error);
              return;
            }
          } else {
            // established: decrypt + dispatch
            if (!session || session.closed) continue;
            try {
              const frame = session.decrypt(b);
              for (const l of frameListeners) l(frame);
            } catch {
              session.closed = true;
              sink.close();
              for (const l of closeListeners) l();
            }
          }
        }
      } finally {
        processing = false;
      }
    });
    source.onClose(() => {
      if (stage === "awaiting-hello-r") reject(new Error("peer closed before handshake"));
      else if (session && !session.closed) {
        session.closed = true;
        for (const l of closeListeners) l();
      }
    });
  });

  await established;
  return buildEndpoint(session!, sink, frameListeners, closeListeners);
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

  const frameListeners = new Set<(frame: SessionFrame) => void>();
  const closeListeners = new Set<() => void>();
  let session: SessionState | undefined;
  let stage: "awaiting-hello-i" | "awaiting-auth" | "established" = "awaiting-hello-i";
  const queue: Uint8Array[] = [];
  let processing = false;

  const established = new Promise<SessionState>((resolve, reject) => {
    source.onMessage(async (bytes) => {
      queue.push(bytes);
      if (processing) return;
      processing = true;
      try {
        while (queue.length > 0) {
          const b = queue.shift()!;
          if (stage === "awaiting-hello-i") {
            try {
              const helloI = parseJson<HelloI>(b);
              const helloR = await responder.processHelloI(helloI);
              sink.send(jsonBytes(helloR));
              stage = "awaiting-auth";
            } catch (err) {
              reject(err as Error);
              return;
            }
          } else if (stage === "awaiting-auth") {
            try {
              const auth = parseJson<Auth>(b);
              const s = await responder.processAuth(auth);
              stage = "established";
              session = s;
              resolve(s);
              // Yield so `.then` handlers on `established` get a chance to
              // register frame listeners before we dispatch queued data frames.
              await new Promise<void>((r) => setTimeout(r, 0));
            } catch (err) {
              reject(err as Error);
              return;
            }
          } else {
            // established: decrypt + dispatch
            if (!session || session.closed) continue;
            try {
              const frame = session.decrypt(b);
              for (const l of frameListeners) l(frame);
            } catch {
              session.closed = true;
              sink.close();
              for (const l of closeListeners) l();
            }
          }
        }
      } finally {
        processing = false;
      }
    });
    source.onClose(() => {
      if (stage !== "established") reject(new Error("peer closed before handshake"));
      else if (session && !session.closed) {
        session.closed = true;
        for (const l of closeListeners) l();
      }
    });
  });

  await established;
  return buildEndpoint(session!, sink, frameListeners, closeListeners);
}

function buildEndpoint(
  session: SessionState,
  sink: WireSink,
  frameListeners: Set<(frame: SessionFrame) => void>,
  closeListeners: Set<() => void>,
): SessionEndpoint {
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
        for (const l of closeListeners) l();
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
