import { describe, expect, test } from "bun:test";
import { ed25519Generate, type SessionFrame } from "tf-types";
import { attachInitiator, attachResponder, wireFromWebSocket } from "../src/index";

interface InMemoryWS {
  sink: { send(b: Uint8Array): void; close(): void };
  source: { onMessage(l: (b: Uint8Array) => void): void; onClose(l: () => void): void };
}

function makePipe(): { a: InMemoryWS; b: InMemoryWS } {
  const aListeners = new Set<(b: Uint8Array) => void>();
  const aClose = new Set<() => void>();
  const bListeners = new Set<(b: Uint8Array) => void>();
  const bClose = new Set<() => void>();
  return {
    a: {
      sink: {
        send(bytes) {
          for (const l of bListeners) l(bytes);
        },
        close() {
          for (const l of aClose) l();
          for (const l of bClose) l();
        },
      },
      source: {
        onMessage(l) {
          aListeners.add(l);
        },
        onClose(l) {
          aClose.add(l);
        },
      },
    },
    b: {
      sink: {
        send(bytes) {
          for (const l of aListeners) l(bytes);
        },
        close() {
          for (const l of bClose) l();
          for (const l of aClose) l();
        },
      },
      source: {
        onMessage(l) {
          bListeners.add(l);
        },
        onClose(l) {
          bClose.add(l);
        },
      },
    },
  };
}

describe("tf-session in-memory pipe", () => {
  test("initiator + responder complete handshake and exchange frames", async () => {
    const iId = await ed25519Generate();
    const rId = await ed25519Generate();
    const pipe = makePipe();

    const respPromise = attachResponder(
      {
        selfActor: "tf:actor:agent:example.com/r",
        identityPriv: rId.privateKey,
        identityPub: rId.publicKey,
      },
      pipe.b.sink,
      pipe.b.source,
    );

    const initPromise = attachInitiator(
      {
        selfActor: "tf:actor:agent:example.com/i",
        peerHint: "tf:actor:agent:example.com/r",
        identityPriv: iId.privateKey,
        identityPub: iId.publicKey,
      },
      pipe.a.sink,
      pipe.a.source,
    );

    const [initiator, responder] = await Promise.all([initPromise, respPromise]);

    const received: SessionFrame[] = [];
    responder.onFrame((f) => received.push(f));

    initiator.send({ kind: "data", payload: { hello: "from initiator" } });
    initiator.send({ kind: "data", payload: { msg: 2 } });

    // Allow the in-memory pipe a microtask to drain.
    await new Promise((r) => setTimeout(r, 5));

    expect(received).toHaveLength(2);
    expect(received[0]).toEqual({ kind: "data", payload: { hello: "from initiator" } });
    expect(received[1]).toEqual({ kind: "data", payload: { msg: 2 } });

    // Responder→initiator direction.
    const replyReceived: SessionFrame[] = [];
    initiator.onFrame((f) => replyReceived.push(f));
    responder.send({ kind: "data", payload: "ack" });
    await new Promise((r) => setTimeout(r, 5));
    expect(replyReceived).toEqual([{ kind: "data", payload: "ack" }]);
  });

  test("Bun.serve WebSocket carrier round-trip", async () => {
    const iId = await ed25519Generate();
    const rId = await ed25519Generate();

    let serverEndpointResolve: (v: Awaited<ReturnType<typeof attachResponder>>) => void;
    const serverEndpointPromise = new Promise<Awaited<ReturnType<typeof attachResponder>>>((r) => {
      serverEndpointResolve = r;
    });

    const server = Bun.serve({
      port: 0,
      fetch(req, server) {
        if (server.upgrade(req, { data: {} as never })) return;
        return new Response("expected websocket", { status: 400 });
      },
      websocket: {
        open(ws) {
          ws.binaryType = "uint8array";
          const wire = wireFromBunServerSocket(ws);
          (ws.data as any).wire = wire;
          // Run the responder handshake asynchronously; it consumes incoming
          // messages via wire.deliverMessage as they arrive.
          attachResponder(
            {
              selfActor: "tf:actor:agent:example.com/r",
              identityPriv: rId.privateKey,
              identityPub: rId.publicKey,
            },
            wire.sink,
            wire.source,
          ).then(serverEndpointResolve);
        },
        message(ws, message) {
          const w = (ws.data as any).wire as ReturnType<typeof wireFromBunServerSocket>;
          w.deliverMessage(message);
        },
        close(ws) {
          const w = (ws.data as any).wire as ReturnType<typeof wireFromBunServerSocket> | undefined;
          if (w) w.deliverClose();
        },
      },
    });

    const url = `ws://localhost:${server.port}/`;
    const client = new WebSocket(url);
    client.binaryType = "arraybuffer";

    await new Promise<void>((resolve) => client.addEventListener("open", () => resolve()));

    const wire = wireFromWebSocket(client as unknown as Parameters<typeof wireFromWebSocket>[0]);
    const initiator = await attachInitiator(
      {
        selfActor: "tf:actor:agent:example.com/i",
        peerHint: "tf:actor:agent:example.com/r",
        identityPriv: iId.privateKey,
        identityPub: iId.publicKey,
      },
      wire.sink,
      wire.source,
    );

    const responder = await serverEndpointPromise;
    const received: SessionFrame[] = [];
    responder.onFrame((f) => received.push(f));

    initiator.send({ kind: "data", payload: "via websocket" });
    await new Promise((r) => setTimeout(r, 30));

    expect(received).toEqual([{ kind: "data", payload: "via websocket" }]);

    client.close();
    server.stop(true);
  });
});

// Bun.serve websockets aren't standard EventTargets; this small adapter
// mirrors the WireSink/WireSource shape used by attachResponder.
function wireFromBunServerSocket(ws: import("bun").ServerWebSocket<unknown>) {
  const messageListeners = new Set<(b: Uint8Array) => void>();
  const closeListeners = new Set<() => void>();
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
      onMessage(l: (b: Uint8Array) => void) {
        messageListeners.add(l);
      },
      onClose(l: () => void) {
        closeListeners.add(l);
      },
    },
    deliverMessage(message: string | Uint8Array | Buffer) {
      let bytes: Uint8Array;
      if (typeof message === "string") bytes = new TextEncoder().encode(message);
      else bytes = new Uint8Array(message);
      for (const l of messageListeners) l(bytes);
    },
    deliverClose() {
      for (const l of closeListeners) l();
    },
  };
}
