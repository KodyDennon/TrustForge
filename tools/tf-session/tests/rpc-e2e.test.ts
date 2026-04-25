import { describe, expect, test } from "bun:test";
import { ed25519Generate, RpcClient, RpcServer, allowAllEnforcer } from "tf-types";
import { attachInitiator, attachResponder, rpcTransportFromEndpoint, wireFromWebSocket } from "../src/index";
import {
  CodeHelperClient,
  registerCodeHelper,
  type CodeHelperServer,
  type FetchFileRequest,
  type FetchFileResponse,
  type StreamDirectoryRequest,
  type StreamDirectoryResponse,
} from "../../tf-types-ts/src/generated/rpc/code-helper";

class DemoServer implements CodeHelperServer {
  async fetchFile(req: FetchFileRequest): Promise<FetchFileResponse> {
    return { path: req.path, contents: `ws contents of ${req.path}`, size: req.path.length };
  }
  async *streamDirectory(req: StreamDirectoryRequest): AsyncIterable<StreamDirectoryResponse> {
    yield { name: "x.txt", kind: "file", size: 1 };
    yield { name: "y.txt", kind: "file", size: 2 };
    yield { name: "z", kind: "dir", size: 0 };
    void req;
  }
}

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

describe("RPC over real WebSocket", () => {
  test("unary + server-streaming round-trip via generated CodeHelperClient", async () => {
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
          attachResponder(
            {
              selfActor: "tf:actor:agent:example.com/r",
              identityPriv: rId.privateKey,
              identityPub: rId.publicKey,
            },
            wire.sink,
            wire.source,
          ).then((endpoint) => {
            // Wrap the session endpoint as an RpcTransport and register
            // the generated handlers.
            const rpcServer = new RpcServer(rpcTransportFromEndpoint(endpoint), {
              selfActor: "tf:actor:agent:example.com/r",
              enforcer: allowAllEnforcer,
            });
            registerCodeHelper(rpcServer, new DemoServer());
            serverEndpointResolve(endpoint);
          });
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
    const clientWs = new WebSocket(url);
    clientWs.binaryType = "arraybuffer";
    await new Promise<void>((resolve) => clientWs.addEventListener("open", () => resolve()));

    const wire = wireFromWebSocket(clientWs as unknown as Parameters<typeof wireFromWebSocket>[0]);
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

    // Make sure the server finished attaching before issuing RPCs.
    await serverEndpointPromise;

    const rpc = new RpcClient(rpcTransportFromEndpoint(initiator), {
      callerActor: "tf:actor:human:example.com/kody",
    });
    const client = new CodeHelperClient(rpc);

    const resp = await client.fetchFile({ path: "README.md" });
    expect(resp).toEqual({
      path: "README.md",
      contents: "ws contents of README.md",
      size: 9,
    });

    const entries: StreamDirectoryResponse[] = [];
    for await (const entry of client.streamDirectory({ path: "." })) {
      entries.push(entry);
    }
    expect(entries).toEqual([
      { name: "x.txt", kind: "file", size: 1 },
      { name: "y.txt", kind: "file", size: 2 },
      { name: "z", kind: "dir", size: 0 },
    ]);

    clientWs.close();
    server.stop(true);
  });
});
