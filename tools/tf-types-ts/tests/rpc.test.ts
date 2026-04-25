import { describe, expect, test } from "bun:test";
import type { SessionFrame } from "../src/core/session";
import {
  RpcClient,
  RpcServer,
  RpcCallError,
  type RpcProofEventStub,
  type RpcTransport,
  denyAllEnforcer,
} from "../src/core/rpc";

function makePipe(): { client: RpcTransport; server: RpcTransport } {
  const clientListeners = new Set<(f: SessionFrame) => void>();
  const serverListeners = new Set<(f: SessionFrame) => void>();
  return {
    client: {
      send(frame) {
        for (const l of serverListeners) l(frame);
      },
      onFrame(listener) {
        clientListeners.add(listener);
      },
    },
    server: {
      send(frame) {
        for (const l of clientListeners) l(frame);
      },
      onFrame(listener) {
        serverListeners.add(listener);
      },
    },
  };
}

describe("RPC unary", () => {
  test("round-trip with response", async () => {
    const { client: clientT, server: serverT } = makePipe();
    const events: RpcProofEventStub[] = [];
    const server = new RpcServer(serverT, {
      selfActor: "tf:actor:agent:example.com/server",
      callerActor: "tf:actor:human:example.com/kody",
      onProofEvent: (e) => events.push(e),
    });
    server.registerUnary<{ path: string }, { path: string; size: number }>(
      "fetchFile",
      "file.read",
      async (req) => ({ path: req.path, size: req.path.length }),
    );
    const client = new RpcClient(clientT, { callerActor: "tf:actor:human:example.com/kody" });
    const res = await client.call<{ path: string }, { path: string; size: number }>(
      "fetchFile",
      { path: "README.md" },
    );
    expect(res).toEqual({ path: "README.md", size: 9 });
    expect(events.find((e) => e.method === "fetchFile" && e.result === "ok")).toBeDefined();
  });

  test("unknown method returns not_found", async () => {
    const { client: clientT, server: serverT } = makePipe();
    void new RpcServer(serverT, { selfActor: "tf:actor:agent:example.com/s" });
    const client = new RpcClient(clientT);
    await expect(client.call("bogus", {})).rejects.toBeInstanceOf(RpcCallError);
  });

  test("handler throw returns internal error", async () => {
    const { client: clientT, server: serverT } = makePipe();
    const server = new RpcServer(serverT, { selfActor: "tf:actor:agent:example.com/s" });
    server.registerUnary("boom", "file.read", async () => {
      throw new Error("oh no");
    });
    const client = new RpcClient(clientT);
    try {
      await client.call("boom", {});
      throw new Error("should have thrown");
    } catch (err) {
      expect(err).toBeInstanceOf(RpcCallError);
      expect((err as RpcCallError).code).toBe("internal");
    }
  });

  test("deny-all enforcer rejects with permission_denied", async () => {
    const { client: clientT, server: serverT } = makePipe();
    const server = new RpcServer(serverT, {
      selfActor: "tf:actor:agent:example.com/s",
      enforcer: denyAllEnforcer,
    });
    server.registerUnary("fetchFile", "file.read", async () => ({}));
    const client = new RpcClient(clientT);
    try {
      await client.call("fetchFile", { path: "x" });
      throw new Error("should have thrown");
    } catch (err) {
      expect(err).toBeInstanceOf(RpcCallError);
      expect((err as RpcCallError).code).toBe("permission_denied");
    }
  });
});

describe("RPC server-streaming", () => {
  test("delivers N values and terminates", async () => {
    const { client: clientT, server: serverT } = makePipe();
    const server = new RpcServer(serverT, { selfActor: "tf:actor:agent:example.com/s" });
    server.registerServerStream<{ count: number }, { n: number }>(
      "count",
      "file.read",
      async function* (req) {
        for (let i = 0; i < req.count; i++) yield { n: i };
      },
    );
    const client = new RpcClient(clientT);
    const received: { n: number }[] = [];
    for await (const v of client.serverStream<{ count: number }, { n: number }>("count", { count: 4 })) {
      received.push(v);
    }
    expect(received).toEqual([{ n: 0 }, { n: 1 }, { n: 2 }, { n: 3 }]);
  });

  test("handler throw delivers error to client stream", async () => {
    const { client: clientT, server: serverT } = makePipe();
    const server = new RpcServer(serverT, { selfActor: "tf:actor:agent:example.com/s" });
    server.registerServerStream("fail", "file.read", async function* () {
      yield 1;
      throw new Error("stream broke");
    });
    const client = new RpcClient(clientT);
    const received: number[] = [];
    try {
      for await (const v of client.serverStream<{}, number>("fail", {})) {
        received.push(v);
      }
      throw new Error("should have thrown");
    } catch (err) {
      expect(err).toBeInstanceOf(RpcCallError);
      expect((err as RpcCallError).code).toBe("internal");
    }
    expect(received).toEqual([1]);
  });
});
