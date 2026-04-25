/**
 * Tests for the additional ProofRPC method kinds: client-streaming,
 * bidi-streaming, subscribe (server-streaming alias), telemetry
 * (client-streaming with no aggregated response).
 */

import { describe, expect, test } from "bun:test";
import { RpcClient, RpcServer, type RpcTransport } from "../src/index";
import type { SessionFrame } from "../src/core/session";

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

async function* asAsync<T>(items: T[]): AsyncIterable<T> {
  for (const item of items) yield item;
}

describe("ProofRPC client-streaming", () => {
  test("client emits N requests, server returns one aggregated response", async () => {
    const { client: clientT, server: serverT } = makePipe();
    const server = new RpcServer(serverT, {
      selfActor: "tf:actor:agent:example.com/server",
    });
    server.registerClientStream<number, number>("sum", "math.sum", async (_initial, msgs) => {
      let total = 0;
      for await (const v of msgs) total += v as number;
      return total;
    });

    const client = new RpcClient(clientT, { callerActor: "tf:actor:agent:example.com/client" });
    const result = await client.clientStream<number, number>("sum", asAsync([1, 2, 3, 4, 5]));
    expect(result).toBe(15);
  });

  test("telemetry returns void after the client stream completes", async () => {
    const { client: clientT, server: serverT } = makePipe();
    const server = new RpcServer(serverT, {
      selfActor: "tf:actor:agent:example.com/server",
    });
    const seen: number[] = [];
    server.registerTelemetry<number>("metrics.push", "metrics.push", async (_initial, frames) => {
      for await (const v of frames) seen.push(v as number);
    });

    const client = new RpcClient(clientT, { callerActor: "tf:actor:agent:example.com/client" });
    await client.telemetry("metrics.push", asAsync([10, 20, 30]));
    expect(seen).toEqual([10, 20, 30]);
  });
});

describe("ProofRPC bidi-streaming", () => {
  test("each side independently emits N messages", async () => {
    const { client: clientT, server: serverT } = makePipe();
    const server = new RpcServer(serverT, {
      selfActor: "tf:actor:agent:example.com/server",
    });
    server.registerBidiStream<number, number>(
      "echo.double",
      "echo.double",
      async function* (_initial, msgs) {
        for await (const v of msgs) {
          yield (v as number) * 2;
        }
      },
    );

    const client = new RpcClient(clientT, { callerActor: "tf:actor:agent:example.com/client" });
    const stream = client.bidiStream<number, number>("echo.double", asAsync([1, 2, 3]));
    const seen: number[] = [];
    for await (const v of stream) seen.push(v);
    expect(seen).toEqual([2, 4, 6]);
  });
});

describe("ProofRPC subscribe (server-streaming alias)", () => {
  test("subscribe flows the same as serverStream", async () => {
    const { client: clientT, server: serverT } = makePipe();
    const server = new RpcServer(serverT, {
      selfActor: "tf:actor:agent:example.com/server",
    });
    server.registerSubscribe<{ topic: string }, string>(
      "events.subscribe",
      "events.subscribe",
      async function* () {
        for (const v of ["alpha", "beta", "gamma"]) yield v;
      },
    );
    const client = new RpcClient(clientT, { callerActor: "tf:actor:agent:example.com/client" });
    const seen: string[] = [];
    for await (const evt of client.subscribe<{ topic: string }, string>("events.subscribe", { topic: "x" })) {
      seen.push(evt);
    }
    expect(seen).toEqual(["alpha", "beta", "gamma"]);
  });
});

describe("ProofRPC method-kind enum (schema)", () => {
  test("the proofrpc.schema.json kind enum exposes all 10 kinds", async () => {
    const raw = await Bun.file("schemas/proofrpc.schema.json").json();
    const kinds = raw.$defs.Method.properties.kind.enum as string[];
    expect(kinds).toContain("unary");
    expect(kinds).toContain("server-streaming");
    expect(kinds).toContain("client-streaming");
    expect(kinds).toContain("bidi-streaming");
    expect(kinds).toContain("subscribe");
    expect(kinds).toContain("command-channel");
    expect(kinds).toContain("bulk-transfer");
    expect(kinds).toContain("telemetry");
    expect(kinds).toContain("remote-shell");
    expect(kinds).toContain("agent-session");
  });
});
