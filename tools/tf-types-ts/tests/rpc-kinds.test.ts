/**
 * Tests for the additional ProofRPC method kinds: client-streaming,
 * bidi-streaming, subscribe (server-streaming alias), telemetry
 * (client-streaming with no aggregated response).
 */

import { describe, expect, test } from "bun:test";
import {
  RpcClient,
  RpcServer,
  type RpcTransport,
  type RpcProofEventStub,
  type RemoteShellFrame,
} from "../src/index";
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

describe("ProofRPC subscribe (distinct from server-streaming)", () => {
  test("emits method_kind=subscribe in proof events", async () => {
    const { client: clientT, server: serverT } = makePipe();
    const events: RpcProofEventStub[] = [];
    const server = new RpcServer(serverT, {
      selfActor: "tf:actor:agent:example.com/server",
      onProofEvent: (ev) => events.push(ev),
    });
    server.registerSubscribe<{ topic: string }, string>(
      "events.subscribe",
      "events.subscribe",
      async function* () {
        for (const v of ["alpha", "beta"]) yield v;
      },
    );
    const client = new RpcClient(clientT, { callerActor: "tf:actor:agent:example.com/client" });
    const seen: string[] = [];
    for await (const v of client.subscribe<{ topic: string }, string>(
      "events.subscribe",
      { topic: "x" },
      { topic: "x" },
    )) {
      seen.push(v);
    }
    expect(seen).toEqual(["alpha", "beta"]);
    const subscribeEv = events.find((e) => e.method_kind === "subscribe");
    expect(subscribeEv).toBeDefined();
    expect(subscribeEv?.result).toBe("ok");
  });
});

describe("ProofRPC command-channel (credit-based backpressure)", () => {
  test("server emits initial credit grant ack and tags proof events", async () => {
    const { client: clientT, server: serverT } = makePipe();
    const events: RpcProofEventStub[] = [];
    const server = new RpcServer(serverT, {
      selfActor: "tf:actor:agent:example.com/server",
      onProofEvent: (ev) => events.push(ev),
    });
    server.registerCommandChannel<number, string>(
      "ctl.run",
      "ctl.run",
      async function* (_initial, msgs, ctx) {
        for await (const v of msgs) {
          await ctx.requestCredit();
          yield `ack:${v}`;
        }
      },
      { initialCredit: 8 },
    );
    const client = new RpcClient(clientT, { callerActor: "tf:actor:agent:example.com/client" });

    async function* requests(): AsyncIterable<number> {
      yield 1;
      yield 2;
      yield 3;
    }
    const seen: string[] = [];
    for await (const v of client.commandChannel<number, string>("ctl.run", requests())) {
      seen.push(v);
    }
    expect(seen).toEqual(["ack:1", "ack:2", "ack:3"]);
    const ev = events.find((e) => e.method_kind === "command-channel");
    expect(ev).toBeDefined();
    expect(ev?.result).toBe("ok");
  });
});

describe("ProofRPC bulk-transfer (hash-verified)", () => {
  test("verifies sha256 of concatenated chunks; reports verified=true", async () => {
    const { client: clientT, server: serverT } = makePipe();
    const events: RpcProofEventStub[] = [];
    const server = new RpcServer(serverT, {
      selfActor: "tf:actor:agent:example.com/server",
      onProofEvent: (ev) => events.push(ev),
    });
    let total = 0;
    server.registerBulkTransfer<{ bytes: number }>(
      "blob.upload",
      "blob.upload",
      async (_initial, chunks) => {
        for await (const c of chunks) total += c.byteLength;
        return { bytes: total };
      },
    );
    const client = new RpcClient(clientT, { callerActor: "tf:actor:agent:example.com/client" });
    const a = new Uint8Array([1, 2, 3, 4]);
    const b = new Uint8Array([5, 6, 7, 8]);
    const receipt = await client.bulkTransfer<{ bytes: number }>("blob.upload", null, [a, b]);
    expect(receipt.bytes).toBe(8);
    const ev = events.find((e) => e.method_kind === "bulk-transfer");
    expect(ev).toBeDefined();
    expect(ev?.bulk_hash_verified).toBe(true);
  });

  test("rejects with invalid_argument when no expected_hash provided", async () => {
    const { client: clientT, server: serverT } = makePipe();
    const server = new RpcServer(serverT, {
      selfActor: "tf:actor:agent:example.com/server",
    });
    server.registerBulkTransfer<{ ok: true }>("blob.upload2", "blob.upload2", () => ({ ok: true }));
    // Bypass the helper and send a raw bulk-transfer rpc-call with no
    // ext.bulk so we exercise the server's invalid_argument path.
    const client = new RpcClient(clientT, { callerActor: "tf:actor:agent:example.com/client" });
    await expect(
      client.call("blob.upload2", null),
    ).rejects.toThrow(/bulk-transfer requires ext.bulk.expected_hash/);
  });
});

describe("ProofRPC telemetry (priority class)", () => {
  test("priority surfaces in proof event", async () => {
    const { client: clientT, server: serverT } = makePipe();
    const events: RpcProofEventStub[] = [];
    const server = new RpcServer(serverT, {
      selfActor: "tf:actor:agent:example.com/server",
      onProofEvent: (ev) => events.push(ev),
    });
    let count = 0;
    server.registerTelemetry<number>(
      "metrics.cpu",
      "metrics.cpu",
      async (_initial, frames) => {
        for await (const _ of frames) count += 1;
      },
      { priority: "P1" },
    );
    const client = new RpcClient(clientT, { callerActor: "tf:actor:agent:example.com/client" });
    async function* g(): AsyncIterable<number> {
      yield 1;
      yield 2;
      yield 3;
    }
    await client.telemetry("metrics.cpu", g(), { priority: "P1" });
    expect(count).toBe(3);
    const ev = events.find((e) => e.method_kind === "telemetry");
    expect(ev?.streaming_priority).toBe("P1");
  });
});

describe("ProofRPC remote-shell (tagged stdin/stdout/stderr)", () => {
  test("server differentiates stdout vs stderr frames; stdin reaches handler", async () => {
    const { client: clientT, server: serverT } = makePipe();
    const events: RpcProofEventStub[] = [];
    const server = new RpcServer(serverT, {
      selfActor: "tf:actor:agent:example.com/server",
      onProofEvent: (ev) => events.push(ev),
    });
    const stdinSeen: string[] = [];
    server.registerRemoteShell("shell.run", "shell.run", async function* (_initial, stdin) {
      for await (const buf of stdin) {
        stdinSeen.push(new TextDecoder().decode(buf));
      }
      yield { stream: "stdout", data: new TextEncoder().encode("hello-out") };
      yield { stream: "stderr", data: new TextEncoder().encode("oops") };
    });
    const client = new RpcClient(clientT, { callerActor: "tf:actor:agent:example.com/client" });
    async function* keys(): AsyncIterable<Uint8Array> {
      yield new TextEncoder().encode("ls -la\n");
    }
    const got: RemoteShellFrame[] = [];
    for await (const f of client.remoteShell("shell.run", keys())) got.push(f);
    expect(stdinSeen).toEqual(["ls -la\n"]);
    expect(got.length).toBe(2);
    expect(got[0]!.stream).toBe("stdout");
    expect(new TextDecoder().decode(got[0]!.data)).toBe("hello-out");
    expect(got[1]!.stream).toBe("stderr");
    expect(new TextDecoder().decode(got[1]!.data)).toBe("oops");
    const ev = events.find((e) => e.method_kind === "remote-shell");
    expect(ev?.result).toBe("ok");
  });
});

describe("ProofRPC agent-session (delegation chain)", () => {
  test("server receives initial chain and emits chained server frames", async () => {
    const { client: clientT, server: serverT } = makePipe();
    const events: RpcProofEventStub[] = [];
    const server = new RpcServer(serverT, {
      selfActor: "tf:actor:agent:example.com/server",
      onProofEvent: (ev) => events.push(ev),
    });
    server.registerAgentSession<string, string>(
      "agent.run",
      "agent.run",
      async function* (_initial, msgs, ctx) {
        for await (const m of msgs) {
          yield {
            value: `${m.value}!`,
            responsibility_chain: [...ctx.initialChain, "tf:actor:agent:example.com/server"],
          };
        }
      },
    );
    const client = new RpcClient(clientT, { callerActor: "tf:actor:agent:example.com/client" });
    async function* msgs(): AsyncIterable<{ value: string; responsibility_chain: string[] }> {
      yield { value: "hi", responsibility_chain: ["tf:actor:human:example.com/alice"] };
    }
    const seen: Array<{ value: string; chain: string[] }> = [];
    for await (const v of client.agentSession<string, string>(
      "agent.run",
      msgs(),
      ["tf:actor:human:example.com/alice"],
    )) {
      seen.push({ value: v.value, chain: v.responsibility_chain });
    }
    expect(seen.length).toBe(1);
    expect(seen[0]!.value).toBe("hi!");
    expect(seen[0]!.chain).toEqual([
      "tf:actor:human:example.com/alice",
      "tf:actor:agent:example.com/server",
    ]);
    const ev = events.find((e) => e.method_kind === "agent-session");
    expect(ev?.result).toBe("ok");
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
