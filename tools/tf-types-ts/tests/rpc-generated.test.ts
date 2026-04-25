import { describe, expect, test } from "bun:test";
import type { SessionFrame } from "../src/core/session";
import type { RpcTransport } from "../src/core/rpc";
import { RpcClient, RpcServer, allowAllEnforcer } from "../src/core/rpc";
import {
  CodeHelperClient,
  registerCodeHelper,
  type CodeHelperServer,
  type FetchFileRequest,
  type FetchFileResponse,
  type StreamDirectoryRequest,
  type StreamDirectoryResponse,
} from "../src/generated/rpc/code-helper";

function makePipe(): { client: RpcTransport; server: RpcTransport } {
  const clientListeners = new Set<(f: SessionFrame) => void>();
  const serverListeners = new Set<(f: SessionFrame) => void>();
  return {
    client: {
      send: (f) => serverListeners.forEach((l) => l(f)),
      onFrame: (l) => clientListeners.add(l),
    },
    server: {
      send: (f) => clientListeners.forEach((l) => l(f)),
      onFrame: (l) => serverListeners.add(l),
    },
  };
}

class DemoServer implements CodeHelperServer {
  async fetchFile(req: FetchFileRequest): Promise<FetchFileResponse> {
    return { path: req.path, contents: `content of ${req.path}`, size: req.path.length };
  }
  async *streamDirectory(req: StreamDirectoryRequest): AsyncIterable<StreamDirectoryResponse> {
    yield { name: "a.txt", kind: "file", size: 10 };
    yield { name: "b.txt", kind: "file", size: 20 };
    yield { name: "sub", kind: "dir", size: 0 };
    void req;
  }
}

describe("generated CodeHelperClient/Server", () => {
  test("unary fetchFile round-trips through generated types", async () => {
    const pipe = makePipe();
    const server = new RpcServer(pipe.server, {
      selfActor: "tf:actor:agent:example.com/srv",
      enforcer: allowAllEnforcer,
    });
    registerCodeHelper(server, new DemoServer());
    const client = new CodeHelperClient(
      new RpcClient(pipe.client, { callerActor: "tf:actor:human:example.com/alice" }),
    );
    const resp = await client.fetchFile({ path: "README.md" });
    expect(resp.path).toBe("README.md");
    expect(resp.contents).toBe("content of README.md");
    expect(resp.size).toBe(9);
  });

  test("generated streamDirectory delivers all entries", async () => {
    const pipe = makePipe();
    const server = new RpcServer(pipe.server, {
      selfActor: "tf:actor:agent:example.com/srv",
      enforcer: allowAllEnforcer,
    });
    registerCodeHelper(server, new DemoServer());
    const client = new CodeHelperClient(
      new RpcClient(pipe.client, { callerActor: "tf:actor:human:example.com/alice" }),
    );
    const entries: StreamDirectoryResponse[] = [];
    for await (const entry of client.streamDirectory({ path: "." })) {
      entries.push(entry);
    }
    expect(entries).toHaveLength(3);
    expect(entries[0]).toEqual({ name: "a.txt", kind: "file", size: 10 });
    expect(entries[2]).toEqual({ name: "sub", kind: "dir", size: 0 });
  });
});
