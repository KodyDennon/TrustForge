/**
 * Continuous reauthorization test for RpcServer.
 *
 * Asserts that an in-flight server-streaming call gets terminated with
 * permission_denied when the bound CapabilityEnforcer flips from allow
 * to deny and `RpcServer.reevaluate()` is called with a configured
 * trigger (TF-0004 `policy.continuous_reevaluation`).
 */

import { describe, expect, test } from "bun:test";
import {
  RpcClient,
  RpcServer,
  type CapabilityEnforcer,
  type CapabilityVerdict,
  type RpcTransport,
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

describe("Continuous reauthorization", () => {
  test("server-streaming call is canceled when revocation trigger fires", async () => {
    const { client: clientT, server: serverT } = makePipe();
    let allowed = true;
    const enforcer: CapabilityEnforcer = {
      check: (): CapabilityVerdict => (allowed ? "allow" : { deny: "revoked" }),
    };
    const server = new RpcServer(serverT, {
      selfActor: "tf:actor:agent:example.com/server",
      enforcer,
      continuousReevaluation: { triggers: ["revocation", "session_rekey"] },
    });
    server.registerServerStream<unknown, number>(
      "demo.tick",
      "demo.tick",
      async function* () {
        for (let i = 0; i < 100; i++) {
          await new Promise((r) => setTimeout(r, 5));
          yield i;
        }
      },
    );

    const client = new RpcClient(clientT, {});
    const stream = client.serverStream<unknown, number>("demo.tick", {});
    let received: number[] = [];
    let errorCode: string | undefined;
    const collected = (async () => {
      try {
        for await (const v of stream) {
          received.push(v);
          if (received.length === 3) {
            // After we've seen a few values, flip the enforcer and trigger
            // the reevaluation.
            allowed = false;
            await server.reevaluate("revocation");
          }
        }
      } catch (err) {
        errorCode = (err as Error).message;
      }
    })();

    await collected;
    server.shutdown();

    expect(received.length).toBeGreaterThanOrEqual(3);
    expect(errorCode).toBeDefined();
    expect(errorCode!).toContain("permission_denied");
  });

  test("reevaluate is a no-op when trigger is not configured", async () => {
    const { client: clientT, server: serverT } = makePipe();
    const enforcer: CapabilityEnforcer = {
      check: (): CapabilityVerdict => "allow",
    };
    const server = new RpcServer(serverT, {
      selfActor: "tf:actor:agent:example.com/server",
      enforcer,
      continuousReevaluation: { triggers: ["revocation"] },
    });
    server.registerUnary<unknown, number>("demo.echo", "demo.echo", async () => 42);
    const client = new RpcClient(clientT, {});
    const result = await client.call<unknown, number>("demo.echo", 0);
    // delegation_change isn't in our trigger list, so this is a no-op
    await server.reevaluate("delegation_change");
    expect(result).toBe(42);
    server.shutdown();
  });
});
