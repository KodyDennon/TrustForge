import { describe, expect, test, beforeEach, afterEach } from "bun:test";
import { startMockDaemon, type MockDaemonHandle } from "@trustforge-protocol/test-utils";
import {
  trustforgeForIronSession,
  tfRequireIron,
} from "../src/index.ts";

let daemon: MockDaemonHandle;

beforeEach(() => {
  daemon = startMockDaemon();
});
afterEach(async () => {
  await daemon.stop();
});

function fakeGetIronSession(payload: Record<string, unknown>) {
  return async (_req: unknown, _res: unknown, _opts: unknown) =>
    ({
      ...payload,
      async save() {},
      async destroy() {},
    }) as any;
}

describe("@trustforge-protocol/iron-session", () => {
  test("wrapped getIronSession populates tfActor on a payload with id", async () => {
    const wrapped = trustforgeForIronSession(
      fakeGetIronSession({ id: "session-id-1", userId: "u-1" }),
      { daemonUrl: daemon.url, quiet: true },
    );
    const sess = await wrapped({}, {});
    expect(sess.tfActor).toBeDefined();
    expect(sess.tfTrustLevel).toBe("T2");
  });

  test("missing identity is a clean pass-through", async () => {
    const wrapped = trustforgeForIronSession(fakeGetIronSession({}), {
      daemonUrl: daemon.url,
      quiet: true,
    });
    const sess = await wrapped({}, {});
    expect(sess.tfActor).toBeUndefined();
  });

  test("tfRequireIron decides via /v1/decide", async () => {
    const guard = tfRequireIron(
      { daemonUrl: daemon.url, quiet: true },
      "fs.write",
    );
    const verdict = await guard({ tfActor: "tf:actor:agent:e/x" });
    expect(verdict.allowed).toBe(true);
    expect(daemon.calls()[0]?.action).toBe("fs.write");
  });
});
