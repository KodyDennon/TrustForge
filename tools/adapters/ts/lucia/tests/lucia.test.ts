import { describe, expect, test, beforeEach, afterEach } from "bun:test";
import { startMockDaemon, type MockDaemonHandle } from "@trustforge-protocol/test-utils";
import { trustforgeForLucia } from "../src/index.ts";

let daemon: MockDaemonHandle;

beforeEach(() => {
  daemon = startMockDaemon();
});
afterEach(async () => {
  await daemon.stop();
});

describe("@trustforge-protocol/lucia", () => {
  test("validateSession projects a valid session into TF actor", async () => {
    const fakeLucia = {
      async validateSession(id: string) {
        return { session: { id, userId: "u-1" }, user: { id: "u-1" } };
      },
    };
    const wrap = trustforgeForLucia(fakeLucia, {
      daemonUrl: daemon.url,
      quiet: true,
    });
    const r = await wrap.validateSession("sess-1");
    expect(r.tfActor).toBeDefined();
    expect(r.tfCredentialId).toBe("cred-mock-1");
    expect(r.session?.id).toBe("sess-1");
  });

  test("validateSession with null session is a clean pass-through", async () => {
    const fakeLucia = {
      async validateSession(_id: string) {
        return { session: null, user: null };
      },
    };
    const wrap = trustforgeForLucia(fakeLucia, {
      daemonUrl: daemon.url,
      quiet: true,
    });
    const r = await wrap.validateSession("expired");
    expect(r.tfActor).toBeUndefined();
    expect(r.session).toBeNull();
  });

  test("tfRequire calls /v1/decide with the projected actor", async () => {
    const fakeLucia = {
      async validateSession(id: string) {
        return { session: { id, userId: "u" }, user: { id: "u" } };
      },
    };
    const wrap = trustforgeForLucia(fakeLucia, {
      daemonUrl: daemon.url,
      quiet: true,
    });
    const r = await wrap.validateSession("sess-2");
    const guard = wrap.tfRequire("net.connect", "https://example.com");
    const verdict = await guard(r);
    expect(verdict.allowed).toBe(true);
    expect(daemon.calls()[0]?.action).toBe("net.connect");
  });
});
