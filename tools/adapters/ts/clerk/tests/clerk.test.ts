import { describe, expect, test, beforeEach, afterEach } from "bun:test";
import { startMockDaemon, type MockDaemonHandle } from "@trustforge/test-utils";
import {
  withTrustForge,
  trustforgeClerk,
  tfRequireClerk,
} from "../src/index.ts";

let daemon: MockDaemonHandle;

beforeEach(() => {
  daemon = startMockDaemon();
});
afterEach(async () => {
  await daemon.stop();
});

describe("@trustforge/clerk", () => {
  test("withTrustForge wraps a Clerk-style middleware and projects sessionId", async () => {
    let innerCalled = false;
    const fakeClerk = async (req: any, _evt: any) => {
      innerCalled = true;
      // Clerk attaches `auth()` to req
      req.auth = () => ({ sessionId: "sess_clerk_1", userId: "user_42" });
      return new Response(null, { status: 200 });
    };
    const mw = withTrustForge(fakeClerk, {
      daemonUrl: daemon.url,
      quiet: true,
    });
    const req: any = {};
    await mw(req, {});
    expect(innerCalled).toBe(true);
    expect(req.tfActor).toBeDefined();
    expect(req.tfCredentialId).toBe("cred-mock-1");
  });

  test("trustforgeClerk Express middleware: happy path", async () => {
    const mw = trustforgeClerk({ daemonUrl: daemon.url, quiet: true });
    const req: any = { auth: { sessionId: "sess_2", userId: "u2" } };
    let nextErr: unknown = "untouched";
    await mw(req, {}, (err) => {
      nextErr = err;
    });
    expect(nextErr).toBeUndefined();
    expect(req.tfActor).toBeDefined();
    expect(Array.isArray(req.tfCapabilities)).toBe(true);
  });

  test("trustforgeClerk: missing sessionId is a clean pass-through", async () => {
    const mw = trustforgeClerk({ daemonUrl: daemon.url, quiet: true });
    const req: any = {};
    let called = false;
    await mw(req, {}, (err) => {
      called = true;
      expect(err).toBeUndefined();
    });
    expect(called).toBe(true);
    expect(req.tfActor).toBeUndefined();
  });

  test("tfRequireClerk decides via /v1/decide", async () => {
    const guard = tfRequireClerk(
      { daemonUrl: daemon.url, quiet: true },
      "shell.exec",
      "/bin/rm",
    );
    const verdict = await guard({ tfActor: "tf:actor:agent:e/x" });
    expect(verdict.allowed).toBe(true);
    expect(daemon.calls()[0]?.target).toBe("/bin/rm");
  });
});
