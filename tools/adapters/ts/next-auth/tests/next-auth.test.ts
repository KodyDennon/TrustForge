import { describe, expect, test, beforeEach, afterEach } from "bun:test";
import { startMockDaemon, type MockDaemonHandle } from "@trustforge/test-utils";
import { trustforgeCallbacks, tfRequire } from "../src/index.ts";

let daemon: MockDaemonHandle;

beforeEach(() => {
  daemon = startMockDaemon();
});
afterEach(async () => {
  await daemon.stop();
});

describe("@trustforge/next-auth", () => {
  test("returns the four NextAuth callbacks", () => {
    const cb = trustforgeCallbacks({ daemonUrl: daemon.url, quiet: true });
    expect(typeof cb.jwt).toBe("function");
    expect(typeof cb.session).toBe("function");
    expect(typeof cb.signIn).toBe("function");
    expect(typeof cb.signOut).toBe("function");
  });

  test("jwt() attaches tfActor on initial sign-in", async () => {
    const cb = trustforgeCallbacks({ daemonUrl: daemon.url, quiet: true });
    const token = await cb.jwt({
      token: { sub: "user-123" },
      user: { id: "user-123" },
      account: { access_token: "jwt-blob", provider: "github" },
    });
    expect(token.tfActor).toBeDefined();
    expect(token.tfTrustLevel).toBe("T2");
    expect(token.tfCredentialId).toBe("cred-mock-1");
  });

  test("session() mirrors TF fields from token onto session", async () => {
    const cb = trustforgeCallbacks({ daemonUrl: daemon.url, quiet: true });
    const session = await cb.session({
      session: { user: { id: "u" } },
      token: {
        sub: "u",
        tfActor: "tf:actor:agent:x/y",
        tfCredentialId: "cred-1",
        tfTrustLevel: "T3",
      },
    });
    expect(session.tfActor).toBe("tf:actor:agent:x/y");
    expect(session.tfTrustLevel).toBe("T3");
    expect(Array.isArray(session.tfCapabilities)).toBe(true);
  });

  test("tfRequire decides via the daemon", async () => {
    const guard = tfRequire(
      { daemonUrl: daemon.url, quiet: true },
      "billing.charge",
    );
    const verdict = await guard({ tfActor: "tf:actor:agent:x/y" });
    expect(verdict.allowed).toBe(true);
    expect(daemon.callCount()).toBe(1);
    expect(daemon.calls()[0]?.action).toBe("billing.charge");
  });
});
