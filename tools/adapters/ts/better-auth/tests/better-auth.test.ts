import { describe, expect, test, beforeEach, afterEach } from "bun:test";
import { startMockDaemon, type MockDaemonHandle } from "@trustforge-protocol/test-utils";
import { trustforgePlugin } from "../src/index.ts";

let daemon: MockDaemonHandle;

beforeEach(() => {
  daemon = startMockDaemon();
});
afterEach(async () => {
  await daemon.stop();
});

describe("@trustforge-protocol/better-auth", () => {
  test("plugin shape: id + hooks.session.fetch present", () => {
    const plugin = trustforgePlugin({
      daemonUrl: daemon.url,
      quiet: true,
    });
    expect(plugin.id).toBe("trustforge");
    expect(typeof plugin.hooks.session.fetch).toBe("function");
    expect(typeof plugin.tfRequire).toBe("function");
  });

  test("session.fetch attaches tfActor / tfCredentialId on a resolved session", async () => {
    const plugin = trustforgePlugin({
      daemonUrl: daemon.url,
      quiet: true,
    });
    const ctx = await plugin.hooks.session.fetch({
      session: { id: "sess-abc", userId: "u-1" },
    });
    expect(ctx.tfActor).toBeDefined();
    expect(ctx.tfCredentialId).toBe("cred-mock-1");
    expect(ctx.tfTrustLevel).toBe("T2");
    expect(Array.isArray(ctx.tfCapabilities)).toBe(true);
  });

  test("session.fetch with null session is a no-op", async () => {
    const plugin = trustforgePlugin({
      daemonUrl: daemon.url,
      quiet: true,
    });
    const ctx = await plugin.hooks.session.fetch({ session: null });
    expect(ctx.tfActor).toBeUndefined();
  });

  test("tfRequire decides via /v1/decide and surfaces the verdict", async () => {
    const plugin = trustforgePlugin({
      daemonUrl: daemon.url,
      quiet: true,
    });
    const guard = plugin.tfRequire("fs.read", "/etc/passwd");
    const verdict = await guard({
      tfActor: "tf:actor:agent:example.com/x",
    });
    expect(verdict.allowed).toBe(true);
    expect(verdict.proofId).toContain("sha256:mock-");
    expect(daemon.callCount()).toBe(1);
    expect(daemon.calls()[0]?.action).toBe("fs.read");
  });
});
