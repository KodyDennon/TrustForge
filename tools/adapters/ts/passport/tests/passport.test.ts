import { describe, expect, test, beforeEach, afterEach } from "bun:test";
import { startMockDaemon, type MockDaemonHandle } from "@trustforge-protocol/test-utils";
import { TrustForgeStrategy } from "../src/index.ts";

let daemon: MockDaemonHandle;

beforeEach(() => {
  daemon = startMockDaemon();
});
afterEach(async () => {
  await daemon.stop();
});

function harness(strategy: TrustForgeStrategy) {
  let outcome:
    | { kind: "success"; user: any }
    | { kind: "fail"; reason: any; status?: number }
    | { kind: "error"; err: Error }
    | { kind: "pass" }
    | null = null;
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  (strategy as any).success = (user: any) => {
    outcome = { kind: "success", user };
  };
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  (strategy as any).fail = (reason: any, status?: number) => {
    outcome = { kind: "fail", reason, status };
  };
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  (strategy as any).error = (err: Error) => {
    outcome = { kind: "error", err };
  };
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  (strategy as any).pass = () => {
    outcome = { kind: "pass" };
  };
  return () => outcome;
}

describe("@trustforge-protocol/passport", () => {
  test("strategy name is trustforge", () => {
    const s = new TrustForgeStrategy({ daemonUrl: daemon.url, quiet: true });
    expect(s.name).toBe("trustforge");
  });

  test("authenticate(): bearer header — happy path", async () => {
    const s = new TrustForgeStrategy({ daemonUrl: daemon.url, quiet: true });
    const get = harness(s);
    await s.authenticate({
      headers: { authorization: "Bearer some-opaque-token" },
    });
    const o = get()!;
    expect(o.kind).toBe("success");
    if (o.kind === "success") {
      expect(o.user.tfActor).toBeDefined();
      expect(o.user.tfTrustLevel).toBe("T2");
    }
  });

  test("authenticate(): missing credential calls fail()", async () => {
    const s = new TrustForgeStrategy({ daemonUrl: daemon.url, quiet: true });
    const get = harness(s);
    await s.authenticate({ headers: {} });
    const o = get()!;
    expect(o.kind).toBe("fail");
  });
});
