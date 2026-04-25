import { describe, expect, test } from "bun:test";
import type { ApprovalRequest } from "../src/generated/approval-request";
import { ApprovalQueue, ApprovalQueueFullError } from "../src/core/approval";

function req(id: string): ApprovalRequest {
  return {
    request_version: "1",
    id,
    actor: "tf:actor:agent:example.com/a",
    action: "shell.exec",
    reason: "just because",
    created_at: "2026-04-24T13:00:00Z",
  };
}

describe("ApprovalQueue", () => {
  test("approve resolves the pending promise", async () => {
    const queue = new ApprovalQueue({ defaultTimeoutMs: 10_000 });
    const promise = queue.push(req("r1"));
    expect(queue.size()).toBe(1);
    queue.respond("r1", "approve", "OK");
    const result = await promise;
    expect(result.decision).toBe("approve");
    expect(result.note).toBe("OK");
    expect(queue.size()).toBe(0);
  });

  test("deny resolves with deny", async () => {
    const queue = new ApprovalQueue({ defaultTimeoutMs: 10_000 });
    const promise = queue.push(req("r2"));
    queue.respond("r2", "deny", "no thanks");
    const result = await promise;
    expect(result.decision).toBe("deny");
  });

  test("timeout defaults to deny", async () => {
    const queue = new ApprovalQueue({ defaultTimeoutMs: 30 });
    const promise = queue.push(req("r3"));
    const result = await promise;
    expect(result.decision).toBe("deny");
    expect(result.note).toBe("timeout");
  });

  test("max-pending throws when full", async () => {
    const queue = new ApprovalQueue({ maxPending: 1, defaultTimeoutMs: 10_000 });
    void queue.push(req("a"));
    expect(() => queue.push(req("b"))).toThrow(ApprovalQueueFullError);
  });

  test("drainDeny resolves every outstanding request", async () => {
    const queue = new ApprovalQueue({ defaultTimeoutMs: 10_000 });
    const a = queue.push(req("a"));
    const b = queue.push(req("b"));
    queue.drainDeny("shutdown");
    expect((await a).decision).toBe("deny");
    expect((await b).decision).toBe("deny");
    expect(queue.size()).toBe(0);
  });
});
