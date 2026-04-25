import { describe, expect, test } from "bun:test";
import {
  ApprovalQueue,
  QuorumApprovalCollector,
  type ApprovalRequest,
} from "../src/index";

const REQUEST: ApprovalRequest = {
  request_version: "1",
  id: "req-quorum-1",
  actor: "tf:actor:agent:example.com/code-helper",
  action: "payment.charge",
  reason: "approve $5000 vendor invoice",
  created_at: "2026-04-24T12:00:00Z",
};

describe("QuorumApprovalCollector", () => {
  test("approves once min_approvers signs", async () => {
    const queue = new ApprovalQueue();
    const collector = new QuorumApprovalCollector(queue, {
      min_approvers: 2,
      of: [
        "tf:actor:human:example.com/alice",
        "tf:actor:human:example.com/bob",
        "tf:actor:human:example.com/carol",
      ],
    });
    const handle = collector.push(REQUEST);
    handle.respondAs("tf:actor:human:example.com/alice", "approve", {
      algorithm: "ed25519",
      signature: "AAAA",
    });
    handle.respondAs("tf:actor:human:example.com/bob", "approve", {
      algorithm: "ed25519",
      signature: "BBBB",
    });
    const outcome = await handle.outcome;
    expect(outcome.decision).toBe("approve");
    expect(outcome.approvers.length).toBe(2);
    expect(outcome.ceremony.kind).toBe("quorum");
    expect(outcome.ceremony.signatures.length).toBe(2);
  });

  test("denies when entire eligible set fails to reach quorum", async () => {
    const queue = new ApprovalQueue();
    const collector = new QuorumApprovalCollector(queue, {
      min_approvers: 2,
      of: ["tf:actor:human:example.com/alice", "tf:actor:human:example.com/bob"],
    });
    const handle = collector.push(REQUEST);
    handle.respondAs("tf:actor:human:example.com/alice", "deny", {
      algorithm: "ed25519",
      signature: "X",
    });
    handle.respondAs("tf:actor:human:example.com/bob", "approve", {
      algorithm: "ed25519",
      signature: "Y",
    });
    const outcome = await handle.outcome;
    expect(outcome.decision).toBe("deny");
    expect(outcome.deniers.length).toBe(1);
    expect(outcome.approvers.length).toBe(1);
  });

  test("ignores responses from non-eligible actors", () => {
    const queue = new ApprovalQueue();
    const collector = new QuorumApprovalCollector(queue, {
      min_approvers: 2,
      of: ["tf:actor:human:example.com/alice", "tf:actor:human:example.com/bob"],
    });
    const handle = collector.push(REQUEST);
    const accepted = handle.respondAs(
      "tf:actor:human:example.com/mallory",
      "approve",
      { algorithm: "ed25519", signature: "X" },
    );
    expect(accepted).toBe(false);
  });

  test("rejects misconfigured quorum at construction time", () => {
    const queue = new ApprovalQueue();
    expect(
      () =>
        new QuorumApprovalCollector(queue, {
          min_approvers: 3,
          of: ["tf:actor:human:example.com/a", "tf:actor:human:example.com/b"],
        }),
    ).toThrow();
    expect(
      () =>
        new QuorumApprovalCollector(queue, {
          min_approvers: 0,
          of: ["tf:actor:human:example.com/a", "tf:actor:human:example.com/b"],
        }),
    ).toThrow();
  });

  test("ignores duplicate responses from the same actor", () => {
    const queue = new ApprovalQueue();
    const collector = new QuorumApprovalCollector(queue, {
      min_approvers: 2,
      of: ["tf:actor:human:example.com/alice", "tf:actor:human:example.com/bob"],
    });
    const handle = collector.push(REQUEST);
    expect(
      handle.respondAs("tf:actor:human:example.com/alice", "approve", {
        algorithm: "ed25519",
        signature: "1",
      }),
    ).toBe(true);
    expect(
      handle.respondAs("tf:actor:human:example.com/alice", "deny", {
        algorithm: "ed25519",
        signature: "2",
      }),
    ).toBe(false);
  });
});
