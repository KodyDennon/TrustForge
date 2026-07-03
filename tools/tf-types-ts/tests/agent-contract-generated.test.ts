import { describe, expect, test } from "bun:test";
import {
  CONTRACT,
  FILE_READ_META,
  SHELL_EXEC_META,
  checkAction,
  createAgentGuard,
  type Action,
} from "../src/generated/agent-contract/exampleappfullcontract";

describe("generated agent-contract bindings", () => {
  test("CONTRACT has expected project id", () => {
    expect(CONTRACT.project).toBe("example-app-full");
  });

  test("Action type includes declared actions", () => {
    const a1: Action = "file.read";
    const a2: Action = "shell.exec";
    expect(a1).toBe("file.read");
    expect(a2).toBe("shell.exec");
  });

  test("per-action metadata exports danger_tags and approval", () => {
    expect(FILE_READ_META.danger_tags).toEqual(["privacy"]);
    expect(SHELL_EXEC_META.danger_tags).toContain("destructive");
    expect(SHELL_EXEC_META.approval).toBe("required");
  });

  test("createAgentGuard produces a working guard", () => {
    const guard = createAgentGuard();
    const decision = checkAction(guard, "file.read", "src/main.ts");
    expect(decision.kind).toBe("allow");
    const denied = checkAction(guard, "file.read", ".env");
    expect(denied.kind).toBe("deny");
    const escalated = checkAction(guard, "shell.exec");
    expect(escalated.kind).toBe("escalate");
  });
});
