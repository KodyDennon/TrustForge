import { describe, expect, test } from "bun:test";
import { readFileSync } from "node:fs";
import { join } from "node:path";
import { parse as parseYAML } from "../src/core/yaml.js";
import { AgentGuard, type GuardDecision, type GuardEventStub } from "../src/core/guard";

type Expect = { kind: GuardDecision["kind"]; danger_tags?: string[] };
type Case = { name: string; query: { action: string; target?: string }; expect: Expect };

const REPO_ROOT = join(import.meta.dir, "..", "..", "..");
const VECTORS = parseYAML(readFileSync(join(REPO_ROOT, "conformance", "guard-vectors.yaml"), "utf8")) as {
  contract: Record<string, unknown>;
  cases: Case[];
};

describe("AgentGuard vectors", () => {
  for (const c of VECTORS.cases) {
    test(c.name, () => {
      const events: GuardEventStub[] = [];
      const guard = AgentGuard.fromContract(VECTORS.contract, { onEvent: (e) => events.push(e) });
      const decision = guard.check({ actor: "tf:actor:agent:example.com/test", ...c.query });
      expect(decision.kind).toBe(c.expect.kind);
      if (c.expect.danger_tags !== undefined) {
        expect(decision.danger_tags.sort()).toEqual(c.expect.danger_tags.sort());
      }
      expect(events[0]?.decision).toBe(c.expect.kind);
    });
  }
});
