/**
 * AgentGuard — declarative contract interpreter.
 *
 * Built from a parsed agent-contract YAML object; answers whether a given
 * action is allowed against a target for a caller, returning a structured
 * GuardDecision. Forbidden list wins; deny_targets win over allow_targets;
 * danger_tags are surfaced on every decision so UIs can escalate.
 */

import type { AgentContract } from "../generated/agent-contract.js";

export type GuardDecision =
  | { kind: "allow"; danger_tags: string[] }
  | { kind: "approval-required"; approval: string; reason: string; danger_tags: string[] }
  | { kind: "escalate"; reason: string; danger_tags: string[] }
  | { kind: "deny"; reason: string; danger_tags: string[] };

export interface GuardQuery {
  actor?: string;
  action: string;
  target?: string;
  context?: Record<string, unknown>;
}

export interface GuardEventStub {
  type: "guard.check";
  actor: string;
  action: string;
  target?: string;
  decision: GuardDecision["kind"];
  danger_tags: string[];
}

export interface GuardOptions {
  onEvent?: (ev: GuardEventStub) => void;
}

interface IndexedAction {
  name: string;
  risk: string;
  approval?: string;
  proof?: string;
  reversible?: boolean;
  danger_tags: string[];
  allow_targets: string[];
  deny_targets: string[];
}

const ESCALATE_TAGS = new Set<string>([
  "destructive",
  "irreversible",
  "financial",
  "security-sensitive",
  "legal-exposure",
]);

export class AgentGuard {
  private actionByName: Map<string, IndexedAction>;
  private forbiddenByName: Map<string, string>;
  private targetSets: Record<string, string[]>;
  private onEvent?: (ev: GuardEventStub) => void;

  private constructor(
    actions: IndexedAction[],
    forbidden: Map<string, string>,
    targetSets: Record<string, string[]>,
    opts: GuardOptions,
  ) {
    this.actionByName = new Map(actions.map((a) => [a.name, a]));
    this.forbiddenByName = forbidden;
    this.targetSets = targetSets;
    this.onEvent = opts.onEvent;
  }

  static fromContract(contract: AgentContract | Record<string, unknown>, opts: GuardOptions = {}): AgentGuard {
    const c = contract as Record<string, unknown>;
    const rawActions = (c.actions as Record<string, unknown>[] | undefined) ?? [];
    const actions: IndexedAction[] = rawActions.map((a) => ({
      name: String(a.name),
      risk: String(a.risk),
      approval: a.approval as string | undefined,
      proof: a.proof as string | undefined,
      reversible: a.reversible as boolean | undefined,
      danger_tags: ((a.danger_tags as string[] | undefined) ?? []).slice(),
      allow_targets: ((a.allow_targets as string[] | undefined) ?? []).slice(),
      deny_targets: ((a.deny_targets as string[] | undefined) ?? []).slice(),
    }));
    const forbidden = new Map<string, string>();
    for (const f of (c.forbidden as Record<string, unknown>[] | undefined) ?? []) {
      forbidden.set(String(f.action), String(f.reason ?? ""));
    }
    const targetSets = (c.target_sets as Record<string, string[]> | undefined) ?? {};
    return new AgentGuard(actions, forbidden, targetSets, opts);
  }

  check(query: GuardQuery): GuardDecision {
    const actor = query.actor ?? "tf:actor:process:local/unknown";
    const forbiddenReason = this.forbiddenByName.get(query.action);
    if (forbiddenReason !== undefined) {
      const decision: GuardDecision = {
        kind: "deny",
        reason: forbiddenReason || "action listed in forbidden",
        danger_tags: [],
      };
      this.emit(decision, actor, query);
      return decision;
    }

    const action = this.actionByName.get(query.action);
    if (!action) {
      const decision: GuardDecision = {
        kind: "deny",
        reason: `action "${query.action}" is not declared`,
        danger_tags: [],
      };
      this.emit(decision, actor, query);
      return decision;
    }

    const tags = action.danger_tags.slice();

    if (query.target) {
      for (const pattern of action.deny_targets) {
        if (this.matchTarget(pattern, query.target)) {
          const decision: GuardDecision = {
            kind: "deny",
            reason: `target ${query.target} is in deny_targets (${pattern})`,
            danger_tags: tags,
          };
          this.emit(decision, actor, query);
          return decision;
        }
      }
      if (action.allow_targets.length > 0) {
        const allowed = action.allow_targets.some((p) => this.matchTarget(p, query.target!));
        if (!allowed) {
          const decision: GuardDecision = {
            kind: "deny",
            reason: `target ${query.target} is not in allow_targets`,
            danger_tags: tags,
          };
          this.emit(decision, actor, query);
          return decision;
        }
      }
    }

    // Escalation on danger tags regardless of declared approval.
    const shouldEscalate = tags.some((t) => ESCALATE_TAGS.has(t));
    if (shouldEscalate) {
      const decision: GuardDecision = {
        kind: "escalate",
        reason: `danger_tags require escalation: ${tags.filter((t) => ESCALATE_TAGS.has(t)).join(", ")}`,
        danger_tags: tags,
      };
      this.emit(decision, actor, query);
      return decision;
    }

    if (action.approval === "required" || action.approval === "quorum") {
      const decision: GuardDecision = {
        kind: "approval-required",
        approval: action.approval,
        reason: `action "${query.action}" requires approval`,
        danger_tags: tags,
      };
      this.emit(decision, actor, query);
      return decision;
    }

    const decision: GuardDecision = { kind: "allow", danger_tags: tags };
    this.emit(decision, actor, query);
    return decision;
  }

  private matchTarget(pattern: string, value: string): boolean {
    if (pattern.startsWith("@")) {
      const set = this.targetSets[pattern.slice(1)] ?? [];
      return set.some((p) => globMatch(p, value));
    }
    return globMatch(pattern, value);
  }

  private emit(decision: GuardDecision, actor: string, query: GuardQuery): void {
    if (!this.onEvent) return;
    this.onEvent({
      type: "guard.check",
      actor,
      action: query.action,
      target: query.target,
      decision: decision.kind,
      danger_tags: decision.danger_tags,
    });
  }
}

function globMatch(pattern: string, value: string): boolean {
  // Minimal glob: `*` matches non-`/` chars, `**` matches any.
  let re = "^";
  let i = 0;
  while (i < pattern.length) {
    const c = pattern[i]!;
    if (c === "*") {
      if (pattern[i + 1] === "*") {
        re += ".*";
        i += 2;
      } else {
        re += "[^/]*";
        i += 1;
      }
    } else if (".+^${}()|[]\\".includes(c)) {
      re += "\\" + c;
      i += 1;
    } else {
      re += c;
      i += 1;
    }
  }
  re += "$";
  return new RegExp(re).test(value);
}
