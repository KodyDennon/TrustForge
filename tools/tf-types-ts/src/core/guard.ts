/**
 * AgentGuard — declarative contract interpreter.
 *
 * Built from a parsed agent-contract YAML object plus optional policy
 * overlay (negative capabilities + enforcement level). Answers whether a
 * given action is allowed against a target for a caller, returning a
 * structured GuardDecision.
 *
 * Decision precedence (highest first):
 *   1. negative_capabilities — explicit denials override everything
 *   2. forbidden — contract-level blacklist
 *   3. unknown action — deny
 *   4. deny_targets — target blacklist for the action
 *   5. allow_targets — target whitelist (deny if non-empty and miss)
 *   6. danger-tag escalation
 *   7. approval requirement
 *   8. allow
 *
 * Decisions then pass through an EnforcementLevel filter (E0–E5 per
 * DECISIONS.md) which can soften denies into log-only / warn at low
 * levels or harden allows into escalations / denies at high levels.
 */

import type { AgentContract } from "../generated/agent-contract.js";
import type { EnforcementLevel, NegativeCapability } from "../generated/_common.js";

export type GuardDecision =
  | { kind: "allow"; danger_tags: string[] }
  | { kind: "approval-required"; approval: string; reason: string; danger_tags: string[] }
  | { kind: "escalate"; reason: string; danger_tags: string[] }
  | { kind: "deny"; reason: string; danger_tags: string[] }
  | { kind: "log-only"; reason: string; danger_tags: string[] };

export interface GuardQuery {
  /** Cryptographic, key-derived caller URI. Authoritative. */
  actor?: string;
  /** Self-claimed peer_hint URI. Advisory; matched alongside `actor` against
   *  allow_actors / deny_actors. */
  actor_claim?: string;
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
  enforcement_level?: EnforcementLevel;
}

export interface GuardOptions {
  onEvent?: (ev: GuardEventStub) => void;
  /** Default E4 (block unauthorized action). Per DECISIONS.md:
   *  E0 observe-only, E1 warn-only, E2 require-proof-logging,
   *  E3 require-policy-approval, E4 block, E5 fail-closed. */
  enforcementLevel?: EnforcementLevel;
  /** Optional list of negative capabilities to apply globally. They win
   *  over every allow path. */
  negativeCapabilities?: NegativeCapability[];
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
  allow_actors: string[];
  deny_actors: string[];
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
  private enforcementLevel: EnforcementLevel;
  private negativeCapabilities: NegativeCapability[];

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
    this.enforcementLevel = opts.enforcementLevel ?? "E4";
    this.negativeCapabilities = (opts.negativeCapabilities ?? []).slice();
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
      allow_actors: ((a.allow_actors as string[] | undefined) ?? []).slice(),
      deny_actors: ((a.deny_actors as string[] | undefined) ?? []).slice(),
    }));
    const forbidden = new Map<string, string>();
    for (const f of (c.forbidden as Record<string, unknown>[] | undefined) ?? []) {
      forbidden.set(String(f.action), String(f.reason ?? ""));
    }
    const targetSets = (c.target_sets as Record<string, string[]> | undefined) ?? {};
    return new AgentGuard(actions, forbidden, targetSets, opts);
  }

  /** Exposed for callers (RpcServer, dashboard) that need to know which
   *  level the guard is currently running under — e.g. to format the
   *  "shadow mode" banner or skip an enforcement gate. */
  getEnforcementLevel(): EnforcementLevel {
    return this.enforcementLevel;
  }

  /** Replace the negative-capability list (e.g. when policy reloads
   *  trigger continuous reevaluation). */
  setNegativeCapabilities(caps: NegativeCapability[]): void {
    this.negativeCapabilities = caps.slice();
  }

  /** Replace the enforcement level (e.g. when shadow-mode toggles). */
  setEnforcementLevel(level: EnforcementLevel): void {
    this.enforcementLevel = level;
  }

  check(query: GuardQuery): GuardDecision {
    const raw = this.checkRaw(query);
    const adjusted = applyEnforcementLevel(raw, this.enforcementLevel);
    const actor = query.actor ?? "tf:actor:process:local/unknown";
    this.emit(adjusted, actor, query);
    return adjusted;
  }

  /** Run the rule logic without applying the EnforcementLevel filter.
   *  Useful for shadow-mode dashboards that want to display the "real"
   *  decision the rules produced before being softened or hardened. */
  checkRaw(query: GuardQuery): GuardDecision {
    // 1. Negative capabilities take absolute precedence.
    for (const neg of this.negativeCapabilities) {
      if (negativeMatches(neg, query)) {
        return {
          kind: "deny",
          reason: neg.reason || `action ${query.action} is denied by negative_capability`,
          danger_tags: ["explicit-denial"],
        };
      }
    }

    const forbiddenReason = this.forbiddenByName.get(query.action);
    if (forbiddenReason !== undefined) {
      return {
        kind: "deny",
        reason: forbiddenReason || "action listed in forbidden",
        danger_tags: [],
      };
    }

    const action = this.actionByName.get(query.action);
    if (!action) {
      return {
        kind: "deny",
        reason: `action "${query.action}" is not declared`,
        danger_tags: [],
      };
    }

    const tags = action.danger_tags.slice();

    // Actor-scope: deny_actors wins over allow_actors. Both lists are matched
    // against the cryptographic actor URI AND the self-claimed peer_hint URI;
    // a hit on either form blocks (deny) or unblocks (allow). Empty lists
    // mean "no restriction".
    const callerActor = query.actor;
    const callerClaim = query.actor_claim;
    if (callerActor !== undefined) {
      for (const pattern of action.deny_actors) {
        if (globMatch(pattern, callerActor) || (callerClaim !== undefined && globMatch(pattern, callerClaim))) {
          return {
            kind: "deny",
            reason: `actor ${callerActor} matches deny_actors (${pattern})`,
            danger_tags: tags,
          };
        }
      }
      if (action.allow_actors.length > 0) {
        const matches = action.allow_actors.some(
          (p) => globMatch(p, callerActor) || (callerClaim !== undefined && globMatch(p, callerClaim)),
        );
        if (!matches) {
          return {
            kind: "deny",
            reason: `actor ${callerActor} not in allow_actors`,
            danger_tags: tags,
          };
        }
      }
    } else if (action.allow_actors.length > 0) {
      // Action restricts callers but no actor was supplied — fail closed.
      return {
        kind: "deny",
        reason: `action ${action.name} requires an authenticated actor`,
        danger_tags: tags,
      };
    }

    if (query.target) {
      for (const pattern of action.deny_targets) {
        if (this.matchTarget(pattern, query.target)) {
          return {
            kind: "deny",
            reason: `target ${query.target} is in deny_targets (${pattern})`,
            danger_tags: tags,
          };
        }
      }
      if (action.allow_targets.length > 0) {
        const allowed = action.allow_targets.some((p) => this.matchTarget(p, query.target!));
        if (!allowed) {
          return {
            kind: "deny",
            reason: `target ${query.target} is not in allow_targets`,
            danger_tags: tags,
          };
        }
      }
    }

    // Escalation on danger tags regardless of declared approval.
    const shouldEscalate = tags.some((t) => ESCALATE_TAGS.has(t));
    if (shouldEscalate) {
      return {
        kind: "escalate",
        reason: `danger_tags require escalation: ${tags.filter((t) => ESCALATE_TAGS.has(t)).join(", ")}`,
        danger_tags: tags,
      };
    }

    if (action.approval === "required" || action.approval === "quorum") {
      return {
        kind: "approval-required",
        approval: action.approval,
        reason: `action "${query.action}" requires approval`,
        danger_tags: tags,
      };
    }

    return { kind: "allow", danger_tags: tags };
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
      enforcement_level: this.enforcementLevel,
    });
  }
}

/** Apply the EnforcementLevel filter described in DECISIONS.md "Progressive
 *  enforcement levels are core". Maps the raw rule decision to the actual
 *  decision the caller will execute against. */
export function applyEnforcementLevel(
  raw: GuardDecision,
  level: EnforcementLevel,
): GuardDecision {
  switch (level) {
    case "E0": {
      // Observe only — never block, never escalate.
      if (raw.kind === "deny" || raw.kind === "escalate" || raw.kind === "approval-required") {
        return {
          kind: "log-only",
          reason: `[shadow] would have ${raw.kind}: ${reasonOf(raw)}`,
          danger_tags: raw.danger_tags.concat(["shadow"]),
        };
      }
      return raw;
    }
    case "E1": {
      // Warn only — denies become allow + warning tag; escalations stay
      // visible but don't block.
      if (raw.kind === "deny") {
        return {
          kind: "allow",
          danger_tags: raw.danger_tags.concat(["warn", `would-deny:${reasonOf(raw)}`]),
        };
      }
      if (raw.kind === "escalate") {
        return {
          kind: "log-only",
          reason: `[warn] ${reasonOf(raw)}`,
          danger_tags: raw.danger_tags.concat(["warn"]),
        };
      }
      return raw;
    }
    case "E2": {
      // Require proof logging — pass through; the daemon must persist
      // every decision to a `.tflog` and refuse to run if logging fails.
      // Tag the decision so callers know logging is mandatory.
      return tagDecision(raw, "proof-log-required");
    }
    case "E3": {
      // Require policy approval — any allow with a danger tag becomes an
      // escalation. Plain allows pass through.
      if (raw.kind === "allow" && raw.danger_tags.length > 0) {
        return {
          kind: "escalate",
          reason: `E3 escalates allow with danger tags: ${raw.danger_tags.join(", ")}`,
          danger_tags: raw.danger_tags,
        };
      }
      return raw;
    }
    case "E4": {
      // Default — pass through.
      return raw;
    }
    case "E5": {
      // Fail-closed — every escalation and approval becomes a hard deny;
      // every allow with any danger tag becomes a deny.
      if (raw.kind === "escalate" || raw.kind === "approval-required") {
        return {
          kind: "deny",
          reason: `E5 fail-closed: ${reasonOf(raw)}`,
          danger_tags: raw.danger_tags,
        };
      }
      if (raw.kind === "allow" && raw.danger_tags.length > 0) {
        return {
          kind: "deny",
          reason: `E5 fail-closed: allow with danger tags ${raw.danger_tags.join(", ")} blocked`,
          danger_tags: raw.danger_tags,
        };
      }
      return raw;
    }
  }
}

function reasonOf(d: GuardDecision): string {
  if (d.kind === "allow") return "allow";
  return d.reason;
}

function tagDecision(d: GuardDecision, tag: string): GuardDecision {
  if (d.kind === "allow") {
    return { kind: "allow", danger_tags: d.danger_tags.concat([tag]) };
  }
  return { ...d, danger_tags: d.danger_tags.concat([tag]) };
}

function negativeMatches(neg: NegativeCapability, q: GuardQuery): boolean {
  // Negative-capability `name` is glob-matched (post-B8). Pre-B8 the
  // match was `===`, which only blocked exact action names — patterns
  // like "fs.write*" failed to cover "fs.write.tmp".
  if (!globMatch(neg.name, q.action)) return false;
  if (!neg.target) return true;
  if (!q.target) return false;
  return globMatch(neg.target, q.target);
}

function globMatch(pattern: string, value: string): boolean {
  // Minimal glob: `*` matches non-`/` chars, `**` matches any.
  // Every other regex meta character — including `?`, which pre-B8 was
  // passed through as the regex zero-or-one quantifier and made
  // `tf:actor:user?` match `tf:actor:use` — is escaped.
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
    } else if (".+^${}()|[]\\?".includes(c)) {
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
