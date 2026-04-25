/**
 * Native TrustForge policy engine.
 *
 * Loads a `policy.schema.json` manifest and answers a `PolicyQuery` with
 * a `PolicyDecision`. The manifest is the authoritative input; rules are
 * evaluated top-to-bottom, with negative_capabilities applied first
 * (overriding any allow downstream) and `continuous_reevaluation` triggers
 * surfaced for callers (typically the RpcServer.reevaluate hook).
 *
 * The engine is intentionally pluggable: callers can swap in a Cedar or
 * Rego adapter by providing a `PolicyEngine` implementation. v0.1.0 ships
 * the native engine and adapter stubs that throw "not implemented" until
 * those backends are wired up.
 */

import type { Policy } from "../generated/policy.js";
import type { PolicyDecision } from "../generated/policy-decision.js";
import type {
  ActorId,
  ActionName,
  Capability,
  Constraint,
  EnforcementLevel,
  NegativeCapability,
  ProofLevel,
  Timestamp,
} from "../generated/_common.js";
import { sha256 } from "@noble/hashes/sha256";
import { canonicalize } from "./canonical.js";

export interface PolicyQuery {
  subject: ActorId;
  instance?: string;
  action: ActionName;
  target?: string;
  context?: Record<string, unknown>;
  /** Active negative capabilities for this evaluation. Engines apply
   *  these BEFORE walking the rules. */
  negativeCapabilities?: NegativeCapability[];
  /** Active enforcement level. Forwarded into the decision so audit
   *  logs preserve the runtime posture. */
  enforcementLevel?: EnforcementLevel;
  /** Wall-clock timestamp of the evaluation in RFC 3339; defaults to
   *  `new Date().toISOString()`. */
  now?: Timestamp;
}

export interface PolicyEngine {
  readonly engine: "native" | "cedar" | "rego" | "custom" | "none";
  evaluate(query: PolicyQuery): PolicyDecision;
}

export interface NativePolicyEngineOptions {
  policy: Policy;
  /** Optional capability bag the engine consults to ensure the subject
   *  even has authority to attempt the action. When unset, rules are
   *  the only authority surface. */
  grantedCapabilities?: Capability[];
}

export class NativePolicyEngine implements PolicyEngine {
  readonly engine = "native" as const;
  private readonly policy: Policy;
  private readonly manifestHash: string;
  private readonly granted: Capability[];

  constructor(opts: NativePolicyEngineOptions) {
    this.policy = opts.policy;
    this.manifestHash = `sha256-${toHex(sha256(canonicalize(this.policy as unknown)))}`;
    this.granted = opts.grantedCapabilities ?? [];
  }

  evaluate(query: PolicyQuery): PolicyDecision {
    const now = query.now ?? new Date().toISOString();
    const negativeCaps =
      query.negativeCapabilities ??
      ((this.policy as unknown as Record<string, unknown>)["negative_capabilities"] as
        | NegativeCapability[]
        | undefined) ??
      [];

    // 1. Negative caps win.
    for (const neg of negativeCaps) {
      if (negativeCapMatches(neg, query)) {
        return this.decision({
          query,
          decision: "deny",
          reason: neg.reason || `denied by negative_capability ${neg.name}`,
          ruleId: undefined,
          now,
          negCaps: negativeCaps,
        });
      }
    }

    // 2. Walk the rules in order; first match wins.
    for (const rule of this.policy.rules) {
      if (!ruleMatches(rule, query)) continue;
      const constraints = (rule as unknown as { constraints?: Constraint[] }).constraints ?? [];
      const reason =
        (rule as unknown as { reason?: string }).reason ?? `matched rule ${rule.id}`;
      const proof = (rule as unknown as { proof_required?: ProofLevel }).proof_required;
      const approval = (rule as unknown as { approval?: PolicyDecision["approval"] }).approval;
      switch (rule.effect) {
        case "allow":
          return this.decision({
            query,
            decision: "allow",
            reason,
            ruleId: rule.id,
            constraints,
            proof,
            approval,
            now,
            negCaps: negativeCaps,
          });
        case "deny":
          return this.decision({
            query,
            decision: "deny",
            reason,
            ruleId: rule.id,
            now,
            negCaps: negativeCaps,
          });
        case "escalate":
          return this.decision({
            query,
            decision: approval === "quorum" ? "escalate" : "approval-required",
            reason,
            ruleId: rule.id,
            constraints,
            proof,
            approval: approval ?? "required",
            now,
            negCaps: negativeCaps,
          });
        case "log_only":
          return this.decision({
            query,
            decision: "log-only",
            reason,
            ruleId: rule.id,
            constraints,
            proof,
            now,
            negCaps: negativeCaps,
          });
      }
    }

    // 3. Default deny — the policy did not match any rule.
    return this.decision({
      query,
      decision: "deny",
      reason: "no matching rule (default deny)",
      now,
      negCaps: negativeCaps,
    });
  }

  /** Triggers the policy declares for in-flight reevaluation. Callers
   *  forward these to the RpcServer's `continuousReevaluation` config. */
  continuousTriggers(): string[] {
    const cont = (this.policy as unknown as Record<string, unknown>)["continuous_reevaluation"];
    if (!cont || typeof cont !== "object") return [];
    const triggers = (cont as { triggers?: string[] }).triggers ?? [];
    return triggers.slice();
  }

  /** Quorum defaults from the manifest, if any. */
  quorumDefaults(): { min_approvers: number; of: ActorId[] } | undefined {
    const q = (this.policy as unknown as Record<string, unknown>)["quorum_defaults"];
    if (!q || typeof q !== "object") return undefined;
    return q as { min_approvers: number; of: ActorId[] };
  }

  /** Capabilities the engine was constructed with. Useful for callers
   *  that need to enforce capability-bearer checks alongside the rules. */
  grantedCapabilities(): Capability[] {
    return this.granted.slice();
  }

  private decision(params: {
    query: PolicyQuery;
    decision: PolicyDecision["decision"];
    reason: string;
    ruleId?: string;
    constraints?: Constraint[];
    proof?: ProofLevel;
    approval?: PolicyDecision["approval"];
    now: Timestamp;
    negCaps: NegativeCapability[];
  }): PolicyDecision {
    const out: PolicyDecision = {
      decision_version: "1",
      policy_engine: "native",
      engine_version: "tf-policy-native-0.1.0",
      trust_domain: this.policy.trust_domain,
      subject: params.query.subject,
      action: params.query.action,
      decision: params.decision,
      evaluated_at: params.now,
      policy_manifest_hash: this.manifestHash,
    };
    if (params.query.instance) out.instance = params.query.instance;
    if (params.query.target) out.target = params.query.target;
    if (params.ruleId) out.rule_id = params.ruleId;
    if (params.reason) out.reason = params.reason;
    if (params.constraints && params.constraints.length > 0) out.constraints_applied = params.constraints;
    if (params.proof) out.proof_required = params.proof;
    if (params.approval) out.approval = params.approval;
    if (params.query.enforcementLevel) out.enforcement_level = params.query.enforcementLevel;
    if (params.negCaps.length > 0) out.negative_capabilities_consulted = params.negCaps;
    if (params.query.context && Object.keys(params.query.context).length > 0) out.context = params.query.context;
    return out;
  }
}

function ruleMatches(
  rule: Policy["rules"][number],
  query: PolicyQuery,
): boolean {
  if ((rule as unknown as { action?: string }).action) {
    if ((rule as unknown as { action: string }).action !== query.action) return false;
  }
  const pattern = (rule as unknown as { action_pattern?: string }).action_pattern;
  if (pattern) {
    // Match through globMatch instead of `new RegExp` to:
    //   1. avoid catastrophic-backtracking ReDoS from untrusted policies
    //   2. give TS and Rust identical match semantics (both implement
    //      the same minimal `*` / `**` glob).
    if (!globMatch(pattern, query.action)) return false;
  }
  const subjectPattern = (rule as unknown as { subject_pattern?: string }).subject_pattern;
  if (subjectPattern) {
    if (!globMatch(subjectPattern, query.subject)) return false;
  }
  const targets = (rule as unknown as { target_patterns?: string[] }).target_patterns ?? [];
  if (targets.length > 0) {
    if (!query.target) return false;
    const hit = targets.some((p) => globMatch(p, query.target!));
    if (!hit) return false;
  }
  return true;
}

function negativeCapMatches(neg: NegativeCapability, q: PolicyQuery): boolean {
  // Negative-capability `name` is glob-matched against the action so
  // patterns like `fs.write*` cover `fs.write.tmp`. Pre-B8 the match
  // was `===`, which only blocked exact action names.
  if (!globMatch(neg.name, q.action)) return false;
  if (!neg.target) return true;
  if (!q.target) return false;
  return globMatch(neg.target, q.target);
}

function globMatch(pattern: string, value: string): boolean {
  let re = "^";
  for (let i = 0; i < pattern.length; i++) {
    const c = pattern[i]!;
    if (c === "*") {
      if (pattern[i + 1] === "*") {
        re += ".*";
        i += 1;
      } else {
        re += "[^/]*";
      }
    } else if (".+^${}()|[]\\?".includes(c)) {
      re += "\\" + c;
    } else {
      re += c;
    }
  }
  return new RegExp(re + "$").test(value);
}

function toHex(bytes: Uint8Array): string {
  let out = "";
  for (const b of bytes) out += b.toString(16).padStart(2, "0");
  return out;
}

/**
 * Cedar adapter stub. v0.1.0 ships the indirection so callers don't
 * have to refactor when the real Cedar runtime lands; until then the
 * engine returns a graceful deny so a misconfigured `engine_hint:
 * cedar` doesn't crash the daemon mid-RPC. Pre-B8 this threw, which
 * caused the daemon's enforcer to surface "internal: capability
 * enforcer threw" errors to clients.
 */
function unavailableDecision(engine: "cedar" | "rego", q: PolicyQuery): PolicyDecision {
  const out: PolicyDecision = {
    decision_version: "1",
    policy_engine: engine,
    engine_version: `${engine}-stub-0.1.0`,
    trust_domain: "unknown",
    subject: q.subject,
    action: q.action,
    decision: "deny",
    evaluated_at: new Date().toISOString(),
    reason: `${engine} adapter not implemented in v0.1.0; configure engine_hint: native or wait for the v0.2.0 ${engine}-wasm integration`,
  };
  if (q.target) out.target = q.target;
  if (q.enforcementLevel) out.enforcement_level = q.enforcementLevel;
  return out;
}

export class CedarPolicyEngine implements PolicyEngine {
  readonly engine = "cedar" as const;
  evaluate(q: PolicyQuery): PolicyDecision {
    return unavailableDecision("cedar", q);
  }
}

/** Rego adapter — same graceful-deny shape as Cedar's. */
export class RegoPolicyEngine implements PolicyEngine {
  readonly engine = "rego" as const;
  evaluate(q: PolicyQuery): PolicyDecision {
    return unavailableDecision("rego", q);
  }
}

/** Build the right engine for a manifest's `engine_hint`. */
export function policyEngineForManifest(policy: Policy, opts: { grantedCapabilities?: Capability[] } = {}): PolicyEngine {
  const hint = (policy as unknown as { engine_hint?: string }).engine_hint;
  switch (hint) {
    case "cedar":
      return new CedarPolicyEngine();
    case "rego":
      return new RegoPolicyEngine();
    case "native":
    case "custom":
    case "none":
    case undefined:
      return new NativePolicyEngine({ policy, grantedCapabilities: opts.grantedCapabilities });
    default:
      throw new Error(`unsupported engine_hint: ${hint}`);
  }
}
