import type { Capability, Constraint } from "../generated/_common.js";

export interface EvalContext {
  readonly now: string;
  readonly session_id?: string;
  readonly target?: string;
  readonly approver_count?: number;
  readonly device_actor?: string;
}

export function isCapability(x: unknown): x is Capability {
  if (!x || typeof x !== "object") return false;
  const c = x as Record<string, unknown>;
  return typeof c.name === "string" && typeof c.risk === "string";
}

/**
 * Check whether every constraint is satisfied by the evaluation context.
 * Unknown constraint kinds are treated as unsatisfied (fail-closed).
 */
export function constraintsSatisfied(constraints: readonly Constraint[], ctx: EvalContext): boolean {
  return constraints.every((c) => satisfies(c, ctx));
}

function satisfies(c: Constraint, ctx: EvalContext): boolean {
  switch (c.kind) {
    case "time_window": {
      if (c.from && ctx.now < c.from) return false;
      if (ctx.now > c.until) return false;
      return true;
    }
    case "target": {
      if (!ctx.target) return false;
      return c.patterns.some((p) => matchesGlob(p, ctx.target!));
    }
    case "quantity":
      return true; // requires external counter; out-of-scope for constraint evaluation
    case "rate":
      return true; // same
    case "session":
      return ctx.session_id === c.session_id;
    case "approval":
      return c.approval === "none" || c.approval === "conditional";
    case "quorum": {
      const required = c.quorum;
      const have = ctx.approver_count ?? 0;
      return have >= required;
    }
    case "device_binding":
      return ctx.device_actor === c.device_actor;
    default: {
      // exhaustiveness: unknown kinds fail closed
      return false;
    }
  }
}

/**
 * Intersect two constraint sets: the result holds iff both input sets hold.
 * This is strictly shrinking — intersecting an already-satisfying set with
 * a weaker one drops nothing.
 */
export function intersectConstraints(a: readonly Constraint[], b: readonly Constraint[]): Constraint[] {
  const out: Constraint[] = [...a];
  for (const nc of b) {
    const idx = out.findIndex((c) => c.kind === nc.kind);
    if (idx < 0) {
      out.push(nc);
      continue;
    }
    out[idx] = intersectSame(out[idx]!, nc);
  }
  return out;
}

function intersectSame(a: Constraint, b: Constraint): Constraint {
  if (a.kind !== b.kind) return a; // caller ensures same kind
  switch (a.kind) {
    case "time_window": {
      const bw = b as Extract<Constraint, { kind: "time_window" }>;
      const from = pickLater(a.from, bw.from);
      const until = pickEarlier(a.until, bw.until);
      return { kind: "time_window", from, until } as Constraint;
    }
    case "target": {
      const bw = b as Extract<Constraint, { kind: "target" }>;
      const patterns = a.patterns.filter((p) => bw.patterns.includes(p));
      return { kind: "target", patterns: patterns.length ? patterns : a.patterns.concat(bw.patterns) } as Constraint;
    }
    case "quantity": {
      const bw = b as Extract<Constraint, { kind: "quantity" }>;
      return { kind: "quantity", max: Math.min(a.max, bw.max), unit: a.unit ?? bw.unit } as Constraint;
    }
    case "rate": {
      const bw = b as Extract<Constraint, { kind: "rate" }>;
      return {
        kind: "rate",
        max_per_window: Math.min(a.max_per_window, bw.max_per_window),
        window_seconds: Math.min(a.window_seconds, bw.window_seconds),
      } as Constraint;
    }
    case "quorum": {
      const bw = b as Extract<Constraint, { kind: "quorum" }>;
      return { kind: "quorum", quorum: Math.max(a.quorum, bw.quorum), of: a.of } as Constraint;
    }
    default:
      return a;
  }
}

function pickLater(a?: string, b?: string): string | undefined {
  if (!a) return b;
  if (!b) return a;
  return a > b ? a : b;
}

function pickEarlier(a: string, b: string): string {
  return a < b ? a : b;
}

function matchesGlob(pattern: string, value: string): boolean {
  // minimal glob: `*` matches any non-`/` chars, `**` matches anything.
  const re = "^" + pattern
    .replace(/[.+^${}()|[\]\\]/g, "\\$&")
    .replace(/\*\*/g, "__DOUBLE_STAR__")
    .replace(/\*/g, "[^/]*")
    .replace(/__DOUBLE_STAR__/g, ".*")
    + "$";
  return new RegExp(re).test(value);
}
