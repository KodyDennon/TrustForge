import type { Constraint, DelegationLink } from "../generated/_common.js";
import { intersectConstraints } from "./capability.js";

export interface WalkResult {
  readonly valid: boolean;
  readonly effective: Constraint[];
  readonly expiredAt?: string;
  readonly brokenStep?: number;
  readonly reason?: string;
}

/**
 * Walk a delegation chain left-to-right (root at index 0) at time `now`.
 *
 * - If any link's `expires_at` is in the past, the chain is invalid from
 *   that step onward.
 * - Redelegation rules are enforced: a step that disallows redelegation
 *   breaks the chain at the *next* step.
 * - The effective constraint set is the intersection of all step constraints.
 */
export function walkChain(chain: readonly DelegationLink[], now: string): WalkResult {
  let effective: Constraint[] = [];
  let allowRedelegation = true;
  let maxDepthRemaining = Number.POSITIVE_INFINITY;

  for (let i = 0; i < chain.length; i++) {
    const step = chain[i]!;
    if (i > 0) {
      if (!allowRedelegation) {
        return {
          valid: false,
          effective,
          brokenStep: i,
          reason: `step ${i - 1} disallows redelegation`,
        };
      }
      if (maxDepthRemaining <= 0) {
        return {
          valid: false,
          effective,
          brokenStep: i,
          reason: `max_depth exceeded at step ${i}`,
        };
      }
      maxDepthRemaining -= 1;
    }
    if (step.expires_at && step.expires_at < now) {
      return {
        valid: false,
        effective,
        brokenStep: i,
        expiredAt: step.expires_at,
        reason: `step ${i} expired at ${step.expires_at}`,
      };
    }
    if (step.constraints && step.constraints.length > 0) {
      effective = intersectConstraints(effective, step.constraints);
    }
    const redelegation = step.redelegation as
      | { allowed?: unknown; max_depth?: unknown }
      | undefined;
    if (redelegation) {
      allowRedelegation = redelegation.allowed === true;
      if (typeof redelegation.max_depth === "number") {
        maxDepthRemaining = Math.min(maxDepthRemaining, redelegation.max_depth);
      }
    } else {
      allowRedelegation = true;
    }
  }

  return { valid: true, effective };
}
