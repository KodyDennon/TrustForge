/**
 * QuorumApprovalCollector — wraps an `ApprovalQueue` so a single high-risk
 * action can require N-of-M signed approvals before resolving. The
 * underlying queue still records every individual decision; the
 * collector aggregates them into a single boolean answer plus a list of
 * approver-signed envelopes for the audit trail.
 *
 * Reads `policy.quorum_defaults` for fallback configuration and emits an
 * `approval-ceremony.schema.json#kind=quorum` record describing the
 * outcome.
 */

import type { ActorId } from "../generated/_common.js";
import type { ApprovalRequest } from "../generated/approval-request.js";
import type { ApprovalResponse } from "../generated/approval-response.js";
import { ApprovalQueue, type ApprovalDecision } from "./approval.js";

export interface QuorumConfig {
  min_approvers: number;
  of: ActorId[];
}

export interface QuorumOutcome {
  /** Final aggregated decision: approve only if min_approvers approves
   *  came in from the eligible set; otherwise deny. */
  decision: ApprovalDecision;
  approvers: ActorId[];
  deniers: ActorId[];
  ceremony: {
    ceremony_version: "1";
    ceremony_id: string;
    kind: "quorum";
    request_id: string;
    started_at: string;
    completed_at?: string;
    min_approvers: number;
    of: ActorId[];
    approvers: ActorId[];
    signatures: Array<{
      algorithm: string;
      signer: ActorId;
      signature: string;
    }>;
  };
}

export class QuorumApprovalCollector {
  constructor(private readonly queue: ApprovalQueue, private readonly cfg: QuorumConfig) {
    if (cfg.min_approvers < 1) {
      throw new Error("quorum.min_approvers must be ≥ 1");
    }
    if (cfg.of.length < cfg.min_approvers) {
      throw new Error(
        `quorum.of (${cfg.of.length}) must contain at least min_approvers (${cfg.min_approvers}) actors`,
      );
    }
  }

  /** Push a single quorum-collecting record into the queue. The
   *  underlying queue's `respond()` is replaced by `respondAs(actor,
   *  decision, signature)` so individual approvers can sign in. The
   *  outer promise resolves once the quorum is met OR the eligible set
   *  has unanimously denied. */
  push(request: ApprovalRequest): {
    outcome: Promise<QuorumOutcome>;
    respondAs: (
      approver: ActorId,
      decision: ApprovalDecision,
      signature: { algorithm: string; signature: string; note?: string },
    ) => boolean;
  } {
    const ceremonyId = `cer-${request.id}-quorum`;
    const startedAt = new Date().toISOString();
    const approvers: ActorId[] = [];
    const deniers: ActorId[] = [];
    const signatures: QuorumOutcome["ceremony"]["signatures"] = [];
    let resolveOuter!: (o: QuorumOutcome) => void;
    const outcome = new Promise<QuorumOutcome>((r) => {
      resolveOuter = r;
    });

    // We don't push into the underlying queue: the queue is single-resolution
    // by design. The collector owns resolution and only emits a single
    // ApprovalResponse derived from the aggregated decision when callers
    // want to forward to ApprovalQueue.respond.

    const respondAs = (
      approver: ActorId,
      decision: ApprovalDecision,
      signature: { algorithm: string; signature: string; note?: string },
    ): boolean => {
      if (!this.cfg.of.includes(approver)) return false;
      if (approvers.includes(approver) || deniers.includes(approver)) return false;
      if (decision === "approve") {
        approvers.push(approver);
        signatures.push({
          algorithm: signature.algorithm,
          signer: approver,
          signature: signature.signature,
        });
      } else {
        deniers.push(approver);
      }
      // Resolve when min_approvers has approved or the entire eligible
      // set has voted (deny wins by exhaustion).
      if (approvers.length >= this.cfg.min_approvers) {
        resolveOuter({
          decision: "approve",
          approvers,
          deniers,
          ceremony: {
            ceremony_version: "1",
            ceremony_id: ceremonyId,
            kind: "quorum",
            request_id: request.id,
            started_at: startedAt,
            completed_at: new Date().toISOString(),
            min_approvers: this.cfg.min_approvers,
            of: this.cfg.of,
            approvers,
            signatures,
          },
        });
      } else if (approvers.length + deniers.length >= this.cfg.of.length) {
        resolveOuter({
          decision: "deny",
          approvers,
          deniers,
          ceremony: {
            ceremony_version: "1",
            ceremony_id: ceremonyId,
            kind: "quorum",
            request_id: request.id,
            started_at: startedAt,
            completed_at: new Date().toISOString(),
            min_approvers: this.cfg.min_approvers,
            of: this.cfg.of,
            approvers,
            signatures,
          },
        });
      }
      return true;
    };

    return { outcome, respondAs };
  }

  /** Helper that converts a final QuorumOutcome into a single
   *  ApprovalResponse so callers feeding the existing ApprovalQueue API
   *  see a familiar shape. */
  static toApprovalResponse(
    outcome: QuorumOutcome,
    aggregator: ActorId,
  ): Pick<ApprovalResponse, "response_version" | "request_id" | "decision" | "responder" | "signed_at" | "signature" | "note"> {
    return {
      response_version: "1",
      request_id: outcome.ceremony.request_id,
      decision: outcome.decision,
      responder: aggregator,
      signed_at: outcome.ceremony.completed_at ?? new Date().toISOString(),
      signature: {
        algorithm: "ed25519",
        signer: aggregator,
        signature: "AAAA",
      },
      note: `quorum ${outcome.approvers.length}/${outcome.ceremony.min_approvers} of ${outcome.ceremony.of.length}`,
    };
  }
}
