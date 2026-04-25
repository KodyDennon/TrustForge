/**
 * Approval queue. A promise-based FIFO where the daemon pushes a request
 * and awaits a human-supplied response (with a default-deny timeout).
 */

import type { ApprovalRequest } from "../generated/approval-request.js";

export type ApprovalDecision = "approve" | "deny";

export interface ApprovalRecord {
  request: ApprovalRequest;
  resolve: (decision: ApprovalDecision, note?: string) => void;
  timeout?: ReturnType<typeof setTimeout>;
}

export interface ApprovalQueueOptions {
  maxPending?: number;
  defaultTimeoutMs?: number;
  onPush?: (request: ApprovalRequest) => void;
  onResolve?: (request: ApprovalRequest, decision: ApprovalDecision, note?: string) => void;
}

export class ApprovalQueueFullError extends Error {}
export class ApprovalQueueDuplicateError extends Error {}

export class ApprovalQueue {
  private pending = new Map<string, ApprovalRecord>();

  constructor(private readonly opts: ApprovalQueueOptions = {}) {}

  push(request: ApprovalRequest): Promise<{ decision: ApprovalDecision; note?: string }> {
    const max = this.opts.maxPending ?? 32;
    if (this.pending.size >= max) {
      throw new ApprovalQueueFullError(`approval queue is full (max ${max})`);
    }
    if (this.pending.has(request.id)) {
      // Pre-B6 a re-push silently orphaned the prior promise (it would
      // hang until its timeout fired). Reject the new push instead.
      throw new ApprovalQueueDuplicateError(
        `approval request ${request.id} is already pending`,
      );
    }
    return new Promise((resolve) => {
      const record: ApprovalRecord = {
        request,
        resolve: (decision, note) => {
          if (record.timeout) clearTimeout(record.timeout);
          this.pending.delete(request.id);
          this.opts.onResolve?.(request, decision, note);
          resolve({ decision, note });
        },
      };
      const timeoutMs = this.opts.defaultTimeoutMs ?? 300_000;
      record.timeout = setTimeout(
        () => record.resolve("deny", "timeout"),
        timeoutMs,
      );
      this.pending.set(request.id, record);
      this.opts.onPush?.(request);
    });
  }

  respond(requestId: string, decision: ApprovalDecision, note?: string): boolean {
    const record = this.pending.get(requestId);
    if (!record) return false;
    record.resolve(decision, note);
    return true;
  }

  list(): ApprovalRequest[] {
    return [...this.pending.values()].map((r) => r.request);
  }

  size(): number {
    return this.pending.size;
  }

  /** Cancel every pending approval with a "deny: shutdown" response. */
  drainDeny(reason = "queue shutting down"): void {
    for (const record of [...this.pending.values()]) {
      record.resolve("deny", reason);
    }
  }
}
