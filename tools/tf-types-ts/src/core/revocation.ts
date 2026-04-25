import type { Revocation } from "../generated/revocation.js";

export type RevocationTargetKind = Revocation["target_kind"];

export interface RevocationQuery {
  readonly id: string;
  readonly kind: RevocationTargetKind;
}

export class RevocationIndex {
  private readonly byKind: Map<RevocationTargetKind, Map<string, Revocation>>;

  private constructor(byKind: Map<RevocationTargetKind, Map<string, Revocation>>) {
    this.byKind = byKind;
  }

  static from(revocations: readonly Revocation[]): RevocationIndex {
    const byKind = new Map<RevocationTargetKind, Map<string, Revocation>>();
    for (const r of revocations) {
      let bucket = byKind.get(r.target_kind);
      if (!bucket) {
        bucket = new Map();
        byKind.set(r.target_kind, bucket);
      }
      const existing = bucket.get(r.target_id);
      if (!existing || existing.effective_at > r.effective_at) {
        bucket.set(r.target_id, r);
      }
    }
    return new RevocationIndex(byKind);
  }

  isRevoked(target: RevocationQuery, at: string): boolean {
    const bucket = this.byKind.get(target.kind);
    if (!bucket) return false;
    const r = bucket.get(target.id);
    if (!r) return false;
    return r.effective_at <= at;
  }
}
