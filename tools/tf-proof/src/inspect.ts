import { readFileSync } from "node:fs";
import {
  canonicalize,
  eventHash,
  readTfproof,
  readTflog,
  TFLOG_MAGIC,
  TFPROOF_MAGIC,
} from "@trustforge-protocol/types";
import type { ProofEvent } from "@trustforge-protocol/types";

export interface InspectOutput {
  format: "tfproof" | "tflog";
  path: string;
  size_bytes: number;
  events: {
    count: number;
    head_id?: string;
    head_hash?: string;
    tail_id?: string;
    tail_hash?: string;
  };
  bundle?: {
    bundle_version: string;
    merkle_root?: string;
    chain_hash?: string;
    transparency_anchor?: unknown;
    signer?: string;
    algorithm?: string;
  };
}

export function inspectFile(path: string, dumpEvents: boolean): string {
  const bytes = new Uint8Array(readFileSync(path));
  if (bytes.length >= 8 && TFPROOF_MAGIC.every((b: number, i: number) => b === bytes[i])) {
    const { bundle } = readTfproof(bytes);
    const events = bundle.events;
    const out: InspectOutput = {
      format: "tfproof",
      path,
      size_bytes: bytes.length,
      events: {
        count: events.length,
        head_id: events[0]?.id,
        head_hash: events[0] ? eventHash(events[0]) : undefined,
        tail_id: events[events.length - 1]?.id,
        tail_hash: events.length > 0 ? eventHash(events[events.length - 1]!) : undefined,
      },
      bundle: {
        bundle_version: bundle.bundle_version,
        merkle_root: bundle.merkle_root,
        chain_hash: bundle.chain_hash,
        transparency_anchor: bundle.transparency_anchor,
        signer: bundle.signature?.signer,
        algorithm: bundle.signature?.algorithm,
      },
    };
    if (dumpEvents) return canonicalize({ ...out, dump: bundle.events });
    return canonicalize(out);
  }

  if (bytes.length >= 8 && TFLOG_MAGIC.every((b: number, i: number) => b === bytes[i])) {
    const events = readTflog(bytes);
    const out: InspectOutput = {
      format: "tflog",
      path,
      size_bytes: bytes.length,
      events: {
        count: events.length,
        head_id: events[0]?.id,
        head_hash: events[0] ? eventHash(events[0]) : undefined,
        tail_id: events[events.length - 1]?.id,
        tail_hash: events.length > 0 ? eventHash(events[events.length - 1]!) : undefined,
      },
    };
    if (dumpEvents) return canonicalize({ ...out, dump: events });
    return canonicalize(out);
  }

  throw new Error(`${path} is not a .tflog or .tfproof file`);
}
