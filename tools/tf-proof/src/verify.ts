import { readFileSync } from "node:fs";
import {
  canonicalize,
  ed25519Verify,
  b64decode,
  chainHash,
  eventHash,
  merkleRoot,
  readTfproof,
  readTflog,
  utf8encode,
  verifyChain,
  TFLOG_MAGIC,
  TFPROOF_MAGIC,
} from "@trustforge-protocol/types";
import type { ProofBundle, SignatureEnvelope } from "@trustforge-protocol/types";
import { readKeyFile } from "./keyfile.js";

export interface VerifyReport {
  ok: boolean;
  format: "tfproof" | "tflog";
  events: number;
  checks: VerifyCheck[];
}

export interface VerifyCheck {
  name: string;
  ok: boolean;
  detail?: string;
}

export async function verifyFile(filePath: string, publicKeyFile?: string): Promise<VerifyReport> {
  const bytes = new Uint8Array(readFileSync(filePath));
  const isTfproof = bytes.length >= 8 && TFPROOF_MAGIC.every((b: number, i: number) => b === bytes[i]);
  const isTflog = bytes.length >= 8 && TFLOG_MAGIC.every((b: number, i: number) => b === bytes[i]);
  if (!isTfproof && !isTflog) {
    return {
      ok: false,
      format: "tfproof",
      events: 0,
      checks: [{ name: "magic", ok: false, detail: "not a .tfproof or .tflog file" }],
    };
  }
  const checks: VerifyCheck[] = [];

  if (isTflog) {
    const events = readTflog(bytes);
    checks.push({ name: "read_tflog", ok: true, detail: `${events.length} events` });
    try {
      verifyChain(events);
      checks.push({ name: "chain", ok: true });
    } catch (err) {
      checks.push({ name: "chain", ok: false, detail: (err as Error).message });
    }
    return {
      ok: checks.every((c) => c.ok),
      format: "tflog",
      events: events.length,
      checks,
    };
  }

  const { bundle, signature: rawSignature } = readTfproof(bytes);
  checks.push({ name: "read_tfproof", ok: true, detail: `${bundle.events.length} events` });

  // Chain-verify the events inside the bundle.
  try {
    verifyChain(bundle.events);
    checks.push({ name: "chain", ok: true });
  } catch (err) {
    checks.push({ name: "chain", ok: false, detail: (err as Error).message });
  }

  // Merkle + chain-hash match if present.
  if (bundle.merkle_root) {
    const computed = merkleRoot(bundle.events);
    const ok = computed === bundle.merkle_root;
    checks.push({ name: "merkle_root", ok, detail: ok ? undefined : `computed ${computed}` });
  }
  if (bundle.chain_hash) {
    const computed = chainHash(bundle.events);
    const ok = computed === bundle.chain_hash;
    checks.push({ name: "chain_hash", ok, detail: ok ? undefined : `computed ${computed}` });
  }

  // Each event's signature: shape-only here. Real per-event verification
  // would need a per-signer public key registry; deferred to Phase 3.
  for (let i = 0; i < bundle.events.length; i++) {
    const e = bundle.events[i]!;
    const sig = e.signature as SignatureEnvelope;
    if (!sig || !sig.signature) {
      checks.push({ name: `event[${i}].signature`, ok: false, detail: "missing signature envelope" });
    }
  }

  // Bundle-level signature verification against the supplied public key.
  if (publicKeyFile) {
    const { bytes: pubkey, kind } = readKeyFile(publicKeyFile);
    if (kind !== "public") {
      checks.push({
        name: "bundle_signature",
        ok: false,
        detail: `${publicKeyFile} is a ${kind} key, expected public`,
      });
    } else {
      // Both the envelope signature and the frame trailer are computed over
      // the canonical JSON of the bundle with signature.signature cleared.
      const toSign = { ...bundle, signature: { ...bundle.signature, signature: "" } };
      const signingPayload = utf8encode(canonicalize(toSign));
      const declared = b64decode((bundle.signature as SignatureEnvelope).signature);
      const envelopeOk = await ed25519Verify(pubkey, signingPayload, declared);
      checks.push({
        name: "bundle_signature_envelope",
        ok: envelopeOk,
        detail: envelopeOk ? undefined : "declared signature did not verify",
      });

      const trailerOk = await ed25519Verify(pubkey, signingPayload, rawSignature);
      checks.push({
        name: "bundle_signature_trailer",
        ok: trailerOk,
        detail: trailerOk ? undefined : "trailer signature did not verify",
      });
    }
  } else {
    checks.push({
      name: "bundle_signature",
      ok: true,
      detail: "no --key supplied; signature shape-checked only",
    });
  }

  return {
    ok: checks.every((c) => c.ok),
    format: "tfproof",
    events: bundle.events.length,
    checks,
  };
}
