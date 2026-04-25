import type { SignatureEnvelope } from "../generated/_common.js";

export type EnvelopeIssue =
  | { code: "missing-algorithm" }
  | { code: "missing-signer" }
  | { code: "missing-signature" }
  | { code: "invalid-base64"; field: "signature" | "alt_signature" }
  | { code: "alt-without-algorithm" }
  | { code: "unknown-algorithm"; algorithm: string }
  | { code: "unknown-alt-algorithm"; algorithm: string };

const KNOWN_ALGORITHMS: ReadonlySet<string> = new Set([
  "ed25519",
  "ed448",
  "p256",
  "p384",
  "p521",
  "rsa-pss-sha256",
  "ml-dsa-44",
  "ml-dsa-65",
  "ml-dsa-87",
  "slh-dsa-sha2-128s",
  "slh-dsa-sha2-192s",
]);

const BASE64_RE = /^[A-Za-z0-9+/]+={0,2}$/;

export interface ValidationResult {
  readonly ok: boolean;
  readonly issues: EnvelopeIssue[];
}

/**
 * Validate the shape of a SignatureEnvelope. Does NOT verify the signature;
 * no crypto is performed in the foundation phase. Unknown algorithms
 * produce non-fatal warnings in the issue list but still pass `ok=true`.
 */
export function validateEnvelopeShape(e: SignatureEnvelope): ValidationResult {
  const issues: EnvelopeIssue[] = [];
  if (!e.algorithm) issues.push({ code: "missing-algorithm" });
  if (!e.signer) issues.push({ code: "missing-signer" });
  if (!e.signature) issues.push({ code: "missing-signature" });
  if (e.signature && !BASE64_RE.test(e.signature)) issues.push({ code: "invalid-base64", field: "signature" });
  if (e.alt_signature && !BASE64_RE.test(e.alt_signature)) issues.push({ code: "invalid-base64", field: "alt_signature" });
  if (e.alt_signature && !e.alt_algorithm) issues.push({ code: "alt-without-algorithm" });

  const fatalCount = issues.filter((i) => !isWarning(i)).length;
  if (e.algorithm && !KNOWN_ALGORITHMS.has(e.algorithm)) {
    issues.push({ code: "unknown-algorithm", algorithm: e.algorithm });
  }
  if (e.alt_algorithm && !KNOWN_ALGORITHMS.has(e.alt_algorithm)) {
    issues.push({ code: "unknown-alt-algorithm", algorithm: e.alt_algorithm });
  }
  return { ok: fatalCount === 0, issues };
}

function isWarning(i: EnvelopeIssue): boolean {
  return i.code === "unknown-algorithm" || i.code === "unknown-alt-algorithm";
}
