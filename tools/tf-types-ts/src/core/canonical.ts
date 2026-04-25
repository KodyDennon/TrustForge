/**
 * Deterministic JSON serialization compatible with the Rust implementation.
 *
 * Rules:
 *   - Object keys are sorted lexicographically by their NFC-normalized
 *     codepoint sequence.
 *   - All string values are NFC-normalized.
 *   - Finite integers emit as integers (no ".0"); finite non-integer numbers
 *     emit via JavaScript's shortest round-trip representation.
 *   - -0 is emitted as 0.
 *   - undefined, functions, symbols, NaN, ±Infinity are rejected.
 *   - No whitespace anywhere in the output.
 *
 * The output is a valid UTF-8 JSON string; byte-for-byte equality with the
 * Rust implementation is tested by canonical-vectors.yaml.
 */
export function canonicalize(value: unknown): string {
  return encode(value);
}

export class CanonicalJsonError extends Error {}

function encode(v: unknown): string {
  if (v === null) return "null";
  if (typeof v === "boolean") return v ? "true" : "false";
  if (typeof v === "number") return encodeNumber(v);
  if (typeof v === "bigint") return v.toString(10);
  if (typeof v === "string") return JSON.stringify(v.normalize("NFC"));
  if (Array.isArray(v)) return "[" + v.map(encode).join(",") + "]";
  if (typeof v === "object") {
    const entries = Object.entries(v as Record<string, unknown>)
      .filter(([, val]) => val !== undefined)
      .map(([k, val]) => [k.normalize("NFC"), val] as const)
      .sort(([a], [b]) => (a < b ? -1 : a > b ? 1 : 0));
    return "{" + entries.map(([k, val]) => JSON.stringify(k) + ":" + encode(val)).join(",") + "}";
  }
  throw new CanonicalJsonError(`cannot canonicalize value of type ${typeof v}`);
}

function encodeNumber(n: number): string {
  if (!Number.isFinite(n)) throw new CanonicalJsonError(`cannot canonicalize non-finite number: ${n}`);
  if (Object.is(n, -0)) return "0";
  if (Number.isInteger(n)) return n.toFixed(0);
  return String(n);
}
