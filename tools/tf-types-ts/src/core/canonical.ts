/**
 * Deterministic JSON serialization compatible with the Rust implementation.
 *
 * Rules:
 *   - Object keys are sorted by UTF-8 byte order of their NFC-normalized
 *     form. (NOT JS string `<` / `>` which uses UTF-16 code-unit order;
 *     UTF-16 and UTF-8 disagree for keys near the surrogate-adjacent BMP
 *     block U+E000+ vs supplementary plane.)
 *   - All string values are NFC-normalized.
 *   - Finite integers emit as integers (no ".0"); finite non-integer numbers
 *     emit via JavaScript's shortest round-trip representation.
 *   - -0 is emitted as 0.
 *   - undefined, functions, symbols, NaN, ±Infinity are rejected.
 *   - No whitespace anywhere in the output.
 *
 * The output is a valid UTF-8 JSON string; byte-for-byte equality with the
 * Rust implementation is tested by `conformance/canonical-vectors.yaml`
 * and `conformance/cross-language-signature-vectors.yaml`.
 */
export function canonicalize(value: unknown): string {
  return encode(value);
}

export class CanonicalJsonError extends Error {}

const utf8 = new TextEncoder();

/** UTF-8 byte-order comparator. Matches Rust's `String::cmp` (which compares
 *  underlying UTF-8 bytes) and the lexicographic byte order Rust's
 *  `BTreeMap<String, _>` uses. */
function utf8Compare(a: string, b: string): number {
  const ab = utf8.encode(a);
  const bb = utf8.encode(b);
  const len = Math.min(ab.length, bb.length);
  for (let i = 0; i < len; i++) {
    const da = ab[i]!;
    const db = bb[i]!;
    if (da !== db) return da - db;
  }
  return ab.length - bb.length;
}

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
      .sort(([a], [b]) => utf8Compare(a, b));
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
