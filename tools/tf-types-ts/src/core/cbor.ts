/**
 * In-house CBOR codec (RFC 8949) — TrustForge owns its codec layer; see
 * `docs/dependency-audit.md`. Mirror of `crates/tf-types/src/cbor.rs`.
 *
 * Scope: exactly what the TrustForge wire formats need.
 *
 * - **Encoding is deterministic**: smallest-width integer/length
 *   headers, definite lengths only, floats always emitted as 8-byte
 *   doubles (the cbor-x `useFloat32: 0` behavior this replaced). Map /
 *   object entries are emitted **in the order provided** — canonical key
 *   ordering is the caller's contract (`binary-format.ts` sorts keys
 *   before encoding). Must stay byte-parity with the Rust encoder over
 *   `conformance/binary-format-vectors.yaml`.
 * - **Decoding is hardened** for externally produced CBOR (WebAuthn
 *   attestation objects, COSE keys): depth-limited, length headers are
 *   validated against remaining input before any allocation, and
 *   indefinite-length items are accepted but bounded by the same
 *   limits. Trailing bytes after the first value are ignored, matching
 *   the replaced decoder.
 *
 * Decoded shapes: maps whose keys are all strings become plain
 * (null-prototype) objects; any other map becomes a `Map`. Byte strings
 * become `Uint8Array`. Integers outside the safe-integer range become
 * `bigint`. Tags decode to `CborTag` wrappers. `undefined` (0xf7)
 * decodes to `null`.
 */

const MAX_DEPTH = 128;

export class CborError extends Error {}

/** Unknown-tag wrapper produced by the decoder. */
export class CborTag {
  constructor(
    public readonly tag: number | bigint,
    public readonly value: unknown,
  ) {}
}

/* ------------------------------------------------------------------ */
/*  Encoding                                                           */
/* ------------------------------------------------------------------ */

class Writer {
  private chunks: number[] = [];

  push(...bytes: number[]): void {
    for (const b of bytes) this.chunks.push(b & 0xff);
  }

  pushBytes(bytes: Uint8Array): void {
    for (const b of bytes) this.chunks.push(b);
  }

  header(major: number, arg: number | bigint): void {
    const mt = major << 5;
    if (typeof arg === "bigint") {
      if (arg < 0n || arg > 0xffffffffffffffffn) {
        throw new CborError("header argument out of range");
      }
      if (arg < 24n) {
        this.push(mt | Number(arg));
      } else if (arg <= 0xffn) {
        this.push(mt | 24, Number(arg));
      } else if (arg <= 0xffffn) {
        const n = Number(arg);
        this.push(mt | 25, n >> 8, n);
      } else if (arg <= 0xffffffffn) {
        const n = Number(arg);
        this.push(mt | 26, n >>> 24, n >>> 16, n >>> 8, n);
      } else {
        this.push(mt | 27);
        for (let shift = 56n; shift >= 0n; shift -= 8n) {
          this.push(Number((arg >> shift) & 0xffn));
        }
      }
      return;
    }
    if (!Number.isSafeInteger(arg) || arg < 0) {
      throw new CborError(`header argument out of range: ${arg}`);
    }
    if (arg < 24) {
      this.push(mt | arg);
    } else if (arg <= 0xff) {
      this.push(mt | 24, arg);
    } else if (arg <= 0xffff) {
      this.push(mt | 25, arg >> 8, arg);
    } else if (arg <= 0xffffffff) {
      this.push(mt | 26, arg >>> 24, arg >>> 16, arg >>> 8, arg);
    } else {
      this.header(major, BigInt(arg));
    }
  }

  float64(f: number): void {
    const buf = new ArrayBuffer(8);
    new DataView(buf).setFloat64(0, f, false);
    this.push(0xfb);
    this.pushBytes(new Uint8Array(buf));
  }

  finish(): Uint8Array {
    return new Uint8Array(this.chunks);
  }
}

const UTF8_ENCODER = new TextEncoder();
const UTF8_DECODER = new TextDecoder("utf-8", { fatal: true });

function encodeInteger(w: Writer, value: bigint): void {
  if (value >= 0n) {
    w.header(0, value);
  } else {
    const magnitude = -value - 1n;
    if (magnitude > 0xffffffffffffffffn) {
      throw new CborError("integer below -2^64");
    }
    w.header(1, magnitude);
  }
}

function encodeInto(w: Writer, value: unknown, depth: number): void {
  if (depth > MAX_DEPTH) throw new CborError("nesting exceeds depth limit");
  if (value === null) {
    w.push(0xf6);
    return;
  }
  if (value === undefined) {
    w.push(0xf7);
    return;
  }
  switch (typeof value) {
    case "boolean":
      w.push(value ? 0xf5 : 0xf4);
      return;
    case "number":
      if (Number.isSafeInteger(value) && !Object.is(value, -0)) {
        encodeInteger(w, BigInt(value));
      } else {
        // Always 8-byte doubles — see determinism note above.
        w.float64(value);
      }
      return;
    case "bigint":
      encodeInteger(w, value);
      return;
    case "string": {
      const bytes = UTF8_ENCODER.encode(value);
      w.header(3, bytes.length);
      w.pushBytes(bytes);
      return;
    }
    case "object":
      break;
    default:
      throw new CborError(`cannot encode ${typeof value}`);
  }
  if (value instanceof Uint8Array) {
    w.header(2, value.length);
    w.pushBytes(value);
    return;
  }
  if (Array.isArray(value)) {
    w.header(4, value.length);
    for (const item of value) encodeInto(w, item, depth + 1);
    return;
  }
  if (value instanceof Map) {
    w.header(5, value.size);
    for (const [k, v] of value) {
      encodeInto(w, k, depth + 1);
      encodeInto(w, v, depth + 1);
    }
    return;
  }
  if (value instanceof CborTag) {
    w.header(6, value.tag);
    encodeInto(w, value.value, depth + 1);
    return;
  }
  // Plain object: string keys in insertion order; `undefined` values
  // are skipped, matching cbor-x/JSON semantics.
  const entries = Object.entries(value as Record<string, unknown>).filter(
    ([, v]) => v !== undefined,
  );
  w.header(5, entries.length);
  for (const [k, v] of entries) {
    encodeInto(w, k, depth + 1);
    encodeInto(w, v, depth + 1);
  }
}

export function encode(value: unknown): Uint8Array {
  const w = new Writer();
  encodeInto(w, value, 0);
  return w.finish();
}

/* ------------------------------------------------------------------ */
/*  Decoding                                                           */
/* ------------------------------------------------------------------ */

class Reader {
  pos = 0;
  constructor(private buf: Uint8Array) {}

  byte(): number {
    if (this.pos >= this.buf.length) throw new CborError("truncated CBOR input");
    return this.buf[this.pos++]!;
  }

  peek(): number {
    if (this.pos >= this.buf.length) throw new CborError("truncated CBOR input");
    return this.buf[this.pos]!;
  }

  take(n: number): Uint8Array {
    if (this.pos + n > this.buf.length) throw new CborError("truncated CBOR input");
    const s = this.buf.subarray(this.pos, this.pos + n);
    this.pos += n;
    return s;
  }

  remaining(): number {
    return this.buf.length - this.pos;
  }

  arg(info: number): number | bigint {
    if (info < 24) return info;
    switch (info) {
      case 24:
        return this.byte();
      case 25: {
        const b = this.take(2);
        return (b[0]! << 8) | b[1]!;
      }
      case 26: {
        const b = this.take(4);
        return ((b[0]! << 24) | (b[1]! << 16) | (b[2]! << 8) | b[3]!) >>> 0;
      }
      case 27: {
        const b = this.take(8);
        let v = 0n;
        for (const byte of b) v = (v << 8n) | BigInt(byte);
        return v <= BigInt(Number.MAX_SAFE_INTEGER) ? Number(v) : v;
      }
      default:
        throw new CborError("invalid CBOR: reserved additional-info value");
    }
  }

  /**
   * Interpret a header argument as a byte/item length, rejecting
   * anything that cannot fit in the remaining input — the allocation
   * guard for hostile length headers.
   */
  argAsLen(arg: number | bigint, perItemBytes: number): number {
    const max = Math.floor(this.remaining() / perItemBytes);
    if (typeof arg === "bigint" || arg > max) {
      throw new CborError("truncated CBOR input");
    }
    return arg;
  }
}

function halfToNumber(raw: number): number {
  const exp = (raw >> 10) & 0x1f;
  const mant = raw & 0x3ff;
  let magnitude: number;
  if (exp === 0) magnitude = mant * 2 ** -24;
  else if (exp === 31) magnitude = mant === 0 ? Infinity : NaN;
  else magnitude = (mant + 1024) * 2 ** (exp - 25);
  return raw & 0x8000 ? -magnitude : magnitude;
}

function integerFrom(arg: number | bigint, negative: boolean): number | bigint {
  if (typeof arg === "number") {
    return negative ? -1 - arg : arg;
  }
  const v = negative ? -1n - arg : arg;
  return v >= BigInt(Number.MIN_SAFE_INTEGER) && v <= BigInt(Number.MAX_SAFE_INTEGER)
    ? Number(v)
    : v;
}

function decodeIndefiniteString(r: Reader, major: number): Uint8Array {
  const parts: Uint8Array[] = [];
  let total = 0;
  for (;;) {
    const initial = r.byte();
    if (initial === 0xff) break;
    if (initial >> 5 !== major || (initial & 0x1f) === 31) {
      throw new CborError("invalid CBOR: bad chunk in indefinite string");
    }
    const len = r.argAsLen(r.arg(initial & 0x1f), 1);
    const chunk = r.take(len);
    parts.push(chunk);
    total += chunk.length;
  }
  const out = new Uint8Array(total);
  let off = 0;
  for (const p of parts) {
    out.set(p, off);
    off += p.length;
  }
  return out;
}

function buildMap(entries: Array<[unknown, unknown]>): unknown {
  if (entries.every(([k]) => typeof k === "string")) {
    // Null prototype so hostile "__proto__" / "constructor" keys cannot
    // pollute; consumers only do property reads.
    const out: Record<string, unknown> = Object.create(null);
    for (const [k, v] of entries) {
      Object.defineProperty(out, k as string, {
        value: v,
        enumerable: true,
        writable: true,
        configurable: true,
      });
    }
    return out;
  }
  return new Map(entries);
}

function decodeValue(r: Reader, depth: number): unknown {
  if (depth > MAX_DEPTH) throw new CborError("nesting exceeds depth limit");
  const initial = r.byte();
  const major = initial >> 5;
  const info = initial & 0x1f;
  switch (major) {
    case 0:
      return integerFrom(r.arg(info), false);
    case 1:
      return integerFrom(r.arg(info), true);
    case 2:
      if (info === 31) return decodeIndefiniteString(r, 2);
      // Copy out of the backing buffer so the value owns its bytes.
      return new Uint8Array(r.take(r.argAsLen(r.arg(info), 1)));
    case 3: {
      const bytes = info === 31 ? decodeIndefiniteString(r, 3) : r.take(r.argAsLen(r.arg(info), 1));
      try {
        return UTF8_DECODER.decode(bytes);
      } catch {
        throw new CborError("invalid CBOR: text string is not UTF-8");
      }
    }
    case 4: {
      if (info === 31) {
        const items: unknown[] = [];
        while (r.peek() !== 0xff) items.push(decodeValue(r, depth + 1));
        r.byte(); // consume break
        return items;
      }
      const len = r.argAsLen(r.arg(info), 1);
      const items: unknown[] = [];
      for (let i = 0; i < len; i++) items.push(decodeValue(r, depth + 1));
      return items;
    }
    case 5: {
      const entries: Array<[unknown, unknown]> = [];
      if (info === 31) {
        while (r.peek() !== 0xff) {
          const k = decodeValue(r, depth + 1);
          const v = decodeValue(r, depth + 1);
          entries.push([k, v]);
        }
        r.byte(); // consume break
      } else {
        const count = r.argAsLen(r.arg(info), 2);
        for (let i = 0; i < count; i++) {
          const k = decodeValue(r, depth + 1);
          const v = decodeValue(r, depth + 1);
          entries.push([k, v]);
        }
      }
      return buildMap(entries);
    }
    case 6: {
      const tag = r.arg(info);
      return new CborTag(tag, decodeValue(r, depth + 1));
    }
    case 7:
      switch (info) {
        case 20:
          return false;
        case 21:
          return true;
        case 22:
          return null;
        case 23:
          return null; // undefined → null
        case 24: {
          const b = r.byte();
          if (b < 32) throw new CborError("invalid CBOR: non-minimal simple value");
          return b; // unassigned simple value
        }
        case 25: {
          const b = r.take(2);
          return halfToNumber((b[0]! << 8) | b[1]!);
        }
        case 26: {
          const b = r.take(4);
          const buf = new ArrayBuffer(4);
          new Uint8Array(buf).set(b);
          return new DataView(buf).getFloat32(0, false);
        }
        case 27: {
          const b = r.take(8);
          const buf = new ArrayBuffer(8);
          new Uint8Array(buf).set(b);
          return new DataView(buf).getFloat64(0, false);
        }
        case 31:
          throw new CborError("invalid CBOR: unexpected break");
        default:
          throw new CborError("invalid CBOR: reserved simple value");
      }
    default:
      throw new CborError("unreachable");
  }
}

/**
 * Decode the first CBOR value in `bytes`. Trailing bytes are ignored,
 * matching the replaced decoder's behavior.
 */
export function decode(bytes: Uint8Array): unknown {
  return decodeValue(new Reader(bytes), 0);
}
