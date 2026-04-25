import { describe, expect, test } from "bun:test";
import { canonicalize, CanonicalJsonError } from "../src/core/canonical";

describe("canonicalize", () => {
  test("primitives", () => {
    expect(canonicalize(null)).toBe("null");
    expect(canonicalize(true)).toBe("true");
    expect(canonicalize(false)).toBe("false");
    expect(canonicalize(42)).toBe("42");
    expect(canonicalize(-0)).toBe("0");
    expect(canonicalize(1.5)).toBe("1.5");
    expect(canonicalize("hi")).toBe('"hi"');
  });

  test("sorts object keys lexicographically", () => {
    expect(canonicalize({ b: 1, a: 2 })).toBe('{"a":2,"b":1}');
    expect(canonicalize({ z: 1, a: { y: 2, x: 1 } })).toBe('{"a":{"x":1,"y":2},"z":1}');
  });

  test("drops undefined fields", () => {
    expect(canonicalize({ a: 1, b: undefined })).toBe('{"a":1}');
  });

  test("arrays preserve order", () => {
    expect(canonicalize([3, 1, 2])).toBe("[3,1,2]");
  });

  test("NFC-normalizes strings and keys", () => {
    // "é" as composed (U+00E9) vs decomposed (e + U+0301).
    const composed = "é"; // decomposed
    const out = canonicalize({ [composed]: "a" });
    expect(out).toBe('{"é":"a"}');
  });

  test("is idempotent under re-parse", () => {
    const input = { xs: [{ b: 1 }, { a: 2 }], meta: { tag: "x", n: 3 } };
    const a = canonicalize(input);
    const b = canonicalize(JSON.parse(a));
    expect(a).toBe(b);
  });

  test("rejects non-finite numbers", () => {
    expect(() => canonicalize(NaN)).toThrow(CanonicalJsonError);
    expect(() => canonicalize(Infinity)).toThrow(CanonicalJsonError);
  });

  test("rejects functions and symbols", () => {
    expect(() => canonicalize(() => 1)).toThrow(CanonicalJsonError);
    expect(() => canonicalize(Symbol("x"))).toThrow(CanonicalJsonError);
  });
});
