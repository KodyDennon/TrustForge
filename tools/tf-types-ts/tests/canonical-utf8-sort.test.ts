import { describe, expect, test } from "bun:test";
import { canonicalize } from "../src/index";

describe("UTF-8 byte-order key sort", () => {
  test("BMP key  sorts before supplementary plane 𠀀", () => {
    // UTF-8 of  is EE 80 80 (lead byte 0xEE).
    // UTF-8 of 𠀀 is F0 A0 80 80 (lead byte 0xF0).
    // UTF-8 byte order:  < 𠀀.
    // (UTF-16 disagrees: surrogate high byte 0xD840 < 0xE000.)
    const out = canonicalize({ "\u{20000}": 2, "": 1 });
    expect(out.indexOf("")).toBeLessThan(out.indexOf("\u{20000}"));
  });

  test("BMP ASCII ~ sorts before supplementary plane 𐀁", () => {
    // ~ = 0x7E, 𐀁 = F0 90 80 81.
    const out = canonicalize({ "\u{10001}": 2, "~": 1 });
    expect(out.indexOf("~")).toBeLessThan(out.indexOf("\u{10001}"));
  });

  test("decomposed and composed forms of café canonicalize identically", () => {
    const composed = "café"; // U+00E9
    const decomposed = "café"; // e + combining acute
    expect(canonicalize({ [composed]: 1 })).toBe(canonicalize({ [decomposed]: 1 }));
  });

  test("a long key with supplementary plane chars round-trips deterministically", () => {
    const k = "𓀀𓀁𓀂"; // egyptian hieroglyphs (plane 1)
    expect(canonicalize({ [k]: 1, a: 2 })).toBe(canonicalize({ a: 2, [k]: 1 }));
  });
});
