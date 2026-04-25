import { describe, expect, test } from "bun:test";
import { generateRust } from "../src/codegen/rust";

describe("Rust codegen", () => {
  test("emits RiskClass as a serde enum with renames", async () => {
    const out = await generateRust();
    expect(out["common.rs"]).toBeDefined();
    expect(out["common.rs"]!).toContain("pub enum RiskClass");
    expect(out["common.rs"]!).toContain('rename = "R0"');
  });

  test("every struct derives Serialize + Deserialize", async () => {
    const out = await generateRust();
    for (const [file, text] of Object.entries(out)) {
      if (file === "mod.rs") continue;
      const structCount = (text.match(/^pub struct /gm) ?? []).length;
      const structDerives = (text.match(/#\[derive\([^)]*Serialize[^)]*Deserialize[^)]*\)\]\npub struct /g) ?? []).length;
      expect(structDerives).toBe(structCount);
    }
  });

  test("Constraint is a tagged enum with kind discriminator", async () => {
    const out = await generateRust();
    expect(out["common.rs"]!).toContain("#[serde(tag = \"kind\")]");
    expect(out["common.rs"]!).toContain("pub enum Constraint");
    expect(out["common.rs"]!).toContain('rename = "time_window"');
  });

  test("mod.rs re-exports every schema module", async () => {
    const out = await generateRust();
    expect(out["mod.rs"]).toBeDefined();
    expect(out["mod.rs"]!).toContain("pub mod common;");
    expect(out["mod.rs"]!).toContain("pub use common::*;");
    expect(out["mod.rs"]!).toContain("pub mod agent_contract;");
  });
});
