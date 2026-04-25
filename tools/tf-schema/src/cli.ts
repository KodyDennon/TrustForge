#!/usr/bin/env bun
import { resolve, relative } from "node:path";
import { REPO_ROOT, buildAjv, loadFile } from "./loader";
import { runValidateAll, formatResult } from "./validate";

function cmdValidate(args: string[]): number {
  const [schemaName, instance] = args;
  if (!schemaName || !instance) {
    console.error("usage: tf-schema validate <schema-name> <instance.(yaml|json)>");
    return 2;
  }
  const ajv = buildAjv();
  const key = `${schemaName}.schema.json`;
  const validator = ajv.getSchema(key);
  if (!validator) {
    console.error(`unknown schema: ${schemaName}`);
    return 2;
  }
  const doc = loadFile(resolve(instance));
  if (validator(doc)) {
    console.log(`OK ${relative(REPO_ROOT, resolve(instance))}`);
    return 0;
  }
  console.error(`FAIL ${relative(REPO_ROOT, resolve(instance))}`);
  for (const e of validator.errors ?? []) {
    console.error(`  ${e.instancePath || "/"} ${e.keyword} ${e.message ?? ""}`);
  }
  return 1;
}

async function cmdValidateAll(args: string[]): Promise<number> {
  const schema = args[0];
  const result = await runValidateAll(schema ? { schema } : undefined);
  console.log(formatResult(result));
  return result.ok ? 0 : 1;
}

async function cmdBundle(args: string[]): Promise<number> {
  const [name] = args;
  if (!name) {
    console.error("usage: tf-schema bundle <schema-name>");
    return 2;
  }
  const { bundleSchema } = await import("./bundle");
  const bundled = await bundleSchema(name);
  console.log(JSON.stringify(bundled, null, 2));
  return 0;
}

function argValue(args: string[], flag: string): string | undefined {
  const idx = args.indexOf(flag);
  if (idx < 0) return undefined;
  return args[idx + 1];
}

async function cmdCodegen(args: string[]): Promise<number> {
  const target = argValue(args, "--target");
  const out = argValue(args, "--out");
  if (target === "ts") {
    const dest = out ?? "tools/tf-types-ts/src/generated";
    const { writeTsOutput } = await import("./codegen/ts");
    const names = await writeTsOutput(dest);
    console.log(`wrote ${names.length} files to ${dest}`);
    return 0;
  }
  if (target === "rust") {
    const dest = out ?? "crates/tf-types/src/generated";
    const { writeRustOutput } = await import("./codegen/rust");
    const names = await writeRustOutput(dest);
    console.log(`wrote ${names.length} files to ${dest}`);
    return 0;
  }
  if (target === "docs") {
    const dest = out ?? "docs/schemas";
    const { writeDocsOutput } = await import("./codegen/docs");
    const names = await writeDocsOutput(dest);
    console.log(`wrote ${names.length} files to ${dest}`);
    return 0;
  }
  if (target === "rpc-ts") {
    const spec = argValue(args, "--spec");
    if (!spec) {
      console.error("usage: tf-schema codegen --target rpc-ts --spec <file.tfrpc.yaml> [--out <dir>]");
      return 2;
    }
    const dest = out ?? "tools/tf-types-ts/src/generated/rpc";
    const { writeRpcTsOutput } = await import("./codegen/rpc-ts");
    const names = writeRpcTsOutput(spec, dest);
    console.log(`wrote ${names.length} files to ${dest}`);
    return 0;
  }
  if (target === "rpc-rust") {
    const spec = argValue(args, "--spec");
    if (!spec) {
      console.error("usage: tf-schema codegen --target rpc-rust --spec <file.tfrpc.yaml> [--out <dir>]");
      return 2;
    }
    const dest = out ?? "crates/tf-types/src/generated/rpc";
    const { writeRpcRustOutput } = await import("./codegen/rpc-rust");
    const names = writeRpcRustOutput(spec, dest);
    console.log(`wrote ${names.length} files to ${dest}`);
    return 0;
  }
  console.error(`codegen: unknown or missing target: ${target ?? "(none)"}`);
  console.error("usage: tf-schema codegen --target ts|rust|docs|rpc-ts|rpc-rust [--out <dir>]");
  return 2;
}

async function cmdLint(): Promise<number> {
  const { lintSchemas } = await import("./lint");
  const result = await lintSchemas();
  for (const i of result.issues) {
    console.error(`${i.file}${i.path} [${i.rule}] ${i.message}`);
  }
  return result.issues.length === 0 ? 0 : 1;
}

async function cmdFuzz(args: string[]): Promise<number> {
  const { fuzzSchema, fuzzAll } = await import("./fuzz");
  const iterations = Number(argValue(args, "--iterations") ?? 200);
  const schema = args.find((a) => !a.startsWith("--"));
  if (schema) {
    const r = await fuzzSchema(schema, { iterations });
    console.log(JSON.stringify(r, null, 2));
    return r.panics.length === 0 ? 0 : 1;
  }
  const results = await fuzzAll(iterations);
  const totalPanics = results.reduce((n, r) => n + r.panics.length, 0);
  console.log(JSON.stringify(results, null, 2));
  return totalPanics === 0 ? 0 : 1;
}

async function cmdParity(args: string[]): Promise<number> {
  const { generateParity, runParityTs, serializeParity } = await import("./parity");
  const { writeFileSync } = await import("node:fs");
  const out = argValue(args, "--out") ?? "conformance/parity.yaml";
  const parity = await generateParity();
  writeFileSync(out, serializeParity(parity));
  const result = await runParityTs(out);
  if (!result.ok) {
    console.error(`parity: ${result.mismatches.length} mismatches`);
    for (const m of result.mismatches) console.error(`  ${m.vector.fixture}: expected ${m.vector.expect}, got ${m.got}`);
    return 1;
  }
  console.log(`parity: ${parity.vectors.length} vectors OK`);
  return 0;
}

const [cmd, ...rest] = process.argv.slice(2);
let exit = 2;
if (cmd === "validate") {
  exit = cmdValidate(rest);
} else if (cmd === "validate-all") {
  exit = await cmdValidateAll(rest);
} else if (cmd === "lint") {
  exit = await cmdLint();
} else if (cmd === "bundle") {
  exit = await cmdBundle(rest);
} else if (cmd === "codegen") {
  exit = await cmdCodegen(rest);
} else if (cmd === "fuzz") {
  exit = await cmdFuzz(rest);
} else if (cmd === "parity") {
  exit = await cmdParity(rest);
} else {
  console.error("usage: tf-schema <validate|validate-all|lint|bundle|codegen|fuzz|parity> [args]");
}
process.exit(exit);
