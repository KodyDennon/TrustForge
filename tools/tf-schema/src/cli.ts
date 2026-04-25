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
  console.error(`codegen: unknown or missing target: ${target ?? "(none)"}`);
  console.error("usage: tf-schema codegen --target ts|rust [--out <dir>]");
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
} else {
  console.error("usage: tf-schema <validate|validate-all|lint|bundle|codegen> [args]");
}
process.exit(exit);
