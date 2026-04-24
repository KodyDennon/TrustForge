#!/usr/bin/env bun
import { readFileSync, readdirSync, statSync } from "node:fs";
import { extname, join, relative, resolve } from "node:path";
import Ajv2020, { type ErrorObject, type ValidateFunction } from "ajv/dist/2020.js";
import addFormats from "ajv-formats";
import { parse as parseYAML } from "yaml";

const REPO_ROOT = resolve(import.meta.dir, "..", "..", "..");
const SCHEMAS_DIR = join(REPO_ROOT, "schemas");
const EXAMPLES_DIR = join(REPO_ROOT, "examples");

type ValidateResult = { ok: true } | { ok: false; errors: ErrorObject[] };

function loadFile(path: string): unknown {
  const raw = readFileSync(path, "utf8");
  const ext = extname(path).toLowerCase();
  if (ext === ".json") return JSON.parse(raw);
  if (ext === ".yaml" || ext === ".yml") return parseYAML(raw);
  throw new Error(`unsupported file extension: ${ext}`);
}

function makeValidator(schemaPath: string): ValidateFunction {
  const schema = loadFile(schemaPath) as object;
  const ajv = new Ajv2020({ allErrors: true, strict: true });
  addFormats(ajv);
  return ajv.compile(schema);
}

function validate(schemaPath: string, instancePath: string): ValidateResult {
  const validate = makeValidator(schemaPath);
  const instance = loadFile(instancePath);
  if (validate(instance)) return { ok: true };
  return { ok: false, errors: validate.errors ?? [] };
}

function walkFiles(dir: string, exts: Set<string>): string[] {
  const out: string[] = [];
  for (const entry of readdirSync(dir)) {
    const p = join(dir, entry);
    const s = statSync(p);
    if (s.isDirectory()) out.push(...walkFiles(p, exts));
    else if (exts.has(extname(p).toLowerCase())) out.push(p);
  }
  return out;
}

function reportErrors(label: string, errors: ErrorObject[]): void {
  console.error(`FAIL ${label}`);
  for (const err of errors) {
    const loc = err.instancePath || "/";
    console.error(`  ${loc} ${err.message ?? "(no message)"}`);
  }
}

function cmdValidate(args: string[]): number {
  const [schema, instance] = args;
  if (!schema || !instance) {
    console.error("usage: tf-schema validate <schema.json> <instance.(yaml|json)>");
    return 2;
  }
  const res = validate(resolve(schema), resolve(instance));
  if (res.ok) {
    console.log(`OK ${relative(REPO_ROOT, resolve(instance))}`);
    return 0;
  }
  reportErrors(relative(REPO_ROOT, resolve(instance)), res.errors);
  return 1;
}

/**
 * Convention-based bulk validator.
 *
 * For each schema file `schemas/<name>.schema.json`, every file under
 * `examples/<name>s/` (plural) is validated against it. A schema with no
 * matching example directory is skipped with a notice. Example dirs without
 * a matching schema are an error.
 */
function cmdValidateAll(): number {
  const schemaFiles = walkFiles(SCHEMAS_DIR, new Set([".json"])).filter((f) =>
    f.endsWith(".schema.json"),
  );
  if (schemaFiles.length === 0) {
    console.error(`no schemas found under ${relative(REPO_ROOT, SCHEMAS_DIR)}`);
    return 1;
  }

  let failed = 0;
  let total = 0;
  for (const schemaPath of schemaFiles) {
    const base = schemaPath.split("/").pop()!.replace(/\.schema\.json$/, "");
    const examplesSubdir = join(EXAMPLES_DIR, `${base}s`);
    let instances: string[] = [];
    try {
      instances = walkFiles(examplesSubdir, new Set([".yaml", ".yml", ".json"]));
    } catch {
      console.log(`skip  ${base}: no examples dir at ${relative(REPO_ROOT, examplesSubdir)}`);
      continue;
    }

    for (const instancePath of instances) {
      total++;
      const res = validate(schemaPath, instancePath);
      if (res.ok) {
        console.log(`OK    ${relative(REPO_ROOT, instancePath)}`);
      } else {
        failed++;
        reportErrors(relative(REPO_ROOT, instancePath), res.errors);
      }
    }
  }

  if (failed > 0) {
    console.error(`\n${failed}/${total} failed`);
    return 1;
  }
  console.log(`\n${total}/${total} validated`);
  return 0;
}

const [cmd, ...rest] = process.argv.slice(2);
const exit =
  cmd === "validate"
    ? cmdValidate(rest)
    : cmd === "validate-all"
      ? cmdValidateAll()
      : (console.error("usage: tf-schema <validate|validate-all> [args]"), 2);
process.exit(exit);
