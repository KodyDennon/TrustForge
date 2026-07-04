import { readFileSync, readdirSync, statSync, existsSync } from "node:fs";
import { extname, join, resolve } from "node:path";
import { SchemaRegistry, type ValidateFunction } from "./validator";
import { parseYaml as parseYAML } from "@trustforge-protocol/types";

export const REPO_ROOT = resolve(import.meta.dir, "..", "..", "..");
export const SCHEMAS_DIR = join(REPO_ROOT, "schemas");
export const FIXTURES_DIR = join(SCHEMAS_DIR, "fixtures");

export const YAML_JSON = new Set([".yaml", ".yml", ".json"]);

export function loadFile(path: string): unknown {
  const raw = readFileSync(path, "utf8");
  const ext = extname(path).toLowerCase();
  if (ext === ".json") return JSON.parse(raw);
  if (ext === ".yaml" || ext === ".yml") return parseYAML(raw);
  throw new Error(`unsupported extension: ${ext}`);
}

export function listSchemas(): { name: string; path: string }[] {
  return readdirSync(SCHEMAS_DIR)
    .filter((f) => f.endsWith(".schema.json"))
    .map((f) => ({ name: f.replace(/\.schema\.json$/, ""), path: join(SCHEMAS_DIR, f) }))
    .sort((a, b) => a.name.localeCompare(b.name));
}

/** Build the schema registry (name kept from the ajv era so call sites
 *  didn't churn; the engine is the in-house `validator.ts`). */
export function buildAjv(): SchemaRegistry {
  const registry = new SchemaRegistry();
  for (const { name, path } of listSchemas()) {
    registry.addSchema(loadFile(path) as object, `${name}.schema.json`);
  }
  return registry;
}

export function getValidator(registry: SchemaRegistry, schemaName: string): ValidateFunction {
  const key = `${schemaName}.schema.json`;
  const v = registry.getSchema(key);
  if (!v) throw new Error(`schema not registered: ${key}`);
  return v;
}

export function walkFiles(dir: string, exts: Set<string>): string[] {
  if (!existsSync(dir)) return [];
  const out: string[] = [];
  for (const entry of readdirSync(dir)) {
    const p = join(dir, entry);
    const s = statSync(p);
    if (s.isDirectory()) out.push(...walkFiles(p, exts));
    else if (exts.has(extname(p).toLowerCase())) out.push(p);
  }
  return out.sort();
}
