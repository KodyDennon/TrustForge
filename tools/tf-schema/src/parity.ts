import { join, relative } from "node:path";
import { stringify as yamlStringify } from "yaml";
import {
  FIXTURES_DIR,
  REPO_ROOT,
  YAML_JSON,
  buildAjv,
  getValidator,
  listSchemas,
  loadFile,
  walkFiles,
} from "./loader";

export interface ParityEntry {
  schema: string;
  fixture: string;
  expect: "valid" | "invalid";
}

export interface ParityFile {
  vectors: ParityEntry[];
}

/**
 * Walk every fixture under schemas/fixtures and produce the parity manifest.
 * `valid/` and `composite/` fixtures are expected to validate; `invalid/`
 * fixtures are expected to fail. The fixture path is stored relative to the
 * repo root so both runtimes can resolve it deterministically.
 */
export async function generateParity(): Promise<ParityFile> {
  const vectors: ParityEntry[] = [];
  for (const { name } of listSchemas()) {
    if (name === "_common") continue;
    for (const group of ["valid", "composite"] as const) {
      const dir = join(FIXTURES_DIR, name, group);
      for (const f of walkFiles(dir, YAML_JSON)) {
        vectors.push({ schema: name, fixture: relative(REPO_ROOT, f), expect: "valid" });
      }
    }
    const invalidDir = join(FIXTURES_DIR, name, "invalid");
    for (const f of walkFiles(invalidDir, YAML_JSON)) {
      if (f.endsWith(".expected-error.yaml")) continue;
      vectors.push({ schema: name, fixture: relative(REPO_ROOT, f), expect: "invalid" });
    }
  }
  return { vectors };
}

/**
 * Load `conformance/parity.yaml` and assert every vector's verdict matches
 * the TypeScript side's AJV validator. Returns the list of disagreements.
 */
export async function runParityTs(parityFilePath: string): Promise<{ ok: boolean; mismatches: Array<{ vector: ParityEntry; got: "valid" | "invalid" }> }> {
  const parity = loadFile(parityFilePath) as ParityFile;
  const ajv = buildAjv();
  const mismatches: Array<{ vector: ParityEntry; got: "valid" | "invalid" }> = [];
  for (const v of parity.vectors) {
    const validator = getValidator(ajv, v.schema);
    const doc = loadFile(join(REPO_ROOT, v.fixture));
    const verdict: "valid" | "invalid" = validator(doc) ? "valid" : "invalid";
    if (verdict !== v.expect) mismatches.push({ vector: v, got: verdict });
  }
  return { ok: mismatches.length === 0, mismatches };
}

export function serializeParity(parity: ParityFile): string {
  return yamlStringify(parity);
}
