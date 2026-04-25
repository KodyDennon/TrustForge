import { join, relative } from "node:path";
import { type ErrorObject } from "ajv/dist/2020.js";
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

export type ExpectedError = {
  path: string;
  keyword: string;
  params_missing?: string;
};

export type Mismatch = {
  file: string;
  kind: "valid-failed" | "invalid-passed" | "invalid-wrong-error";
  got?: ErrorObject[];
  expected?: ExpectedError[];
};

export type ValidateAllResult = {
  ok: boolean;
  summary: { validPassed: number; invalidMatched: number; mismatches: Mismatch[] };
};

export async function runValidateAll(opts?: { schema?: string }): Promise<ValidateAllResult> {
  const ajv = buildAjv();
  const schemas = listSchemas().filter((s) => !opts?.schema || s.name === opts.schema);
  const mismatches: Mismatch[] = [];
  let validPassed = 0;
  let invalidMatched = 0;

  for (const { name } of schemas) {
    if (name === "_common") continue;
    const validDir = join(FIXTURES_DIR, name, "valid");
    const invalidDir = join(FIXTURES_DIR, name, "invalid");
    const validator = getValidator(ajv, name);

    for (const f of walkFiles(validDir, YAML_JSON)) {
      const doc = loadFile(f);
      if (validator(doc)) {
        validPassed++;
      } else {
        mismatches.push({
          file: relative(REPO_ROOT, f),
          kind: "valid-failed",
          got: validator.errors ?? [],
        });
      }
    }

    for (const f of walkFiles(invalidDir, YAML_JSON)) {
      if (f.endsWith(".expected-error.yaml")) continue;
      const doc = loadFile(f);
      const passed = validator(doc);
      const expectPath = f.replace(/\.(yaml|yml|json)$/, ".expected-error.yaml");
      const expected = (loadFile(expectPath) as { errors: ExpectedError[] }).errors;

      if (passed) {
        mismatches.push({ file: relative(REPO_ROOT, f), kind: "invalid-passed", expected });
        continue;
      }
      if (matchesExpected(validator.errors ?? [], expected)) {
        invalidMatched++;
      } else {
        mismatches.push({
          file: relative(REPO_ROOT, f),
          kind: "invalid-wrong-error",
          got: validator.errors ?? [],
          expected,
        });
      }
    }
  }

  return { ok: mismatches.length === 0, summary: { validPassed, invalidMatched, mismatches } };
}

function matchesExpected(got: ErrorObject[], expected: ExpectedError[]): boolean {
  return expected.every((e) =>
    got.some((g) => {
      if (g.keyword !== e.keyword) return false;
      if (g.instancePath !== e.path) return false;
      if (e.params_missing && e.keyword === "required") {
        return (g.params as { missingProperty?: string }).missingProperty === e.params_missing;
      }
      return true;
    }),
  );
}

export function formatResult(result: ValidateAllResult): string {
  const { validPassed, invalidMatched, mismatches } = result.summary;
  const lines = [`valid:   ${validPassed} ok`, `invalid: ${invalidMatched} matched`];
  for (const m of mismatches) {
    lines.push(`FAIL ${m.kind} ${m.file}`);
    if (m.got) for (const e of m.got) lines.push(`  got ${e.instancePath || "/"} ${e.keyword} ${e.message ?? ""}`);
    if (m.expected) for (const e of m.expected) lines.push(`  expected ${e.path} ${e.keyword}${e.params_missing ? ` (missing ${e.params_missing})` : ""}`);
  }
  return lines.join("\n");
}
