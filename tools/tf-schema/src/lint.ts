import { listSchemas, loadFile } from "./loader";

export type LintIssue = { file: string; path: string; rule: string; message: string };
export type LintResult = { issues: LintIssue[] };

type JSONValue = string | number | boolean | null | JSONValue[] | { [k: string]: JSONValue };

const ID_PREFIX = "https://trustforge.io/schemas/v0/";

export async function lintSchemas(): Promise<LintResult> {
  const issues: LintIssue[] = [];
  for (const { name, path } of listSchemas()) {
    const schema = loadFile(path) as Record<string, JSONValue>;
    const expectedId = `${ID_PREFIX}${name}.schema.json`;
    if (schema["$id"] !== expectedId) {
      issues.push({
        file: `${name}.schema.json`,
        path: "/$id",
        rule: "id-matches-filename",
        message: `expected ${expectedId}, got ${String(schema["$id"])}`,
      });
    }
    lintOne(name, schema, "", issues);
  }
  return { issues };
}

function isObj(v: JSONValue | undefined): v is { [k: string]: JSONValue } {
  return !!v && typeof v === "object" && !Array.isArray(v);
}

function lintOne(file: string, node: JSONValue, path: string, issues: LintIssue[]): void {
  if (!isObj(node)) {
    if (Array.isArray(node)) for (const [i, v] of node.entries()) lintOne(file, v, `${path}/${i}`, issues);
    return;
  }

  if (node["$ref"] !== undefined) {
    // leaf ref; descend into nothing further
    return;
  }

  if (node["type"] === "object") {
    if (!("additionalProperties" in node) && !("propertyNames" in node)) {
      issues.push({
        file: `${file}.schema.json`,
        path: path || "/",
        rule: "no-extra-props",
        message: "object lacks explicit additionalProperties or propertyNames",
      });
    }
    const props = node["properties"];
    if (isObj(props)) {
      for (const [k, v] of Object.entries(props)) {
        if (isObj(v) && !("description" in v) && !("$ref" in v)) {
          issues.push({
            file: `${file}.schema.json`,
            path: `${path}/properties/${k}`,
            rule: "description-required",
            message: `property '${k}' has no description`,
          });
        }
      }
    }
  }

  for (const [k, v] of Object.entries(node)) {
    lintOne(file, v, `${path}/${k}`, issues);
  }
}
