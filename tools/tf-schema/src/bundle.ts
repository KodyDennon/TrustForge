import { join } from "node:path";
import { SCHEMAS_DIR, listSchemas, loadFile } from "./loader";

type Obj = Record<string, unknown>;

/**
 * Resolve every cross-file $ref in the named schema into an inline $defs
 * entry at the bundle root. Produces a self-contained JSON Schema that
 * downstream codegen can consume without needing the surrounding directory.
 */
export async function bundleSchema(name: string): Promise<Obj> {
  const registry: Record<string, Obj> = {};
  for (const s of listSchemas()) registry[s.name] = loadFile(s.path) as Obj;

  const crossFileDefs: Record<string, unknown> = {};

  function crossName(schemaName: string, defName: string): string {
    return `${toPascal(schemaName)}_${defName}`;
  }

  function resolve(node: unknown, currentFile: string): unknown {
    if (Array.isArray(node)) return node.map((v) => resolve(v, currentFile));
    if (!node || typeof node !== "object") return node;
    const obj = node as Obj;
    const ref = obj["$ref"];
    if (typeof ref === "string") {
      if (ref.startsWith("#")) {
        if (currentFile === name) return { ...obj };
        // Same-file ref within an *imported* schema → hoist into crossFileDefs.
        const defName = ref.split("/$defs/")[1]!;
        const newName = crossName(currentFile, defName);
        ensureCrossDef(currentFile, defName, newName);
        return { $ref: `#/$defs/${newName}` };
      }
      const [filePart, fragment] = ref.split("#");
      const schemaName = filePart!.replace(/\.schema\.json$/, "");
      if (fragment && fragment.startsWith("/$defs/")) {
        const defName = fragment.slice("/$defs/".length);
        const newName = crossName(schemaName, defName);
        ensureCrossDef(schemaName, defName, newName);
        return { $ref: `#/$defs/${newName}` };
      }
      // Whole-schema cross-file ref (e.g. proof-bundle → proof-event.schema.json).
      const rootName = `${toPascal(schemaName)}_root`;
      ensureCrossRoot(schemaName, rootName);
      return { $ref: `#/$defs/${rootName}` };
    }
    const out: Obj = {};
    for (const [k, v] of Object.entries(obj)) {
      if (k === "$id" || k === "$schema") continue;
      out[k] = resolve(v, currentFile);
    }
    return out;
  }

  function ensureCrossDef(schemaName: string, defName: string, newName: string): void {
    if (newName in crossFileDefs) return;
    const source = registry[schemaName];
    if (!source) throw new Error(`unknown schema in $ref: ${schemaName}`);
    const defs = source["$defs"] as Obj | undefined;
    const def = defs?.[defName];
    if (def === undefined) throw new Error(`unknown $def: ${schemaName}#/$defs/${defName}`);
    crossFileDefs[newName] = {};
    crossFileDefs[newName] = resolve(def, schemaName);
  }

  function ensureCrossRoot(schemaName: string, newName: string): void {
    if (newName in crossFileDefs) return;
    const source = registry[schemaName];
    if (!source) throw new Error(`unknown schema in $ref: ${schemaName}`);
    const { $id: _id, $schema: _schema, $defs: srcDefs, ...rest } = source;
    crossFileDefs[newName] = {};
    crossFileDefs[newName] = resolve(rest as Obj, schemaName);
    for (const [defName, def] of Object.entries((srcDefs as Obj) ?? {})) {
      const prefixed = crossName(schemaName, defName);
      if (!(prefixed in crossFileDefs)) {
        crossFileDefs[prefixed] = {};
        crossFileDefs[prefixed] = resolve(def, schemaName);
      }
    }
  }

  const root = registry[name];
  if (!root) throw new Error(`unknown schema: ${name}`);
  const resolvedRoot = resolve(root, name) as Obj;
  const mergedDefs: Obj = { ...((resolvedRoot["$defs"] as Obj) ?? {}), ...crossFileDefs };
  if (Object.keys(mergedDefs).length > 0) resolvedRoot["$defs"] = mergedDefs;
  resolvedRoot["$id"] = root["$id"];
  resolvedRoot["$schema"] = root["$schema"];
  return resolvedRoot;
}

function toPascal(s: string): string {
  return s
    .split(/[-_]/)
    .filter((p) => p.length > 0)
    .map((p) => p.charAt(0).toUpperCase() + p.slice(1))
    .join("");
}
