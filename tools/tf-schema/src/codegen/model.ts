import { listSchemas, loadFile, SCHEMAS_DIR } from "../loader";
import { join } from "node:path";

type Node = Record<string, unknown>;

export type Prop = {
  name: string;
  required: boolean;
  description?: string;
  tsType: string;
  rustType: string;
};

export type Variant = {
  name: string;
  tag: string;
  description?: string;
  props: Prop[];
};

export type TypeDecl =
  | { kind: "alias"; name: string; description?: string; tsType: string; rustType: string }
  | { kind: "enum"; name: string; description?: string; enumValues: string[] }
  | { kind: "struct"; name: string; description?: string; props: Prop[] }
  | { kind: "union"; name: string; description?: string; tsType: string; rustType: string }
  | { kind: "tagged-union"; name: string; description?: string; variants: Variant[] };

export type SchemaModel = {
  schemaName: string;
  rootDeclName?: string;
  decls: TypeDecl[];
};

export function pascal(s: string): string {
  return s
    .split(/[-_./]/)
    .filter((p) => p.length > 0)
    .map((p) => p.charAt(0).toUpperCase() + p.slice(1))
    .join("");
}

/** A $ref string → (schemaName, defName) | (schemaName, null for whole-schema) */
function parseRef(ref: string): { schema?: string; def?: string } {
  if (ref.startsWith("#")) {
    return { def: ref.split("/$defs/")[1] };
  }
  const [filePart, fragment] = ref.split("#");
  const schema = filePart!.replace(/\.schema\.json$/, "");
  if (fragment?.startsWith("/$defs/")) return { schema, def: fragment.slice("/$defs/".length) };
  return { schema };
}

function refTypeName(ref: string, currentSchema: string): string {
  const parsed = parseRef(ref);
  if (parsed.def && !parsed.schema) return parsed.def;
  if (parsed.schema && parsed.def) return parsed.def;
  if (parsed.schema && !parsed.def) return pascal(parsed.schema);
  return "unknown";
}

export function tsTypeOf(node: Node | undefined, currentSchema: string): string {
  if (!node) return "unknown";
  if (typeof node.$ref === "string") return refTypeName(node.$ref, currentSchema);
  if (Array.isArray(node.enum) && node.enum.every((v) => typeof v === "string")) {
    return (node.enum as string[]).map((v) => JSON.stringify(v)).join(" | ");
  }
  if (typeof node.const === "string") return JSON.stringify(node.const);
  if (node.type === "string") return "string";
  if (node.type === "integer" || node.type === "number") return "number";
  if (node.type === "boolean") return "boolean";
  if (node.type === "array") return `${tsTypeOf(node.items as Node, currentSchema)}[]`;
  if (node.type === "object") {
    if (node.additionalProperties && typeof node.additionalProperties === "object") {
      return `Record<string, ${tsTypeOf(node.additionalProperties as Node, currentSchema)}>`;
    }
    return "Record<string, unknown>";
  }
  if (Array.isArray(node.oneOf)) return (node.oneOf as Node[]).map((v) => tsTypeOf(v, currentSchema)).join(" | ");
  if (Array.isArray(node.anyOf)) return (node.anyOf as Node[]).map((v) => tsTypeOf(v, currentSchema)).join(" | ");
  return "unknown";
}

export function rustTypeOf(node: Node | undefined, currentSchema: string, boxed = false): string {
  if (!node) return "serde_json::Value";
  if (typeof node.$ref === "string") {
    const base = refTypeName(node.$ref, currentSchema);
    return boxed ? `Box<${base}>` : base;
  }
  if (Array.isArray(node.enum) && node.enum.every((v) => typeof v === "string")) {
    return "String";
  }
  if (typeof node.const === "string") return "String";
  if (node.type === "string") return "String";
  if (node.type === "integer") return "i64";
  if (node.type === "number") return "f64";
  if (node.type === "boolean") return "bool";
  if (node.type === "array") return `Vec<${rustTypeOf(node.items as Node, currentSchema)}>`;
  if (node.type === "object") {
    if (node.additionalProperties === true) return "serde_json::Value";
    if (node.additionalProperties && typeof node.additionalProperties === "object") {
      return `std::collections::BTreeMap<String, ${rustTypeOf(node.additionalProperties as Node, currentSchema)}>`;
    }
    return "serde_json::Value";
  }
  if (Array.isArray(node.oneOf) || Array.isArray(node.anyOf)) return "serde_json::Value";
  return "serde_json::Value";
}

function declForNamed(name: string, node: Node, schemaName: string): TypeDecl {
  if (Array.isArray(node.enum) && node.enum.every((v) => typeof v === "string")) {
    return { kind: "enum", name, description: node.description as string | undefined, enumValues: node.enum as string[] };
  }
  if (node.type === "object" && node.properties) {
    const required = new Set<string>((node.required as string[]) ?? []);
    const props: Prop[] = Object.entries(node.properties as Record<string, Node>).map(([k, v]) => ({
      name: k,
      required: required.has(k),
      description: v.description as string | undefined,
      tsType: tsTypeOf(v, schemaName),
      rustType: rustTypeOf(v, schemaName),
    }));
    return { kind: "struct", name, description: node.description as string | undefined, props };
  }
  if (Array.isArray(node.oneOf)) {
    // Tagged union if every variant has a `kind: const` discriminator.
    const variants = node.oneOf as Node[];
    const tagged = variants.every((v) => {
      const props = v.properties as Record<string, Node> | undefined;
      return props && typeof props.kind === "object" && typeof props.kind.const === "string";
    });
    if (tagged) {
      const v: Variant[] = variants.map((variant) => {
        const props = variant.properties as Record<string, Node>;
        const required = new Set<string>((variant.required as string[]) ?? []);
        const tag = props.kind!.const as string;
        const vprops: Prop[] = Object.entries(props)
          .filter(([k]) => k !== "kind")
          .map(([k, v]) => ({
            name: k,
            required: required.has(k),
            description: v.description as string | undefined,
            tsType: tsTypeOf(v, schemaName),
            rustType: rustTypeOf(v, schemaName),
          }));
        return { name: pascal(tag), tag, description: variant.description as string | undefined, props: vprops };
      });
      return { kind: "tagged-union", name, description: node.description as string | undefined, variants: v };
    }
    return {
      kind: "union",
      name,
      description: node.description as string | undefined,
      tsType: variants.map((v) => tsTypeOf(v, schemaName)).join(" | "),
      rustType: "serde_json::Value",
    };
  }
  if (node.type === "string") {
    return { kind: "alias", name, description: node.description as string | undefined, tsType: "string", rustType: "String" };
  }
  return {
    kind: "alias",
    name,
    description: node.description as string | undefined,
    tsType: tsTypeOf(node, schemaName),
    rustType: rustTypeOf(node, schemaName),
  };
}

/**
 * Hoist inline `type:"object"` with `properties`, inline `enum`, and inline
 * `oneOf` discriminated unions into named `$defs` entries. Mutates the
 * schema in-place and returns it. The generated type name is
 * `<ParentName>_<PropKey>` in PascalCase; arrays become `<ParentName>_Item`.
 * Stops recursing past `$ref` leaves.
 */
function hoistInlineTypes(schema: Node, schemaName: string): Node {
  const defs: Record<string, Node> = (schema.$defs ?? {}) as Record<string, Node>;
  schema.$defs = defs;

  const taken = new Set<string>(Object.keys(defs));
  function uniqueName(base: string): string {
    let n = base;
    let i = 2;
    while (taken.has(n)) {
      n = `${base}${i++}`;
    }
    taken.add(n);
    return n;
  }

  function walk(node: Node, parentName: string): void {
    if (!node || typeof node !== "object") return;
    if (typeof node.$ref === "string") return;
    const props = node.properties as Record<string, Node> | undefined;
    if (props) {
      for (const [k, v] of Object.entries(props)) {
        if (v && typeof v === "object" && !Array.isArray(v)) {
          props[k] = hoistProp(v, `${parentName}_${pascal(k)}`);
          walk(props[k], `${parentName}_${pascal(k)}`);
        }
      }
    }
    if (node.items && typeof node.items === "object") {
      const items = node.items as Node;
      if (typeof items.$ref !== "string" && shouldHoist(items)) {
        node.items = hoistProp(items, `${parentName}_Item`);
      }
      walk(node.items as Node, `${parentName}_Item`);
    }
    if (Array.isArray(node.oneOf)) {
      for (let i = 0; i < node.oneOf.length; i++) {
        walk(node.oneOf[i] as Node, `${parentName}_Variant${i}`);
      }
    }
    if (Array.isArray(node.allOf)) {
      for (let i = 0; i < node.allOf.length; i++) {
        walk(node.allOf[i] as Node, `${parentName}_AllOf${i}`);
      }
    }
  }

  function shouldHoist(v: Node): boolean {
    if (typeof v.$ref === "string") return false;
    if (v.type === "object" && v.properties && typeof v.properties === "object") return true;
    if (Array.isArray(v.enum) && v.enum.every((x) => typeof x === "string") && v.enum.length > 0) return true;
    if (Array.isArray(v.oneOf)) return true;
    return false;
  }

  function hoistProp(v: Node, preferredName: string): Node {
    if (!shouldHoist(v)) return v;
    const name = uniqueName(preferredName);
    // Preserve description on the $ref site so docs/tests still see it.
    const description = typeof v.description === "string" ? v.description : undefined;
    defs[name] = v;
    const ref: Node = { $ref: `#/$defs/${name}` };
    if (description) ref.description = description;
    return ref;
  }

  // Walk each existing $def so hoisting is transitive.
  for (const [defName, def] of Object.entries({ ...defs })) {
    walk(def as Node, defName);
  }

  // Walk the root.
  if (schema.type === "object" && schema.properties) {
    walk(schema, pascal(schemaName));
  }

  return schema;
}

export function buildModel(schemaName: string): SchemaModel {
  const raw = loadFile(join(SCHEMAS_DIR, `${schemaName}.schema.json`)) as Node;
  const schema = hoistInlineTypes(structuredCloneDeep(raw), schemaName);
  const decls: TypeDecl[] = [];
  const defs = (schema.$defs ?? {}) as Record<string, Node>;
  for (const [name, def] of Object.entries(defs)) {
    decls.push(declForNamed(name, def, schemaName));
  }
  let rootDeclName: string | undefined;
  if (schema.type === "object" && schema.properties) {
    rootDeclName = pascal(schemaName);
    decls.push(declForNamed(rootDeclName, schema, schemaName));
  }
  return { schemaName, rootDeclName, decls };
}

function structuredCloneDeep<T>(v: T): T {
  return JSON.parse(JSON.stringify(v)) as T;
}

export function allModels(): SchemaModel[] {
  return listSchemas().map((s) => buildModel(s.name));
}

/** TypeName → schemaName that owns it. Used by emitters to write cross-file imports. */
export function buildSymbolRegistry(models: SchemaModel[]): Map<string, string> {
  const reg = new Map<string, string>();
  for (const m of models) for (const d of m.decls) reg.set(d.name, m.schemaName);
  // Also register root-schema type names so whole-schema $refs resolve.
  for (const m of models) if (m.rootDeclName) reg.set(m.rootDeclName, m.schemaName);
  return reg;
}
