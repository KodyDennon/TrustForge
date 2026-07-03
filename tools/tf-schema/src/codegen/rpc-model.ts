import { readFileSync } from "node:fs";
import { parseYaml as parseYAML } from "@trustforge-protocol/types";
import { pascal, type TypeDecl } from "./model";

type Node = Record<string, unknown>;

export interface RpcMethod {
  name: string;
  kind: "unary" | "server-streaming";
  description?: string;
  capability: string;
  risk: string;
  proof?: string;
  approval?: string;
  requestTypeName: string;
  responseTypeName: string;
  decls: TypeDecl[]; // request + response + any hoisted nested types
}

export interface RpcServiceModel {
  serviceId: string;
  description?: string;
  methods: RpcMethod[];
}

export function loadRpcSpec(path: string): RpcServiceModel {
  const raw = readFileSync(path, "utf8");
  const spec = parseYAML(raw) as Node;
  const serviceId = String(spec.service_id);
  const description = (spec.description as string | undefined) ?? undefined;

  const rawMethods = (spec.methods as Node[]) ?? [];
  const methods: RpcMethod[] = [];

  for (const raw of rawMethods) {
    const name = String(raw.name);
    const kind = String(raw.kind) as RpcMethod["kind"];
    const capability = String(raw.capability);
    const risk = String(raw.risk);
    const pascalName = pascal(name);
    const requestTypeName = `${pascalName}Request`;
    const responseTypeName = `${pascalName}Response`;

    const requestSchema = hoist(
      cloneJSON(raw.request as Node),
      requestTypeName,
    );
    const responseSchema = hoist(
      cloneJSON(raw.response as Node),
      responseTypeName,
    );

    const decls: TypeDecl[] = [];
    appendDecls(decls, requestTypeName, requestSchema);
    appendDecls(decls, responseTypeName, responseSchema);

    methods.push({
      name,
      kind,
      description: raw.description as string | undefined,
      capability,
      risk,
      proof: raw.proof as string | undefined,
      approval: raw.approval as string | undefined,
      requestTypeName,
      responseTypeName,
      decls,
    });
  }

  return { serviceId, description, methods };
}

function cloneJSON<T>(v: T): T {
  return JSON.parse(JSON.stringify(v)) as T;
}

function appendDecls(out: TypeDecl[], rootName: string, schema: Node): void {
  const defs = ((schema.$defs as Record<string, Node>) ?? {});
  for (const [name, def] of Object.entries(defs)) {
    out.push(declForNode(name, def));
  }
  if (schema.type === "object" && schema.properties) {
    out.push(declForNode(rootName, schema));
  } else if (Array.isArray(schema.enum) && schema.enum.every((v: unknown) => typeof v === "string")) {
    out.push({
      kind: "enum",
      name: rootName,
      description: schema.description as string | undefined,
      enumValues: schema.enum as string[],
    });
  } else if (schema.type === "string") {
    out.push({
      kind: "alias",
      name: rootName,
      description: schema.description as string | undefined,
      tsType: "string",
      rustType: "String",
    });
  }
}

function declForNode(name: string, node: Node): TypeDecl {
  if (Array.isArray(node.enum) && node.enum.every((v) => typeof v === "string")) {
    return {
      kind: "enum",
      name,
      description: node.description as string | undefined,
      enumValues: node.enum as string[],
    };
  }
  if (node.type === "object" && node.properties) {
    const required = new Set<string>((node.required as string[]) ?? []);
    const props = Object.entries(node.properties as Record<string, Node>).map(([k, v]) => ({
      name: k,
      required: required.has(k),
      description: v.description as string | undefined,
      tsType: tsType(v),
      rustType: rustType(v),
    }));
    return {
      kind: "struct",
      name,
      description: node.description as string | undefined,
      props,
    };
  }
  if (node.type === "string") {
    return {
      kind: "alias",
      name,
      description: node.description as string | undefined,
      tsType: "string",
      rustType: "String",
    };
  }
  return {
    kind: "alias",
    name,
    description: node.description as string | undefined,
    tsType: tsType(node),
    rustType: rustType(node),
  };
}

function tsType(node: Node | undefined): string {
  if (!node) return "unknown";
  if (typeof node.$ref === "string") {
    const parts = node.$ref.split("/$defs/");
    return parts[parts.length - 1] ?? "unknown";
  }
  if (Array.isArray(node.enum) && node.enum.every((v) => typeof v === "string")) {
    return (node.enum as string[]).map((v) => JSON.stringify(v)).join(" | ");
  }
  if (node.type === "string") return "string";
  if (node.type === "integer" || node.type === "number") return "number";
  if (node.type === "boolean") return "boolean";
  if (node.type === "array") return `${tsType(node.items as Node)}[]`;
  if (node.type === "object") return "Record<string, unknown>";
  return "unknown";
}

function rustType(node: Node | undefined): string {
  if (!node) return "serde_json::Value";
  if (typeof node.$ref === "string") {
    const parts = node.$ref.split("/$defs/");
    return parts[parts.length - 1] ?? "serde_json::Value";
  }
  if (Array.isArray(node.enum) && node.enum.every((v) => typeof v === "string")) {
    return "String";
  }
  if (node.type === "string") return "String";
  if (node.type === "integer") return "i64";
  if (node.type === "number") return "f64";
  if (node.type === "boolean") return "bool";
  if (node.type === "array") return `Vec<${rustType(node.items as Node)}>`;
  return "serde_json::Value";
}

/**
 * Walk the schema and hoist every inline object-with-properties into a named
 * $def. Returns the schema with inline objects replaced by $refs.
 */
function hoist(schema: Node, rootName: string): Node {
  const defs: Record<string, Node> = (schema.$defs as Record<string, Node>) ?? {};
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
      if (shouldHoist(items)) node.items = hoistProp(items, `${parentName}_Item`);
      walk(node.items as Node, `${parentName}_Item`);
    }
  }

  function shouldHoist(v: Node): boolean {
    if (typeof v.$ref === "string") return false;
    if (v.type === "object" && v.properties && typeof v.properties === "object") return true;
    if (Array.isArray(v.enum) && v.enum.every((x) => typeof x === "string") && v.enum.length > 0) return true;
    return false;
  }

  function hoistProp(v: Node, preferredName: string): Node {
    if (!shouldHoist(v)) return v;
    const name = uniqueName(preferredName);
    const description = typeof v.description === "string" ? v.description : undefined;
    defs[name] = v;
    const ref: Node = { $ref: `#/$defs/${name}` };
    if (description) ref.description = description;
    return ref;
  }

  walk(schema, rootName);
  return schema;
}
