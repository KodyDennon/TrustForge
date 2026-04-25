import { SCHEMAS_DIR, listSchemas, loadFile } from "../loader";
import { join } from "node:path";

type Node = Record<string, unknown>;

const SPEC_HINTS: Record<string, string> = {
  _common: "underlies every other schema",
  "agent-contract": "TF-0006",
  policy: "TF-0004",
  "threat-model": "TF-0006",
  actions: "TF-0006",
  "proof-profile": "TF-0005",
  conformance: "TF-0010",
  "actor-identity": "TF-0002",
  "capability-token": "TF-0004",
  revocation: "TF-0004",
  "proof-event": "TF-0005",
  "proof-bundle": "TF-0005",
};

export async function generateDocs(): Promise<Record<string, string>> {
  const files: Record<string, string> = {};
  for (const { name } of listSchemas()) {
    const schema = loadFile(join(SCHEMAS_DIR, `${name}.schema.json`)) as Node;
    files[`${name}.md`] = emitPage(name, schema);
  }
  files["index.md"] = emitIndex();
  return files;
}

function emitIndex(): string {
  const lines: string[] = [
    "# TrustForge Schemas",
    "",
    "This directory is generated from `schemas/*.schema.json` by",
    "`tf-schema codegen --target docs`. Do not edit by hand.",
    "",
    "| Schema | Spec | Description |",
    "| --- | --- | --- |",
  ];
  for (const { name } of listSchemas()) {
    const schema = loadFile(join(SCHEMAS_DIR, `${name}.schema.json`)) as Node;
    const spec = SPEC_HINTS[name] ?? "—";
    const desc = ((schema.description as string) ?? "").split(". ")[0];
    lines.push(`| [${name}](./${name}.md) | ${spec} | ${desc} |`);
  }
  lines.push("");
  return lines.join("\n");
}

function emitPage(name: string, schema: Node): string {
  const lines: string[] = [];
  lines.push(`# ${schema.title ?? name}`);
  lines.push("");
  const spec = SPEC_HINTS[name];
  if (spec) lines.push(`> Defined by ${spec}.`);
  lines.push(`> \`$id\`: \`${schema.$id ?? "(none)"}\``);
  lines.push("");
  if (schema.description) {
    lines.push(`${schema.description}`);
    lines.push("");
  }

  if (schema.type === "object" && schema.properties) {
    lines.push("## Fields");
    lines.push("");
    lines.push(fieldsTable(schema));
    lines.push("");
  }

  const defs = (schema.$defs ?? {}) as Record<string, Node>;
  const defNames = Object.keys(defs).sort();
  if (defNames.length > 0) {
    lines.push("## `$defs`");
    lines.push("");
    for (const n of defNames) {
      const def = defs[n]!;
      lines.push(`### \`${n}\``);
      lines.push("");
      if (def.description) lines.push(`${def.description}`);
      lines.push("");
      if (def.type === "object" && def.properties) {
        lines.push(fieldsTable(def));
        lines.push("");
      } else if (Array.isArray(def.enum)) {
        lines.push(`Enum: ${(def.enum as string[]).map((v) => `\`${v}\``).join(", ")}`);
        lines.push("");
      } else if (def.oneOf) {
        lines.push("Discriminated union:");
        lines.push("");
        for (const variant of def.oneOf as Node[]) {
          const props = (variant.properties as Record<string, Node>) ?? {};
          const tag = (props.kind?.const as string) ?? "(untagged)";
          lines.push(`- \`kind: "${tag}"\``);
          for (const [k, v] of Object.entries(props)) {
            if (k === "kind") continue;
            const required = (variant.required as string[] | undefined)?.includes(k) ? " *(required)*" : "";
            lines.push(`  - \`${k}\`${required}: ${renderType(v)}`);
          }
        }
        lines.push("");
      } else {
        lines.push(`Type: ${renderType(def)}`);
        lines.push("");
      }
    }
  }

  return lines.join("\n");
}

function fieldsTable(node: Node): string {
  const properties = (node.properties ?? {}) as Record<string, Node>;
  const required = new Set<string>((node.required as string[]) ?? []);
  const rows: string[] = ["| Field | Type | Required | Description |", "| --- | --- | --- | --- |"];
  for (const [name, prop] of Object.entries(properties)) {
    const r = required.has(name) ? "✓" : "·";
    rows.push(`| \`${name}\` | ${renderType(prop)} | ${r} | ${escapeMd((prop.description as string) ?? "")} |`);
  }
  return rows.join("\n");
}

function renderType(node: Node | undefined): string {
  if (!node) return "_unknown_";
  if (typeof node.$ref === "string") {
    const parsed = parseRef(node.$ref);
    if (parsed.schema && parsed.def) return `[\`${parsed.def}\`](./${parsed.schema}.md#${parsed.def.toLowerCase()})`;
    if (parsed.def) return `\`${parsed.def}\``;
    if (parsed.schema) return `[\`${parsed.schema}\`](./${parsed.schema}.md)`;
    return `\`${node.$ref}\``;
  }
  if (Array.isArray(node.enum) && node.enum.every((v) => typeof v === "string")) {
    return (node.enum as string[]).map((v) => `\`"${v}"\``).join(" \\| ");
  }
  if (typeof node.const === "string") return `\`"${node.const}"\``;
  if (node.type === "string") {
    const extras: string[] = [];
    if (typeof node.pattern === "string") extras.push(`pattern: \`${node.pattern}\``);
    if (typeof node.minLength === "number") extras.push(`minLength: ${node.minLength}`);
    return extras.length > 0 ? `string (${extras.join(", ")})` : "string";
  }
  if (node.type === "integer") return `integer${typeof node.minimum === "number" ? ` (≥ ${node.minimum})` : ""}`;
  if (node.type === "number") return "number";
  if (node.type === "boolean") return "boolean";
  if (node.type === "array") {
    const item = renderType(node.items as Node);
    const m: string[] = [];
    if (typeof node.minItems === "number") m.push(`minItems: ${node.minItems}`);
    return m.length > 0 ? `array of ${item} (${m.join(", ")})` : `array of ${item}`;
  }
  if (node.type === "object") return "object";
  if (node.oneOf) return (node.oneOf as Node[]).map(renderType).join(" \\| ");
  return "_unknown_";
}

function parseRef(ref: string): { schema?: string; def?: string } {
  if (ref.startsWith("#")) return { def: ref.split("/$defs/")[1] };
  const [filePart, fragment] = ref.split("#");
  const schema = filePart!.replace(/\.schema\.json$/, "");
  if (fragment?.startsWith("/$defs/")) return { schema, def: fragment.slice("/$defs/".length) };
  return { schema };
}

function escapeMd(s: string): string {
  return s.replace(/\|/g, "\\|").replace(/\n/g, " ");
}

export async function writeDocsOutput(outDir: string): Promise<string[]> {
  const { writeFileSync, mkdirSync } = await import("node:fs");
  mkdirSync(outDir, { recursive: true });
  const files = await generateDocs();
  for (const [name, content] of Object.entries(files)) {
    writeFileSync(`${outDir}/${name}`, content);
  }
  return Object.keys(files);
}
