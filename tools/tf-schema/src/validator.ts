/**
 * In-house JSON Schema (draft 2020-12 subset) validator — replaces `ajv`
 * for TrustForge's schema surface; see `docs/dependency-audit.md`.
 *
 * Implements exactly the keywords the `schemas/*.schema.json` corpus
 * uses (compile fails loudly on anything else, preserving ajv's
 * `strict: true` behavior): type, enum, const, properties, required,
 * additionalProperties, propertyNames, items, prefixItems, minItems,
 * maxItems, minLength, maxLength, pattern, minimum, maximum,
 * exclusiveMinimum/Maximum, multipleOf, $ref (local `#/$defs/…` and
 * cross-file `x.schema.json#/$defs/…`), $defs, if/then/else,
 * allOf/anyOf/oneOf/not. `contentEncoding` and the metadata keywords
 * are annotations, per 2020-12.
 *
 * Error objects mirror ajv's shape (`instancePath`, `keyword`,
 * `params.missingProperty`, …) because the `.expected-error.yaml`
 * fixtures pin them — `bun run validate:all` over every fixture is the
 * conformance gate for this engine.
 */

export interface ErrorObject {
  instancePath: string;
  schemaPath: string;
  keyword: string;
  message: string;
  params: Record<string, unknown>;
}

export interface ValidateFunction {
  (data: unknown): boolean;
  errors: ErrorObject[] | null;
  schema: unknown;
}

/** Compile-time schema problem (unknown keyword, bad ref, bad pattern). */
export class SchemaCompileError extends Error {}

const KNOWN_KEYWORDS = new Set([
  // applicators / validators
  "type",
  "enum",
  "const",
  "properties",
  "patternProperties",
  "required",
  "additionalProperties",
  "propertyNames",
  "items",
  "prefixItems",
  "minItems",
  "maxItems",
  "uniqueItems",
  "minLength",
  "maxLength",
  "pattern",
  "minimum",
  "maximum",
  "exclusiveMinimum",
  "exclusiveMaximum",
  "multipleOf",
  "minProperties",
  "maxProperties",
  "$ref",
  "if",
  "then",
  "else",
  "allOf",
  "anyOf",
  "oneOf",
  "not",
  // annotations
  "$schema",
  "$id",
  "$defs",
  "definitions",
  "$comment",
  "title",
  "description",
  "default",
  "examples",
  "deprecated",
  "contentEncoding",
  "contentMediaType",
]);

type Schema = Record<string, unknown> | boolean;

interface Ctx {
  /** Document the current schema node lives in (for `#/…` refs). */
  doc: Record<string, unknown>;
  errors: ErrorObject[];
  registry: SchemaRegistry;
  /** Compiled-regex cache. */
  regexes: Map<string, RegExp>;
}

export class SchemaRegistry {
  private docs = new Map<string, Record<string, unknown>>();
  private validators = new Map<string, ValidateFunction>();

  addSchema(schema: object, key: string): void {
    const doc = schema as Record<string, unknown>;
    this.docs.set(key, doc);
    if (typeof doc["$id"] === "string") {
      this.docs.set(doc["$id"] as string, doc);
    }
    checkKeywords(doc, key);
  }

  /** Resolve a document by ref target: exact key, $id, or basename. */
  resolveDoc(target: string): Record<string, unknown> | undefined {
    const direct = this.docs.get(target);
    if (direct) return direct;
    const base = target.split("/").pop()!;
    return this.docs.get(base);
  }

  getSchema(key: string): ValidateFunction | undefined {
    const cached = this.validators.get(key);
    if (cached) return cached;
    const doc = this.docs.get(key);
    if (!doc) return undefined;
    const fn = this.buildValidator(doc);
    this.validators.set(key, fn);
    return fn;
  }

  /** Compile a standalone (self-contained or registry-referencing) schema. */
  compile(schema: object): ValidateFunction {
    checkKeywords(schema as Record<string, unknown>, "(inline)");
    return this.buildValidator(schema as Record<string, unknown>);
  }

  private buildValidator(doc: Record<string, unknown>): ValidateFunction {
    const registry = this;
    const fn = ((data: unknown): boolean => {
      const ctx: Ctx = { doc, errors: [], registry, regexes: new Map() };
      validateNode(doc, data, "", "#", ctx);
      fn.errors = ctx.errors.length > 0 ? ctx.errors : null;
      return ctx.errors.length === 0;
    }) as ValidateFunction;
    fn.errors = null;
    fn.schema = doc;
    return fn;
  }
}

function checkKeywords(node: unknown, where: string): void {
  if (Array.isArray(node)) {
    node.forEach((item) => checkKeywords(item, where));
    return;
  }
  if (!node || typeof node !== "object") return;
  for (const [k, v] of Object.entries(node)) {
    if (!KNOWN_KEYWORDS.has(k)) {
      throw new SchemaCompileError(`${where}: unknown schema keyword ${JSON.stringify(k)}`);
    }
    switch (k) {
      case "properties":
      case "patternProperties":
      case "$defs":
      case "definitions":
        for (const sub of Object.values(v as Record<string, unknown>)) {
          checkKeywords(sub, where);
        }
        break;
      case "enum":
      case "examples":
      case "const":
      case "default":
        break; // data, not schema
      default:
        if (typeof v === "object" && v !== null) checkKeywords(v, where);
    }
  }
}

/* ------------------------------------------------------------------ */
/*  Core validation                                                    */
/* ------------------------------------------------------------------ */

function deepEqual(a: unknown, b: unknown): boolean {
  if (a === b) return true;
  if (Array.isArray(a) && Array.isArray(b)) {
    return a.length === b.length && a.every((x, i) => deepEqual(x, b[i]));
  }
  if (a && b && typeof a === "object" && typeof b === "object") {
    const ka = Object.keys(a as object);
    const kb = Object.keys(b as object);
    if (ka.length !== kb.length) return false;
    return ka.every((k) =>
      deepEqual((a as Record<string, unknown>)[k], (b as Record<string, unknown>)[k]),
    );
  }
  return false;
}

function typeOf(data: unknown): string {
  if (data === null) return "null";
  if (Array.isArray(data)) return "array";
  return typeof data;
}

function matchesType(data: unknown, t: string): boolean {
  switch (t) {
    case "null":
      return data === null;
    case "array":
      return Array.isArray(data);
    case "object":
      return typeof data === "object" && data !== null && !Array.isArray(data);
    case "string":
      return typeof data === "string";
    case "boolean":
      return typeof data === "boolean";
    case "number":
      return typeof data === "number";
    case "integer":
      return typeof data === "number" && Number.isInteger(data);
    default:
      return false;
  }
}

function regex(ctx: Ctx, pattern: string): RegExp {
  let re = ctx.regexes.get(pattern);
  if (!re) {
    // ajv compiles with the `u` flag by default (unicodeRegExp: true).
    re = new RegExp(pattern, "u");
    ctx.regexes.set(pattern, re);
  }
  return re;
}

/** Unicode length (code points), matching ajv's string counting. */
function ucLength(s: string): number {
  let n = 0;
  for (const _ of s) n++;
  return n;
}

function escapePointer(segment: string): string {
  return segment.replace(/~/g, "~0").replace(/\//g, "~1");
}

function resolvePointer(doc: Record<string, unknown>, pointer: string): unknown {
  if (pointer === "" || pointer === "/") return doc;
  let node: unknown = doc;
  for (const raw of pointer.replace(/^\//, "").split("/")) {
    const seg = raw.replace(/~1/g, "/").replace(/~0/g, "~");
    if (node && typeof node === "object") {
      node = (node as Record<string, unknown>)[seg];
    } else {
      return undefined;
    }
  }
  return node;
}

function resolveRef(
  ref: string,
  ctx: Ctx,
): { schema: Schema; doc: Record<string, unknown> } {
  const [target, pointer = ""] = ref.split("#") as [string, string?];
  const doc = target === "" ? ctx.doc : ctx.registry.resolveDoc(target);
  if (!doc) {
    throw new SchemaCompileError(`cannot resolve $ref document ${JSON.stringify(ref)}`);
  }
  const schema = resolvePointer(doc, pointer ?? "");
  if (schema === undefined) {
    throw new SchemaCompileError(`cannot resolve $ref pointer ${JSON.stringify(ref)}`);
  }
  return { schema: schema as Schema, doc };
}

function validateNode(
  schema: Schema,
  data: unknown,
  instancePath: string,
  schemaPath: string,
  ctx: Ctx,
): boolean {
  if (schema === true) return true;
  if (schema === false) {
    ctx.errors.push({
      instancePath,
      schemaPath,
      keyword: "false schema",
      message: "boolean schema is false",
      params: {},
    });
    return false;
  }
  const before = ctx.errors.length;
  const s = schema;

  if (typeof s["$ref"] === "string") {
    const { schema: target, doc } = resolveRef(s["$ref"], ctx);
    const savedDoc = ctx.doc;
    ctx.doc = doc;
    validateNode(target, data, instancePath, `${schemaPath}/$ref`, ctx);
    ctx.doc = savedDoc;
  }

  if (s["type"] !== undefined) {
    const types = Array.isArray(s["type"]) ? (s["type"] as string[]) : [s["type"] as string];
    if (!types.some((t) => matchesType(data, t))) {
      ctx.errors.push({
        instancePath,
        schemaPath: `${schemaPath}/type`,
        keyword: "type",
        message: `must be ${types.join(",")}`,
        params: { type: types.join(",") },
      });
    }
  }

  if (s["enum"] !== undefined) {
    const allowed = s["enum"] as unknown[];
    if (!allowed.some((v) => deepEqual(v, data))) {
      ctx.errors.push({
        instancePath,
        schemaPath: `${schemaPath}/enum`,
        keyword: "enum",
        message: "must be equal to one of the allowed values",
        params: { allowedValues: allowed },
      });
    }
  }

  if (s["const"] !== undefined) {
    if (!deepEqual(s["const"], data)) {
      ctx.errors.push({
        instancePath,
        schemaPath: `${schemaPath}/const`,
        keyword: "const",
        message: "must be equal to constant",
        params: { allowedValue: s["const"] },
      });
    }
  }

  if (typeof data === "string") {
    validateString(s, data, instancePath, schemaPath, ctx);
  }
  if (typeof data === "number") {
    validateNumber(s, data, instancePath, schemaPath, ctx);
  }
  if (Array.isArray(data)) {
    validateArray(s, data, instancePath, schemaPath, ctx);
  }
  if (typeof data === "object" && data !== null && !Array.isArray(data)) {
    validateObject(s, data as Record<string, unknown>, instancePath, schemaPath, ctx);
  }

  // Conditionals & combinators.
  if (s["if"] !== undefined) {
    const passed = silently(ctx, () =>
      validateNode(s["if"] as Schema, data, instancePath, `${schemaPath}/if`, ctx),
    );
    const branch = passed ? "then" : "else";
    if (s[branch] !== undefined) {
      validateNode(s[branch] as Schema, data, instancePath, `${schemaPath}/${branch}`, ctx);
    }
  }
  if (Array.isArray(s["allOf"])) {
    (s["allOf"] as Schema[]).forEach((sub, i) => {
      validateNode(sub, data, instancePath, `${schemaPath}/allOf/${i}`, ctx);
    });
  }
  if (Array.isArray(s["anyOf"])) {
    const subs = s["anyOf"] as Schema[];
    const anyPassed = subs.some((sub, i) =>
      silently(ctx, () => validateNode(sub, data, instancePath, `${schemaPath}/anyOf/${i}`, ctx)),
    );
    if (!anyPassed) {
      ctx.errors.push({
        instancePath,
        schemaPath: `${schemaPath}/anyOf`,
        keyword: "anyOf",
        message: "must match a schema in anyOf",
        params: {},
      });
    }
  }
  if (Array.isArray(s["oneOf"])) {
    const subs = s["oneOf"] as Schema[];
    let passing = 0;
    subs.forEach((sub, i) => {
      if (
        silently(ctx, () => validateNode(sub, data, instancePath, `${schemaPath}/oneOf/${i}`, ctx))
      ) {
        passing++;
      }
    });
    if (passing !== 1) {
      ctx.errors.push({
        instancePath,
        schemaPath: `${schemaPath}/oneOf`,
        keyword: "oneOf",
        message: "must match exactly one schema in oneOf",
        params: { passingSchemas: passing },
      });
    }
  }
  if (s["not"] !== undefined) {
    if (
      silently(ctx, () => validateNode(s["not"] as Schema, data, instancePath, `${schemaPath}/not`, ctx))
    ) {
      ctx.errors.push({
        instancePath,
        schemaPath: `${schemaPath}/not`,
        keyword: "not",
        message: "must NOT be valid",
        params: {},
      });
    }
  }

  return ctx.errors.length === before;
}

/** Run a subschema check without leaking its errors. */
function silently(ctx: Ctx, run: () => boolean): boolean {
  const mark = ctx.errors.length;
  const ok = run();
  ctx.errors.length = mark;
  return ok;
}

function validateString(
  s: Record<string, unknown>,
  data: string,
  instancePath: string,
  schemaPath: string,
  ctx: Ctx,
): void {
  if (typeof s["minLength"] === "number" && ucLength(data) < s["minLength"]) {
    ctx.errors.push({
      instancePath,
      schemaPath: `${schemaPath}/minLength`,
      keyword: "minLength",
      message: `must NOT have fewer than ${s["minLength"]} characters`,
      params: { limit: s["minLength"] },
    });
  }
  if (typeof s["maxLength"] === "number" && ucLength(data) > s["maxLength"]) {
    ctx.errors.push({
      instancePath,
      schemaPath: `${schemaPath}/maxLength`,
      keyword: "maxLength",
      message: `must NOT have more than ${s["maxLength"]} characters`,
      params: { limit: s["maxLength"] },
    });
  }
  if (typeof s["pattern"] === "string" && !regex(ctx, s["pattern"]).test(data)) {
    ctx.errors.push({
      instancePath,
      schemaPath: `${schemaPath}/pattern`,
      keyword: "pattern",
      message: `must match pattern "${s["pattern"]}"`,
      params: { pattern: s["pattern"] },
    });
  }
}

function validateNumber(
  s: Record<string, unknown>,
  data: number,
  instancePath: string,
  schemaPath: string,
  ctx: Ctx,
): void {
  const push = (keyword: string, comparison: string, limit: number) => {
    ctx.errors.push({
      instancePath,
      schemaPath: `${schemaPath}/${keyword}`,
      keyword,
      message: `must be ${comparison} ${limit}`,
      params: { comparison, limit },
    });
  };
  if (typeof s["minimum"] === "number" && data < s["minimum"]) push("minimum", ">=", s["minimum"]);
  if (typeof s["maximum"] === "number" && data > s["maximum"]) push("maximum", "<=", s["maximum"]);
  if (typeof s["exclusiveMinimum"] === "number" && data <= s["exclusiveMinimum"]) {
    push("exclusiveMinimum", ">", s["exclusiveMinimum"]);
  }
  if (typeof s["exclusiveMaximum"] === "number" && data >= s["exclusiveMaximum"]) {
    push("exclusiveMaximum", "<", s["exclusiveMaximum"]);
  }
  if (typeof s["multipleOf"] === "number" && (data / s["multipleOf"]) % 1 !== 0) {
    ctx.errors.push({
      instancePath,
      schemaPath: `${schemaPath}/multipleOf`,
      keyword: "multipleOf",
      message: `must be multiple of ${s["multipleOf"]}`,
      params: { multipleOf: s["multipleOf"] },
    });
  }
}

function validateArray(
  s: Record<string, unknown>,
  data: unknown[],
  instancePath: string,
  schemaPath: string,
  ctx: Ctx,
): void {
  if (typeof s["minItems"] === "number" && data.length < s["minItems"]) {
    ctx.errors.push({
      instancePath,
      schemaPath: `${schemaPath}/minItems`,
      keyword: "minItems",
      message: `must NOT have fewer than ${s["minItems"]} items`,
      params: { limit: s["minItems"] },
    });
  }
  if (typeof s["maxItems"] === "number" && data.length > s["maxItems"]) {
    ctx.errors.push({
      instancePath,
      schemaPath: `${schemaPath}/maxItems`,
      keyword: "maxItems",
      message: `must NOT have more than ${s["maxItems"]} items`,
      params: { limit: s["maxItems"] },
    });
  }
  if (s["uniqueItems"] === true) {
    for (let i = 0; i < data.length; i++) {
      for (let j = i + 1; j < data.length; j++) {
        if (deepEqual(data[i], data[j])) {
          ctx.errors.push({
            instancePath,
            schemaPath: `${schemaPath}/uniqueItems`,
            keyword: "uniqueItems",
            message: `must NOT have duplicate items (items ## ${i} and ${j} are identical)`,
            params: { i, j },
          });
          i = data.length;
          break;
        }
      }
    }
  }
  const prefix = Array.isArray(s["prefixItems"]) ? (s["prefixItems"] as Schema[]) : [];
  prefix.forEach((sub, i) => {
    if (i < data.length) {
      validateNode(sub, data[i], `${instancePath}/${i}`, `${schemaPath}/prefixItems/${i}`, ctx);
    }
  });
  if (s["items"] !== undefined) {
    for (let i = prefix.length; i < data.length; i++) {
      validateNode(s["items"] as Schema, data[i], `${instancePath}/${i}`, `${schemaPath}/items`, ctx);
    }
  }
}

function validateObject(
  s: Record<string, unknown>,
  data: Record<string, unknown>,
  instancePath: string,
  schemaPath: string,
  ctx: Ctx,
): void {
  if (Array.isArray(s["required"])) {
    for (const prop of s["required"] as string[]) {
      if (!(prop in data)) {
        ctx.errors.push({
          instancePath,
          schemaPath: `${schemaPath}/required`,
          keyword: "required",
          message: `must have required property '${prop}'`,
          params: { missingProperty: prop },
        });
      }
    }
  }
  const keys = Object.keys(data);
  if (typeof s["minProperties"] === "number" && keys.length < s["minProperties"]) {
    ctx.errors.push({
      instancePath,
      schemaPath: `${schemaPath}/minProperties`,
      keyword: "minProperties",
      message: `must NOT have fewer than ${s["minProperties"]} properties`,
      params: { limit: s["minProperties"] },
    });
  }
  if (typeof s["maxProperties"] === "number" && keys.length > s["maxProperties"]) {
    ctx.errors.push({
      instancePath,
      schemaPath: `${schemaPath}/maxProperties`,
      keyword: "maxProperties",
      message: `must NOT have more than ${s["maxProperties"]} properties`,
      params: { limit: s["maxProperties"] },
    });
  }

  const props = (s["properties"] as Record<string, Schema> | undefined) ?? {};
  const patternProps = (s["patternProperties"] as Record<string, Schema> | undefined) ?? {};
  for (const [key, value] of Object.entries(data)) {
    let matched = false;
    if (key in props) {
      matched = true;
      validateNode(
        props[key]!,
        value,
        `${instancePath}/${escapePointer(key)}`,
        `${schemaPath}/properties/${escapePointer(key)}`,
        ctx,
      );
    }
    for (const [pattern, sub] of Object.entries(patternProps)) {
      if (regex(ctx, pattern).test(key)) {
        matched = true;
        validateNode(
          sub,
          value,
          `${instancePath}/${escapePointer(key)}`,
          `${schemaPath}/patternProperties/${escapePointer(pattern)}`,
          ctx,
        );
      }
    }
    if (!matched && s["additionalProperties"] !== undefined) {
      if (s["additionalProperties"] === false) {
        ctx.errors.push({
          instancePath,
          schemaPath: `${schemaPath}/additionalProperties`,
          keyword: "additionalProperties",
          message: "must NOT have additional properties",
          params: { additionalProperty: key },
        });
      } else if (s["additionalProperties"] !== true) {
        validateNode(
          s["additionalProperties"] as Schema,
          value,
          `${instancePath}/${escapePointer(key)}`,
          `${schemaPath}/additionalProperties`,
          ctx,
        );
      }
    }
    if (s["propertyNames"] !== undefined) {
      const ok = silently(ctx, () =>
        validateNode(
          s["propertyNames"] as Schema,
          key,
          instancePath,
          `${schemaPath}/propertyNames`,
          ctx,
        ),
      );
      if (!ok) {
        ctx.errors.push({
          instancePath,
          schemaPath: `${schemaPath}/propertyNames`,
          keyword: "propertyNames",
          message: `property name '${key}' is invalid`,
          params: { propertyName: key },
        });
      }
    }
  }
}
