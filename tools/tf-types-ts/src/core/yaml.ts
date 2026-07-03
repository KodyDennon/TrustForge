/**
 * TF-YAML: the strict YAML subset TrustForge parses and emits — in-house
 * codec (see `docs/dependency-audit.md`), mirror of
 * `crates/tf-types/src/yaml.rs`.
 *
 * Supported (everything TrustForge manifests, conformance vectors, and
 * schema fixtures use):
 *   - block mappings and sequences (indentation-structured)
 *   - flow collections `[a, b]` / `{k: v}`, including multi-line flow
 *   - plain, single-quoted, and double-quoted scalars
 *   - multi-line plain scalars (folded per YAML rules)
 *   - block scalars: literal `|` and folded `>`, with `-` / `+` chomping
 *     and explicit indentation indicators
 *   - comments, blank lines, a leading `---` document marker
 *   - YAML 1.2 core-schema scalar resolution (null / bool / int incl.
 *     0x/0o / float incl. .inf/.nan — everything else is a string)
 *
 * Deliberately rejected (out of subset):
 *   - anchors & aliases (`&a` / `*a`) — immune to billion-laughs by
 *     construction; deduplicate fixtures by expansion instead
 *   - tags (`!!type`, `!custom`)
 *   - multi-document streams (`---` separating two documents)
 *   - complex mapping keys (`? key`)
 *
 * The emitter (`stringify`) produces plain block-style YAML (2-space
 * indent) that this parser and any YAML 1.2 parser read back to the
 * same tree. It is not intended to reproduce any other library's exact
 * output.
 */

export class YamlError extends Error {
  constructor(message: string, line?: number) {
    super(line === undefined ? message : `line ${line + 1}: ${message}`);
  }
}

/* ------------------------------------------------------------------ */
/*  Scalar resolution (YAML 1.2 core schema)                           */
/* ------------------------------------------------------------------ */

function resolveScalar(text: string): unknown {
  if (
    text === "" ||
    text === "~" ||
    text === "null" ||
    text === "Null" ||
    text === "NULL"
  ) {
    return null;
  }
  if (text === "true" || text === "True" || text === "TRUE") return true;
  if (text === "false" || text === "False" || text === "FALSE") return false;
  if (/^[-+]?[0-9]+$/.test(text)) {
    const n = Number(text);
    if (Number.isSafeInteger(n)) return n;
    return text; // overflow-sized digit strings stay strings
  }
  if (/^0x[0-9a-fA-F]+$/.test(text)) return parseInt(text.slice(2), 16);
  if (/^0o[0-7]+$/.test(text)) return parseInt(text.slice(2), 8);
  if (/^[-+]?(\.[0-9]+|[0-9]+(\.[0-9]*)?)([eE][-+]?[0-9]+)?$/.test(text)) {
    const n = Number(text);
    if (Number.isFinite(n)) return n;
  }
  if (/^[-+]?(\.inf|\.Inf|\.INF)$/.test(text)) {
    return text.startsWith("-") ? -Infinity : Infinity;
  }
  if (text === ".nan" || text === ".NaN" || text === ".NAN") return NaN;
  return text;
}

/* ------------------------------------------------------------------ */
/*  Parser                                                             */
/* ------------------------------------------------------------------ */

interface Line {
  indent: number;
  /** Content with indentation stripped; never empty (blank lines are skipped). */
  content: string;
  /** Index into the raw line array (for error messages / block scalars). */
  raw: number;
}

class Parser {
  private lines: string[];
  /** Content lines only (blank / comment-only lines removed). */
  private items: Line[] = [];
  private pos = 0;

  constructor(input: string) {
    this.lines = input.split(/\r?\n/);
    for (let i = 0; i < this.lines.length; i++) {
      const raw = this.lines[i]!;
      const trimmed = raw.trimEnd();
      const indent = countIndent(trimmed);
      if (raw.includes("\t") && /^\s*\t/.test(raw)) {
        throw new YamlError("tabs are not allowed in indentation", i);
      }
      const content = trimmed.slice(indent);
      if (content === "" || content.startsWith("#")) continue;
      if (content === "---" && this.items.length === 0) continue; // leading doc marker
      if (content === "---") {
        throw new YamlError("multi-document streams are not supported", i);
      }
      if (content === "...") continue; // document end marker
      this.items.push({ indent, content, raw: i });
    }
  }

  parse(): unknown {
    if (this.items.length === 0) return null;
    const value = this.parseNode(0);
    if (this.pos < this.items.length) {
      throw new YamlError("unexpected content", this.items[this.pos]!.raw);
    }
    return value;
  }

  private peek(): Line | undefined {
    return this.items[this.pos];
  }

  private parseNode(minIndent: number): unknown {
    const line = this.peek();
    if (!line || line.indent < minIndent) return null;
    if (line.content === "-" || line.content.startsWith("- ")) {
      return this.parseSequence(line.indent);
    }
    if (this.findKey(line.content)) {
      return this.parseMapping(line.indent);
    }
    return this.parseScalarLines(line.indent);
  }

  private parseSequence(indent: number): unknown[] {
    const out: unknown[] = [];
    for (;;) {
      const line = this.peek();
      if (!line || line.indent !== indent) break;
      if (line.content !== "-" && !line.content.startsWith("- ")) break;
      if (line.content === "-") {
        this.pos++;
        const next = this.peek();
        out.push(next && next.indent > indent ? this.parseNode(indent + 1) : null);
        continue;
      }
      // Rewrite `- rest` in place as deeper-indented content so nested
      // structures (`- - x`, `- k: v` compact maps) parse naturally with
      // their true columns preserved.
      const rest = line.content.slice(2);
      const restIndent = indent + 2 + countIndent(rest);
      this.items[this.pos] = {
        indent: restIndent,
        content: rest.slice(countIndent(rest)),
        raw: line.raw,
      };
      out.push(this.parseNode(indent + 1));
    }
    return out;
  }

  private parseMapping(indent: number): Record<string, unknown> {
    const out: Record<string, unknown> = {};
    for (;;) {
      const line = this.peek();
      if (!line || line.indent !== indent) break;
      if (line.content === "-" || line.content.startsWith("- ")) break;
      const found = this.findKey(line.content);
      if (!found) break;
      const { key, rest } = found;
      this.pos++;
      let value: unknown;
      if (rest === "") {
        const next = this.peek();
        value = next && next.indent > indent ? this.parseNode(indent + 1) : null;
      } else if (rest.startsWith("|") || rest.startsWith(">")) {
        value = this.parseBlockScalar(rest, indent, line.raw);
      } else {
        value = this.parseInlineValue(rest, indent, line.raw);
      }
      if (Object.prototype.hasOwnProperty.call(out, key)) {
        throw new YamlError(`duplicate mapping key ${JSON.stringify(key)}`, line.raw);
      }
      out[key] = value;
    }
    return out;
  }

  /**
   * Split a mapping line into key and remainder, or return undefined if
   * the line is not a mapping entry. Handles quoted keys and refuses
   * `:` inside flow/quoted contexts.
   */
  private findKey(content: string): { key: string; rest: string } | undefined {
    let keyEnd: number;
    let keyText: string;
    if (content.startsWith('"') || content.startsWith("'")) {
      const q = parseQuoted(content, 0);
      if (!q) return undefined;
      keyText = q.value;
      keyEnd = q.end;
      const after = content.slice(keyEnd).trimStart();
      if (!after.startsWith(":")) return undefined;
      const rest = after.slice(1);
      if (rest !== "" && !rest.startsWith(" ")) return undefined;
      return { key: keyText, rest: stripComment(rest.trim()) };
    }
    // Plain key: find `: ` or `:` at end-of-line, outside brackets.
    let depth = 0;
    for (let i = 0; i < content.length; i++) {
      const c = content[i]!;
      if (c === "[" || c === "{") depth++;
      else if (c === "]" || c === "}") depth--;
      else if (c === ":" && depth === 0) {
        if (i + 1 === content.length || content[i + 1] === " ") {
          const key = content.slice(0, i).trim();
          if (key === "" || key.startsWith("#")) return undefined;
          return { key, rest: stripComment(content.slice(i + 1).trim()) };
        }
      } else if (c === "#" && i > 0 && content[i - 1] === " ") {
        return undefined; // comment before any key separator
      }
    }
    return undefined;
  }

  /**
   * A value that starts on the same line as its key (or seq dash):
   * flow collection (possibly spanning lines), quoted scalar, or plain
   * scalar (possibly continuing on following more-indented lines).
   */
  private parseInlineValue(rest: string, indent: number, rawLine: number): unknown {
    if (rest.startsWith("[") || rest.startsWith("{")) {
      const text = this.collectFlow(rest, rawLine);
      const flow = new FlowParser(text, rawLine);
      const value = flow.parseValue();
      flow.expectEnd();
      return value;
    }
    if (rest.startsWith('"') || rest.startsWith("'")) {
      const q = parseQuoted(rest, 0);
      if (!q) throw new YamlError("unterminated quoted scalar", rawLine);
      const after = stripComment(rest.slice(q.end).trim());
      if (after !== "") {
        throw new YamlError("unexpected content after quoted scalar", rawLine);
      }
      return q.value;
    }
    if (rest.startsWith("&") || rest.startsWith("*")) {
      throw new YamlError("anchors and aliases are not supported (TF-YAML subset)", rawLine);
    }
    if (rest.startsWith("!")) {
      throw new YamlError("tags are not supported (TF-YAML subset)", rawLine);
    }
    // Plain scalar; fold continuation lines that are more indented and
    // not themselves structure.
    let text = stripComment(rest);
    for (;;) {
      const next = this.peek();
      if (!next || next.indent <= indent) break;
      if (next.content.startsWith("- ") || next.content === "-") break;
      if (this.findKey(next.content)) break;
      text += ` ${stripComment(next.content)}`;
      this.pos++;
    }
    return resolveScalar(text.trim());
  }

  /** A scalar occupying whole lines (document is just a scalar). */
  private parseScalarLines(indent: number): unknown {
    const first = this.peek()!;
    this.pos++;
    return this.parseInlineValue(first.content, indent - 1, first.raw);
  }

  /** Collect a flow collection that may span multiple physical lines. */
  private collectFlow(first: string, rawLine: number): string {
    let text = stripFlowComment(first);
    for (;;) {
      if (flowBalanced(text)) return text;
      const next = this.peek();
      if (!next) throw new YamlError("unterminated flow collection", rawLine);
      this.pos++;
      text += ` ${stripFlowComment(next.content)}`;
    }
  }

  private parseBlockScalar(header: string, keyIndent: number, rawLine: number): string {
    const folded = header[0] === ">";
    let chomp: "clip" | "strip" | "keep" = "clip";
    let explicitIndent: number | undefined;
    for (const c of stripComment(header.slice(1).trim())) {
      if (c === "-") chomp = "strip";
      else if (c === "+") chomp = "keep";
      else if (c >= "1" && c <= "9") explicitIndent = keyIndent + Number(c);
      else throw new YamlError(`bad block scalar header ${JSON.stringify(header)}`, rawLine);
    }

    // Collect raw physical lines (blank lines matter here) that belong
    // to the block: everything more indented than the key, up to the
    // first non-empty line at or below the key's indent.
    const startRaw = rawLine + 1;
    let endRaw = startRaw;
    for (let i = startRaw; i < this.lines.length; i++) {
      const l = this.lines[i]!;
      if (l.trim() === "") {
        continue; // blank lines belong tentatively; trimmed later
      }
      if (countIndent(l) <= keyIndent) break;
      endRaw = i + 1;
    }
    const raw: string[] = [];
    for (let i = startRaw; i < endRaw; i++) {
      raw.push(this.lines[i] ?? "");
    }
    // The body lines were captured into the content-item list during
    // preprocessing; skip past them.
    while (this.pos < this.items.length && this.items[this.pos]!.raw < endRaw) {
      this.pos++;
    }
    // Determine block indentation from the first non-empty line.
    let blockIndent = explicitIndent;
    if (blockIndent === undefined) {
      for (const l of raw) {
        if (l.trim() !== "") {
          blockIndent = countIndent(l);
          break;
        }
      }
    }
    if (blockIndent === undefined) blockIndent = keyIndent + 1;
    if (blockIndent <= keyIndent) {
      throw new YamlError("block scalar body must be indented past its key", rawLine);
    }

    const body: string[] = raw.map((l) =>
      l.trim() === "" ? "" : l.slice(Math.min(blockIndent!, countIndent(l))),
    );
    // Trim trailing blank lines out of the body (they belong to chomping).
    let end = body.length;
    while (end > 0 && body[end - 1] === "") end--;
    const kept = body.slice(0, end);
    const trailingBlank = body.length - end;

    let text: string;
    if (!folded) {
      text = kept.join("\n");
    } else {
      // Folded: single newline between non-empty lines becomes a space;
      // blank lines become newlines; more-indented lines stay literal.
      text = "";
      let prevWasText = false;
      let prevWasLiteral = false;
      for (const l of kept) {
        const literal = l !== "" && (l.startsWith(" ") || l.startsWith("\t"));
        if (l === "") {
          text += "\n";
          prevWasText = false;
          prevWasLiteral = false;
          continue;
        }
        if (prevWasText && !literal && !prevWasLiteral) text += " ";
        else if (prevWasLiteral || (prevWasText && literal)) text += "\n";
        text += l;
        prevWasText = true;
        prevWasLiteral = literal;
      }
    }
    switch (chomp) {
      case "strip":
        return text.replace(/\n+$/, "");
      case "keep":
        return kept.length === 0 && trailingBlank === 0
          ? text
          : text + "\n".repeat(trailingBlank + 1);
      default:
        return text === "" && trailingBlank === 0 ? "" : `${text}\n`;
    }
  }
}

function countIndent(s: string): number {
  let i = 0;
  while (i < s.length && s[i] === " ") i++;
  return i;
}

/** Strip a ` #comment` suffix from a plain-scalar remainder. */
function stripComment(s: string): string {
  // A '#' only starts a comment when preceded by whitespace (or at the
  // very start) and outside quotes.
  if (s.startsWith("#")) return "";
  let inSingle = false;
  let inDouble = false;
  for (let i = 0; i < s.length; i++) {
    const c = s[i]!;
    if (c === "'" && !inDouble) inSingle = !inSingle;
    else if (c === '"' && !inSingle && (i === 0 || s[i - 1] !== "\\")) inDouble = !inDouble;
    else if (c === "#" && !inSingle && !inDouble && i > 0 && (s[i - 1] === " " || s[i - 1] === "\t")) {
      return s.slice(0, i).trimEnd();
    }
  }
  return s;
}

/** Strip comments from a flow-collection physical line. */
function stripFlowComment(s: string): string {
  return stripComment(s.trim());
}

/** Are all brackets balanced outside quotes? */
function flowBalanced(s: string): boolean {
  let depth = 0;
  let inSingle = false;
  let inDouble = false;
  for (let i = 0; i < s.length; i++) {
    const c = s[i]!;
    if (inSingle) {
      if (c === "'") inSingle = false;
      continue;
    }
    if (inDouble) {
      if (c === "\\") i++;
      else if (c === '"') inDouble = false;
      continue;
    }
    if (c === "'") inSingle = true;
    else if (c === '"') inDouble = true;
    else if (c === "[" || c === "{") depth++;
    else if (c === "]" || c === "}") depth--;
  }
  return depth <= 0 && !inSingle && !inDouble;
}

/** Parse a quoted scalar starting at `start`; returns value and end offset. */
function parseQuoted(s: string, start: number): { value: string; end: number } | undefined {
  const quote = s[start];
  if (quote === "'") {
    let out = "";
    let i = start + 1;
    while (i < s.length) {
      if (s[i] === "'") {
        if (s[i + 1] === "'") {
          out += "'";
          i += 2;
        } else {
          return { value: out, end: i + 1 };
        }
      } else {
        out += s[i];
        i++;
      }
    }
    return undefined;
  }
  if (quote === '"') {
    let out = "";
    let i = start + 1;
    while (i < s.length) {
      const c = s[i]!;
      if (c === '"') return { value: out, end: i + 1 };
      if (c === "\\") {
        const esc = s[i + 1];
        i += 2;
        switch (esc) {
          case "n":
            out += "\n";
            break;
          case "t":
            out += "\t";
            break;
          case "r":
            out += "\r";
            break;
          case "0":
            out += "\0";
            break;
          case "a":
            out += "\x07";
            break;
          case "b":
            out += "\b";
            break;
          case "f":
            out += "\f";
            break;
          case "v":
            out += "\v";
            break;
          case "e":
            out += "\x1b";
            break;
          case '"':
          case "\\":
          case "/":
            out += esc;
            break;
          case "x":
            out += String.fromCharCode(parseInt(s.slice(i, i + 2), 16));
            i += 2;
            break;
          case "u":
            out += String.fromCharCode(parseInt(s.slice(i, i + 4), 16));
            i += 4;
            break;
          case "U":
            out += String.fromCodePoint(parseInt(s.slice(i, i + 8), 16));
            i += 8;
            break;
          default:
            return undefined;
        }
      } else {
        out += c;
        i++;
      }
    }
    return undefined;
  }
  return undefined;
}

/* ------------------------------------------------------------------ */
/*  Flow-collection parser                                             */
/* ------------------------------------------------------------------ */

class FlowParser {
  private i = 0;
  constructor(
    private s: string,
    private rawLine: number,
  ) {}

  private ws(): void {
    while (this.i < this.s.length && (this.s[this.i] === " " || this.s[this.i] === "\t")) this.i++;
  }

  private fail(msg: string): never {
    throw new YamlError(`${msg} in flow collection`, this.rawLine);
  }

  parseValue(): unknown {
    this.ws();
    const c = this.s[this.i];
    if (c === undefined) this.fail("unexpected end");
    if (c === "[") return this.parseArray();
    if (c === "{") return this.parseMap();
    if (c === '"' || c === "'") {
      const q = parseQuoted(this.s, this.i);
      if (!q) this.fail("unterminated quoted scalar");
      this.i = q.end;
      return q.value;
    }
    if (c === "&" || c === "*") this.fail("anchors/aliases are not supported");
    if (c === "!") this.fail("tags are not supported");
    // Plain scalar: up to , ] } or : (when followed by space/end).
    const start = this.i;
    while (this.i < this.s.length) {
      const ch = this.s[this.i]!;
      if (ch === "," || ch === "]" || ch === "}") break;
      if (ch === ":" && (this.s[this.i + 1] === " " || this.i + 1 === this.s.length)) break;
      this.i++;
    }
    return resolveScalar(this.s.slice(start, this.i).trim());
  }

  private parseArray(): unknown[] {
    this.i++; // consume [
    const out: unknown[] = [];
    this.ws();
    if (this.s[this.i] === "]") {
      this.i++;
      return out;
    }
    for (;;) {
      out.push(this.parseValue());
      this.ws();
      const c = this.s[this.i];
      if (c === ",") {
        this.i++;
        this.ws();
        if (this.s[this.i] === "]") {
          this.i++;
          return out;
        }
        continue;
      }
      if (c === "]") {
        this.i++;
        return out;
      }
      this.fail("expected , or ]");
    }
  }

  private parseMap(): Record<string, unknown> {
    this.i++; // consume {
    const out: Record<string, unknown> = {};
    this.ws();
    if (this.s[this.i] === "}") {
      this.i++;
      return out;
    }
    for (;;) {
      this.ws();
      let key: string;
      const c = this.s[this.i];
      if (c === '"' || c === "'") {
        const q = parseQuoted(this.s, this.i);
        if (!q) this.fail("unterminated quoted key");
        key = q.value;
        this.i = q.end;
      } else {
        const start = this.i;
        while (
          this.i < this.s.length &&
          this.s[this.i] !== ":" &&
          this.s[this.i] !== "," &&
          this.s[this.i] !== "}"
        ) {
          this.i++;
        }
        key = this.s.slice(start, this.i).trim();
      }
      this.ws();
      let value: unknown = null;
      if (this.s[this.i] === ":") {
        this.i++;
        value = this.parseValue();
      }
      if (Object.prototype.hasOwnProperty.call(out, key)) {
        this.fail(`duplicate key ${JSON.stringify(key)}`);
      }
      out[key] = value;
      this.ws();
      const d = this.s[this.i];
      if (d === ",") {
        this.i++;
        this.ws();
        if (this.s[this.i] === "}") {
          this.i++;
          return out;
        }
        continue;
      }
      if (d === "}") {
        this.i++;
        return out;
      }
      this.fail("expected , or }");
    }
  }

  expectEnd(): void {
    this.ws();
    if (this.i < this.s.length) this.fail("trailing content");
  }
}

/* ------------------------------------------------------------------ */
/*  Public API                                                         */
/* ------------------------------------------------------------------ */

export function parse(input: string): unknown {
  return new Parser(input).parse();
}

/* ------------------------------------------------------------------ */
/*  Emitter                                                            */
/* ------------------------------------------------------------------ */

const PLAIN_SAFE = /^[A-Za-z0-9_][A-Za-z0-9_\-./@ ]*$/;

function needsQuoting(s: string): boolean {
  if (s === "") return true;
  if (!PLAIN_SAFE.test(s)) return true;
  if (s !== s.trim()) return true;
  // Anything the parser would resolve to a non-string must be quoted.
  if (typeof resolveScalar(s) !== "string") return true;
  // Anything *syntactically* number-like must be quoted even when our
  // resolver keeps it a string (e.g. digit runs beyond the safe-integer
  // range) — other YAML parsers would read it as a lossy number.
  if (/^[-+]?[0-9][0-9_]*$/.test(s)) return true;
  if (/^[-+]?(\.[0-9]+|[0-9][0-9_]*(\.[0-9]*)?)([eE][-+]?[0-9]+)?$/.test(s)) return true;
  return false;
}

function quote(s: string): string {
  return JSON.stringify(s);
}

function formatScalar(v: unknown): string {
  if (v === null || v === undefined) return "null";
  if (typeof v === "boolean") return v ? "true" : "false";
  if (typeof v === "number") {
    if (Number.isNaN(v)) return ".nan";
    if (v === Infinity) return ".inf";
    if (v === -Infinity) return "-.inf";
    return String(v);
  }
  if (typeof v === "string") return needsQuoting(v) ? quote(v) : v;
  throw new YamlError(`cannot stringify ${typeof v}`);
}

function isScalar(v: unknown): boolean {
  return v === null || v === undefined || typeof v !== "object";
}

function formatKey(k: string): string {
  return needsQuoting(k) || k.includes(":") || k.includes("#") ? quote(k) : k;
}

function stringifyNode(v: unknown, indent: number, out: string[]): void {
  const pad = "  ".repeat(indent);
  if (Array.isArray(v)) {
    if (v.length === 0) {
      out[out.length - 1] += " []";
      return;
    }
    for (const item of v) {
      if (isScalar(item)) {
        // Always single-line here: the parser's sequence path takes no
        // block-scalar headers, so multiline strings are JSON-quoted.
        out.push(`${pad}- ${formatScalar(item)}`);
      } else if (Array.isArray(item)) {
        out.push(`${pad}-`);
        stringifyNode(item, indent + 1, out);
      } else {
        // Compact map-in-seq: first key on the dash line.
        const entries = Object.entries(item as Record<string, unknown>).filter(
          ([, val]) => val !== undefined,
        );
        if (entries.length === 0) {
          out.push(`${pad}- {}`);
          continue;
        }
        let first = true;
        for (const [k, val] of entries) {
          const prefix = first ? `${pad}- ` : `${pad}  `;
          first = false;
          // Keys sit one level deeper than the dash, so their children
          // are two levels below `indent`.
          emitEntry(prefix, k, val, indent + 2, out);
        }
      }
    }
    return;
  }
  // Mapping
  const entries = Object.entries(v as Record<string, unknown>).filter(
    ([, val]) => val !== undefined,
  );
  if (entries.length === 0) {
    out[out.length - 1] += " {}";
    return;
  }
  for (const [k, val] of entries) {
    emitEntry(pad, k, val, indent + 1, out);
  }
}

function emitEntry(
  prefix: string,
  key: string,
  val: unknown,
  childIndent: number,
  out: string[],
): void {
  if (isScalar(val)) {
    out.push(`${prefix}${formatKey(key)}: ${formatMultiline(val, childIndent)}`);
  } else {
    out.push(`${prefix}${formatKey(key)}:`);
    stringifyNode(val, childIndent, out);
  }
}

/** Multi-line strings become literal block scalars. */
function formatMultiline(v: unknown, indent: number): string {
  if (typeof v === "string" && v.includes("\n") && !/^\s|\s$/.test(v) && !v.includes("\n\n\n")) {
    const pad = "  ".repeat(indent);
    const body = v.split("\n").map((l) => (l === "" ? "" : pad + l));
    const chomp = v.endsWith("\n") ? "" : "-";
    // Trailing newline inside the value is represented by clip chomping.
    const lines = v.endsWith("\n") ? body.slice(0, -1) : body;
    return `|${chomp}\n${lines.join("\n")}`;
  }
  return formatScalar(v);
}

export function stringify(value: unknown): string {
  if (isScalar(value)) return `${formatScalar(value)}\n`;
  const out: string[] = [];
  stringifyNode(value, 0, out);
  return `${out.join("\n")}\n`;
}
