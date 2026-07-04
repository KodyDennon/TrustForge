//! TF-YAML: the strict YAML subset TrustForge parses and emits — in-house
//! codec (see `docs/dependency-audit.md`), mirror of
//! `tools/tf-types-ts/src/core/yaml.ts`. Read that file's doc comment for
//! the full subset definition; the two implementations must stay
//! semantically identical (verified by parsing every `.yaml` in the repo
//! plus the conformance suites in both languages).
//!
//! Values parse into `serde_json::Value`: mapping keys are always
//! strings, integers restrict to the ±2^53-1 safe range (larger digit
//! runs stay strings, matching the TS/JSON number model), and the
//! non-JSON floats `.inf`/`.nan` are rejected.
//!
//! Deliberately rejected (out of subset): anchors & aliases, tags,
//! multi-document streams, complex (`? `) keys.

use serde_json::{Map, Number, Value};
use std::fmt;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct YamlError {
    message: String,
    /// 0-based raw line, when known.
    line: Option<usize>,
}

impl YamlError {
    fn new(message: impl Into<String>, line: Option<usize>) -> Self {
        Self {
            message: message.into(),
            line,
        }
    }
}

impl fmt::Display for YamlError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.line {
            Some(l) => write!(f, "line {}: {}", l + 1, self.message),
            None => write!(f, "{}", self.message),
        }
    }
}

impl std::error::Error for YamlError {}

const MAX_SAFE_INTEGER: i64 = 9_007_199_254_740_991; // 2^53 - 1

/* ------------------------------------------------------------------ */
/*  Scalar resolution (YAML 1.2 core schema)                           */
/* ------------------------------------------------------------------ */

fn resolve_scalar(text: &str) -> Result<Value, YamlError> {
    match text {
        "" | "~" | "null" | "Null" | "NULL" => return Ok(Value::Null),
        "true" | "True" | "TRUE" => return Ok(Value::Bool(true)),
        "false" | "False" | "FALSE" => return Ok(Value::Bool(false)),
        ".nan" | ".NaN" | ".NAN" => {
            return Err(YamlError::new("non-finite floats are not supported", None))
        }
        _ => {}
    }
    let bytes = text.as_bytes();
    let digits = |s: &[u8]| !s.is_empty() && s.iter().all(u8::is_ascii_digit);
    let unsigned = bytes
        .strip_prefix(b"-")
        .or_else(|| bytes.strip_prefix(b"+"));
    let body = unsigned.unwrap_or(bytes);
    if digits(body) {
        if let Ok(n) = text.parse::<i64>() {
            if n.abs() <= MAX_SAFE_INTEGER {
                return Ok(Value::Number(n.into()));
            }
        }
        return Ok(Value::String(text.to_string())); // overflow-sized digit runs
    }
    if let Some(hex) = text.strip_prefix("0x") {
        if !hex.is_empty() && hex.bytes().all(|b| b.is_ascii_hexdigit()) {
            if let Ok(n) = i64::from_str_radix(hex, 16) {
                if n <= MAX_SAFE_INTEGER {
                    return Ok(Value::Number(n.into()));
                }
            }
            return Ok(Value::String(text.to_string()));
        }
    }
    if let Some(oct) = text.strip_prefix("0o") {
        if !oct.is_empty() && oct.bytes().all(|b| (b'0'..=b'7').contains(&b)) {
            if let Ok(n) = i64::from_str_radix(oct, 8) {
                if n <= MAX_SAFE_INTEGER {
                    return Ok(Value::Number(n.into()));
                }
            }
            return Ok(Value::String(text.to_string()));
        }
    }
    if is_float_syntax(text) {
        if let Ok(f) = text.parse::<f64>() {
            if f.is_finite() {
                if let Some(n) = Number::from_f64(f) {
                    return Ok(Value::Number(n));
                }
            }
        }
    }
    if matches!(
        text,
        ".inf" | ".Inf" | ".INF" | "-.inf" | "-.Inf" | "-.INF" | "+.inf" | "+.Inf" | "+.INF"
    ) {
        return Err(YamlError::new("non-finite floats are not supported", None));
    }
    Ok(Value::String(text.to_string()))
}

/// `[-+]?(\.[0-9]+|[0-9]+(\.[0-9]*)?)([eE][-+]?[0-9]+)?`
fn is_float_syntax(text: &str) -> bool {
    let s = text
        .strip_prefix('-')
        .or_else(|| text.strip_prefix('+'))
        .unwrap_or(text);
    let (mantissa, exponent) = match s.find(['e', 'E']) {
        Some(i) => (&s[..i], Some(&s[i + 1..])),
        None => (s, None),
    };
    let mantissa_ok = if let Some(frac) = mantissa.strip_prefix('.') {
        !frac.is_empty() && frac.bytes().all(|b| b.is_ascii_digit())
    } else if let Some(dot) = mantissa.find('.') {
        let (int, frac) = (&mantissa[..dot], &mantissa[dot + 1..]);
        !int.is_empty()
            && int.bytes().all(|b| b.is_ascii_digit())
            && frac.bytes().all(|b| b.is_ascii_digit())
    } else {
        // Pure integers are handled earlier; only exponent forms remain.
        exponent.is_some() && !mantissa.is_empty() && mantissa.bytes().all(|b| b.is_ascii_digit())
    };
    if !mantissa_ok {
        return false;
    }
    match exponent {
        None => true,
        Some(e) => {
            let e = e
                .strip_prefix('-')
                .or_else(|| e.strip_prefix('+'))
                .unwrap_or(e);
            !e.is_empty() && e.bytes().all(|b| b.is_ascii_digit())
        }
    }
}

/* ------------------------------------------------------------------ */
/*  Parser                                                             */
/* ------------------------------------------------------------------ */

#[derive(Clone)]
struct Line {
    indent: usize,
    content: String,
    raw: usize,
}

struct Parser {
    lines: Vec<String>,
    items: Vec<Line>,
    pos: usize,
}

impl Parser {
    fn new(input: &str) -> Result<Self, YamlError> {
        let lines: Vec<String> = input
            .split('\n')
            .map(|l| l.trim_end_matches('\r').to_string())
            .collect();
        let mut items = Vec::new();
        for (i, raw) in lines.iter().enumerate() {
            let trimmed = raw.trim_end();
            let indent = count_indent(trimmed);
            if raw[..indent.min(raw.len())].contains('\t')
                || raw.trim_start_matches(' ').starts_with('\t') && raw.trim().is_empty()
            {
                return Err(YamlError::new(
                    "tabs are not allowed in indentation",
                    Some(i),
                ));
            }
            let content = &trimmed[indent..];
            if content.is_empty() || content.starts_with('#') {
                continue;
            }
            if content == "---" {
                if items.is_empty() {
                    continue; // leading document marker
                }
                return Err(YamlError::new(
                    "multi-document streams are not supported",
                    Some(i),
                ));
            }
            if content == "..." {
                continue;
            }
            items.push(Line {
                indent,
                content: content.to_string(),
                raw: i,
            });
        }
        Ok(Self {
            lines,
            items,
            pos: 0,
        })
    }

    fn parse(mut self) -> Result<Value, YamlError> {
        if self.items.is_empty() {
            return Ok(Value::Null);
        }
        let value = self.parse_node(0)?;
        if self.pos < self.items.len() {
            return Err(YamlError::new(
                "unexpected content",
                Some(self.items[self.pos].raw),
            ));
        }
        Ok(value)
    }

    fn peek(&self) -> Option<&Line> {
        self.items.get(self.pos)
    }

    fn parse_node(&mut self, min_indent: usize) -> Result<Value, YamlError> {
        let Some(line) = self.peek() else {
            return Ok(Value::Null);
        };
        if line.indent < min_indent {
            return Ok(Value::Null);
        }
        if line.content == "-" || line.content.starts_with("- ") {
            let indent = line.indent;
            return self.parse_sequence(indent);
        }
        if find_key(&line.content).is_some() {
            let indent = line.indent;
            return self.parse_mapping(indent);
        }
        self.parse_scalar_lines()
    }

    fn parse_sequence(&mut self, indent: usize) -> Result<Value, YamlError> {
        let mut out = Vec::new();
        while let Some(line) = self.peek() {
            if line.indent != indent {
                break;
            }
            if line.content == "-" {
                self.pos += 1;
                let deeper = self.peek().map(|n| n.indent > indent).unwrap_or(false);
                out.push(if deeper {
                    self.parse_node(indent + 1)?
                } else {
                    Value::Null
                });
                continue;
            }
            if !line.content.starts_with("- ") {
                break;
            }
            // Rewrite `- rest` in place as deeper-indented content so
            // nested structures parse naturally with true columns.
            let rest = line.content[2..].to_string();
            let raw = line.raw;
            let extra = count_indent(&rest);
            self.items[self.pos] = Line {
                indent: indent + 2 + extra,
                content: rest[extra..].to_string(),
                raw,
            };
            out.push(self.parse_node(indent + 1)?);
        }
        Ok(Value::Array(out))
    }

    fn parse_mapping(&mut self, indent: usize) -> Result<Value, YamlError> {
        let mut out = Map::new();
        while let Some(line) = self.peek() {
            if line.indent != indent {
                break;
            }
            if line.content == "-" || line.content.starts_with("- ") {
                break;
            }
            let Some((key, rest)) = find_key(&line.content) else {
                break;
            };
            let raw = line.raw;
            self.pos += 1;
            let value = if rest.is_empty() {
                let deeper = self.peek().map(|n| n.indent > indent).unwrap_or(false);
                if deeper {
                    self.parse_node(indent + 1)?
                } else {
                    Value::Null
                }
            } else if rest.starts_with('|') || rest.starts_with('>') {
                Value::String(self.parse_block_scalar(&rest, indent, raw)?)
            } else {
                self.parse_inline_value(&rest, indent, raw)?
            };
            if out.contains_key(&key) {
                return Err(YamlError::new(
                    format!("duplicate mapping key {key:?}"),
                    Some(raw),
                ));
            }
            out.insert(key, value);
        }
        Ok(Value::Object(out))
    }

    fn parse_inline_value(
        &mut self,
        rest: &str,
        indent: usize,
        raw_line: usize,
    ) -> Result<Value, YamlError> {
        if rest.starts_with('[') || rest.starts_with('{') {
            let text = self.collect_flow(rest, raw_line)?;
            let mut flow = FlowParser {
                s: text.as_bytes(),
                text: &text,
                i: 0,
                raw_line,
            };
            let value = flow.parse_value()?;
            flow.expect_end()?;
            return Ok(value);
        }
        if rest.starts_with('"') || rest.starts_with('\'') {
            let (value, end) = parse_quoted(rest)
                .ok_or_else(|| YamlError::new("unterminated quoted scalar", Some(raw_line)))?;
            let after = strip_comment(rest[end..].trim());
            if !after.is_empty() {
                return Err(YamlError::new(
                    "unexpected content after quoted scalar",
                    Some(raw_line),
                ));
            }
            return Ok(Value::String(value));
        }
        if rest.starts_with('&') || rest.starts_with('*') {
            return Err(YamlError::new(
                "anchors and aliases are not supported (TF-YAML subset)",
                Some(raw_line),
            ));
        }
        if rest.starts_with('!') {
            return Err(YamlError::new(
                "tags are not supported (TF-YAML subset)",
                Some(raw_line),
            ));
        }
        // Plain scalar with folded continuation lines.
        let mut text = strip_comment(rest).to_string();
        while let Some(next) = self.peek() {
            if next.indent <= indent {
                break;
            }
            if next.content == "-" || next.content.starts_with("- ") {
                break;
            }
            if find_key(&next.content).is_some() {
                break;
            }
            text.push(' ');
            text.push_str(strip_comment(&next.content));
            self.pos += 1;
        }
        resolve_scalar(text.trim()).map_err(|e| YamlError::new(e.message, Some(raw_line)))
    }

    fn parse_scalar_lines(&mut self) -> Result<Value, YamlError> {
        let first = self.peek().expect("caller checked").clone();
        self.pos += 1;
        self.parse_inline_value(&first.content, first.indent.saturating_sub(1), first.raw)
    }

    fn collect_flow(&mut self, first: &str, raw_line: usize) -> Result<String, YamlError> {
        let mut text = strip_comment(first.trim()).to_string();
        loop {
            if flow_balanced(&text) {
                return Ok(text);
            }
            let Some(next) = self.peek() else {
                return Err(YamlError::new(
                    "unterminated flow collection",
                    Some(raw_line),
                ));
            };
            let chunk = strip_comment(next.content.trim()).to_string();
            self.pos += 1;
            text.push(' ');
            text.push_str(&chunk);
        }
    }

    fn parse_block_scalar(
        &mut self,
        header: &str,
        key_indent: usize,
        raw_line: usize,
    ) -> Result<String, YamlError> {
        let folded = header.starts_with('>');
        #[derive(PartialEq)]
        enum Chomp {
            Clip,
            Strip,
            Keep,
        }
        let mut chomp = Chomp::Clip;
        let mut explicit_indent = None;
        for c in strip_comment(header[1..].trim()).chars() {
            match c {
                '-' => chomp = Chomp::Strip,
                '+' => chomp = Chomp::Keep,
                '1'..='9' => explicit_indent = Some(key_indent + c.to_digit(10).unwrap() as usize),
                _ => {
                    return Err(YamlError::new(
                        format!("bad block scalar header {header:?}"),
                        Some(raw_line),
                    ))
                }
            }
        }

        let start_raw = raw_line + 1;
        let mut end_raw = start_raw;
        for i in start_raw..self.lines.len() {
            let l = &self.lines[i];
            if l.trim().is_empty() {
                continue;
            }
            if count_indent(l) <= key_indent {
                break;
            }
            end_raw = i + 1;
        }
        let raw: Vec<&str> = (start_raw..end_raw)
            .map(|i| self.lines[i].as_str())
            .collect();
        while self.pos < self.items.len() && self.items[self.pos].raw < end_raw {
            self.pos += 1;
        }

        let mut block_indent = explicit_indent;
        if block_indent.is_none() {
            for l in &raw {
                if !l.trim().is_empty() {
                    block_indent = Some(count_indent(l));
                    break;
                }
            }
        }
        let block_indent = block_indent.unwrap_or(key_indent + 1);
        if block_indent <= key_indent {
            return Err(YamlError::new(
                "block scalar body must be indented past its key",
                Some(raw_line),
            ));
        }

        let body: Vec<String> = raw
            .iter()
            .map(|l| {
                if l.trim().is_empty() {
                    String::new()
                } else {
                    l[block_indent.min(count_indent(l))..].to_string()
                }
            })
            .collect();
        let mut end = body.len();
        while end > 0 && body[end - 1].is_empty() {
            end -= 1;
        }
        let kept = &body[..end];
        let trailing_blank = body.len() - end;

        let text = if !folded {
            kept.join("\n")
        } else {
            let mut text = String::new();
            let mut prev_was_text = false;
            let mut prev_was_literal = false;
            for l in kept {
                let literal = !l.is_empty() && (l.starts_with(' ') || l.starts_with('\t'));
                if l.is_empty() {
                    text.push('\n');
                    prev_was_text = false;
                    prev_was_literal = false;
                    continue;
                }
                if prev_was_text && !literal && !prev_was_literal {
                    text.push(' ');
                } else if prev_was_literal || (prev_was_text && literal) {
                    text.push('\n');
                }
                text.push_str(l);
                prev_was_text = true;
                prev_was_literal = literal;
            }
            text
        };
        Ok(match chomp {
            Chomp::Strip => text.trim_end_matches('\n').to_string(),
            Chomp::Keep => {
                if kept.is_empty() && trailing_blank == 0 {
                    text
                } else {
                    text + &"\n".repeat(trailing_blank + 1)
                }
            }
            Chomp::Clip => {
                if text.is_empty() && trailing_blank == 0 {
                    text
                } else {
                    text + "\n"
                }
            }
        })
    }
}

fn count_indent(s: &str) -> usize {
    s.bytes().take_while(|&b| b == b' ').count()
}

/// Split a mapping line into key and remainder (comment-stripped).
fn find_key(content: &str) -> Option<(String, String)> {
    if content.starts_with('"') || content.starts_with('\'') {
        let (key, end) = parse_quoted(content)?;
        let after = content[end..].trim_start();
        let rest = after.strip_prefix(':')?;
        if !rest.is_empty() && !rest.starts_with(' ') {
            return None;
        }
        return Some((key, strip_comment(rest.trim()).to_string()));
    }
    let bytes = content.as_bytes();
    let mut depth = 0i32;
    for i in 0..bytes.len() {
        match bytes[i] {
            b'[' | b'{' => depth += 1,
            b']' | b'}' => depth -= 1,
            b':' if depth == 0 && (i + 1 == bytes.len() || bytes[i + 1] == b' ') => {
                let key = content[..i].trim();
                if key.is_empty() || key.starts_with('#') {
                    return None;
                }
                return Some((
                    key.to_string(),
                    strip_comment(content[i + 1..].trim()).to_string(),
                ));
            }
            b'#' if i > 0 && bytes[i - 1] == b' ' => return None,
            _ => {}
        }
    }
    None
}

/// Strip a ` #comment` suffix outside quotes.
fn strip_comment(s: &str) -> &str {
    if s.starts_with('#') {
        return "";
    }
    let bytes = s.as_bytes();
    let mut in_single = false;
    let mut in_double = false;
    let mut i = 0;
    while i < bytes.len() {
        match bytes[i] {
            b'\'' if !in_double => in_single = !in_single,
            b'"' if !in_single && (i == 0 || bytes[i - 1] != b'\\') => in_double = !in_double,
            b'#' if !in_single
                && !in_double
                && i > 0
                && (bytes[i - 1] == b' ' || bytes[i - 1] == b'\t') =>
            {
                return s[..i].trim_end();
            }
            _ => {}
        }
        i += 1;
    }
    s
}

fn flow_balanced(s: &str) -> bool {
    let bytes = s.as_bytes();
    let mut depth = 0i32;
    let mut in_single = false;
    let mut in_double = false;
    let mut i = 0;
    while i < bytes.len() {
        let b = bytes[i];
        if in_single {
            if b == b'\'' {
                in_single = false;
            }
        } else if in_double {
            if b == b'\\' {
                i += 1;
            } else if b == b'"' {
                in_double = false;
            }
        } else {
            match b {
                b'\'' => in_single = true,
                b'"' => in_double = true,
                b'[' | b'{' => depth += 1,
                b']' | b'}' => depth -= 1,
                _ => {}
            }
        }
        i += 1;
    }
    depth <= 0 && !in_single && !in_double
}

/// Parse a quoted scalar at the start of `s`; returns (value, end byte offset).
fn parse_quoted(s: &str) -> Option<(String, usize)> {
    let mut chars = s.char_indices();
    let (_, quote) = chars.next()?;
    if quote == '\'' {
        let mut out = String::new();
        let mut iter = chars.peekable();
        while let Some((i, c)) = iter.next() {
            if c == '\'' {
                if matches!(iter.peek(), Some((_, '\''))) {
                    out.push('\'');
                    iter.next();
                } else {
                    return Some((out, i + 1));
                }
            } else {
                out.push(c);
            }
        }
        return None;
    }
    if quote == '"' {
        let bytes = s.as_bytes();
        let mut out = String::new();
        let mut i = 1;
        while i < s.len() {
            let c = s[i..].chars().next()?;
            if c == '"' {
                return Some((out, i + 1));
            }
            if c == '\\' {
                let esc = s[i + 1..].chars().next()?;
                i += 1 + esc.len_utf8();
                match esc {
                    'n' => out.push('\n'),
                    't' => out.push('\t'),
                    'r' => out.push('\r'),
                    '0' => out.push('\0'),
                    'a' => out.push('\x07'),
                    'b' => out.push('\x08'),
                    'f' => out.push('\x0c'),
                    'v' => out.push('\x0b'),
                    'e' => out.push('\x1b'),
                    '"' | '\\' | '/' => out.push(esc),
                    'x' => {
                        let h = s.get(i..i + 2)?;
                        out.push(char::from_u32(u32::from_str_radix(h, 16).ok()?)?);
                        i += 2;
                    }
                    'u' => {
                        let h = s.get(i..i + 4)?;
                        let cp = u32::from_str_radix(h, 16).ok()?;
                        // Surrogates in \u escapes: TS uses UTF-16 code
                        // units; TF-YAML content never uses them, so
                        // reject rather than mis-handle.
                        out.push(char::from_u32(cp)?);
                        i += 4;
                    }
                    'U' => {
                        let h = s.get(i..i + 8)?;
                        out.push(char::from_u32(u32::from_str_radix(h, 16).ok()?)?);
                        i += 8;
                    }
                    _ => return None,
                }
                let _ = bytes;
                continue;
            }
            out.push(c);
            i += c.len_utf8();
        }
        return None;
    }
    None
}

/* ------------------------------------------------------------------ */
/*  Flow-collection parser                                             */
/* ------------------------------------------------------------------ */

struct FlowParser<'a> {
    s: &'a [u8],
    text: &'a str,
    i: usize,
    raw_line: usize,
}

impl<'a> FlowParser<'a> {
    fn ws(&mut self) {
        while self.i < self.s.len() && (self.s[self.i] == b' ' || self.s[self.i] == b'\t') {
            self.i += 1;
        }
    }

    fn fail(&self, msg: &str) -> YamlError {
        YamlError::new(format!("{msg} in flow collection"), Some(self.raw_line))
    }

    fn parse_value(&mut self) -> Result<Value, YamlError> {
        self.ws();
        let Some(&c) = self.s.get(self.i) else {
            return Err(self.fail("unexpected end"));
        };
        match c {
            b'[' => self.parse_array(),
            b'{' => self.parse_map(),
            b'"' | b'\'' => {
                let (value, end) = parse_quoted(&self.text[self.i..])
                    .ok_or_else(|| self.fail("unterminated quoted scalar"))?;
                self.i += end;
                Ok(Value::String(value))
            }
            b'&' | b'*' => Err(self.fail("anchors/aliases are not supported")),
            b'!' => Err(self.fail("tags are not supported")),
            _ => {
                let start = self.i;
                while self.i < self.s.len() {
                    let ch = self.s[self.i];
                    if ch == b',' || ch == b']' || ch == b'}' {
                        break;
                    }
                    if ch == b':' && (self.i + 1 == self.s.len() || self.s[self.i + 1] == b' ') {
                        break;
                    }
                    self.i += 1;
                }
                resolve_scalar(self.text[start..self.i].trim())
                    .map_err(|e| YamlError::new(e.message, Some(self.raw_line)))
            }
        }
    }

    fn parse_array(&mut self) -> Result<Value, YamlError> {
        self.i += 1;
        let mut out = Vec::new();
        self.ws();
        if self.s.get(self.i) == Some(&b']') {
            self.i += 1;
            return Ok(Value::Array(out));
        }
        loop {
            out.push(self.parse_value()?);
            self.ws();
            match self.s.get(self.i) {
                Some(b',') => {
                    self.i += 1;
                    self.ws();
                    if self.s.get(self.i) == Some(&b']') {
                        self.i += 1;
                        return Ok(Value::Array(out));
                    }
                }
                Some(b']') => {
                    self.i += 1;
                    return Ok(Value::Array(out));
                }
                _ => return Err(self.fail("expected , or ]")),
            }
        }
    }

    fn parse_map(&mut self) -> Result<Value, YamlError> {
        self.i += 1;
        let mut out = Map::new();
        self.ws();
        if self.s.get(self.i) == Some(&b'}') {
            self.i += 1;
            return Ok(Value::Object(out));
        }
        loop {
            self.ws();
            let key = match self.s.get(self.i) {
                Some(b'"') | Some(b'\'') => {
                    let (k, end) = parse_quoted(&self.text[self.i..])
                        .ok_or_else(|| self.fail("unterminated quoted key"))?;
                    self.i += end;
                    k
                }
                _ => {
                    let start = self.i;
                    while self.i < self.s.len()
                        && self.s[self.i] != b':'
                        && self.s[self.i] != b','
                        && self.s[self.i] != b'}'
                    {
                        self.i += 1;
                    }
                    self.text[start..self.i].trim().to_string()
                }
            };
            self.ws();
            let mut value = Value::Null;
            if self.s.get(self.i) == Some(&b':') {
                self.i += 1;
                value = self.parse_value()?;
            }
            if out.contains_key(&key) {
                return Err(self.fail(&format!("duplicate key {key:?}")));
            }
            out.insert(key, value);
            self.ws();
            match self.s.get(self.i) {
                Some(b',') => {
                    self.i += 1;
                    self.ws();
                    if self.s.get(self.i) == Some(&b'}') {
                        self.i += 1;
                        return Ok(Value::Object(out));
                    }
                }
                Some(b'}') => {
                    self.i += 1;
                    return Ok(Value::Object(out));
                }
                _ => return Err(self.fail("expected , or }")),
            }
        }
    }

    fn expect_end(&mut self) -> Result<(), YamlError> {
        self.ws();
        if self.i < self.s.len() {
            return Err(self.fail("trailing content"));
        }
        Ok(())
    }
}

/* ------------------------------------------------------------------ */
/*  Public API                                                         */
/* ------------------------------------------------------------------ */

/// Parse TF-YAML into a JSON value tree.
pub fn parse(input: &str) -> Result<Value, YamlError> {
    Parser::new(input)?.parse()
}

/// Parse TF-YAML directly into a typed struct.
pub fn from_str<T: serde::de::DeserializeOwned>(input: &str) -> Result<T, YamlError> {
    let value = parse(input)?;
    serde_json::from_value(value).map_err(|e| YamlError::new(e.to_string(), None))
}

/// Serialize a value as block-style TF-YAML.
pub fn to_string<T: serde::Serialize>(value: &T) -> Result<String, YamlError> {
    let json = serde_json::to_value(value).map_err(|e| YamlError::new(e.to_string(), None))?;
    Ok(emit(&json))
}

/* ------------------------------------------------------------------ */
/*  Emitter                                                            */
/* ------------------------------------------------------------------ */

fn plain_safe(s: &str) -> bool {
    let mut chars = s.chars();
    match chars.next() {
        Some(c) if c.is_ascii_alphanumeric() || c == '_' => {}
        _ => return false,
    }
    s.chars()
        .all(|c| c.is_ascii_alphanumeric() || matches!(c, '_' | '-' | '.' | '/' | '@' | ' '))
}

fn needs_quoting(s: &str) -> bool {
    if s.is_empty() || !plain_safe(s) || s != s.trim() {
        return true;
    }
    match resolve_scalar(s) {
        Ok(Value::String(_)) => {}
        _ => return true,
    }
    // Syntactically number-like strings must be quoted regardless of our
    // own resolution — see the TS mirror.
    let body = s
        .strip_prefix('-')
        .or_else(|| s.strip_prefix('+'))
        .unwrap_or(s);
    if !body.is_empty()
        && body.bytes().all(|b| b.is_ascii_digit() || b == b'_')
        && body.bytes().next().unwrap().is_ascii_digit()
    {
        return true;
    }
    if is_float_syntax(s) {
        return true;
    }
    false
}

fn quote(s: &str) -> String {
    serde_json::to_string(s).expect("string serializes")
}

fn format_scalar(v: &Value) -> String {
    match v {
        Value::Null => "null".to_string(),
        Value::Bool(true) => "true".to_string(),
        Value::Bool(false) => "false".to_string(),
        Value::Number(n) => n.to_string(),
        Value::String(s) => {
            if needs_quoting(s) {
                quote(s)
            } else {
                s.clone()
            }
        }
        _ => unreachable!("caller checked scalar"),
    }
}

fn is_scalar(v: &Value) -> bool {
    !matches!(v, Value::Array(_) | Value::Object(_))
}

fn format_key(k: &str) -> String {
    if needs_quoting(k) || k.contains(':') || k.contains('#') {
        quote(k)
    } else {
        k.to_string()
    }
}

/// Multi-line strings become literal block scalars when safe.
fn format_multiline(v: &Value, indent: usize) -> String {
    if let Value::String(s) = v {
        let ok = s.contains('\n')
            && !s.starts_with(char::is_whitespace)
            && !s.ends_with(char::is_whitespace)
            && !s.contains("\n\n\n");
        if ok {
            let pad = "  ".repeat(indent);
            let body: Vec<String> = s
                .split('\n')
                .map(|l| {
                    if l.is_empty() {
                        String::new()
                    } else {
                        format!("{pad}{l}")
                    }
                })
                .collect();
            return format!("|-\n{}", body.join("\n"));
        }
    }
    format_scalar(v)
}

fn emit_entry(prefix: &str, key: &str, val: &Value, child_indent: usize, out: &mut Vec<String>) {
    if is_scalar(val) {
        out.push(format!(
            "{prefix}{}: {}",
            format_key(key),
            format_multiline(val, child_indent)
        ));
    } else {
        out.push(format!("{prefix}{}:", format_key(key)));
        emit_node(val, child_indent, out);
    }
}

fn emit_node(v: &Value, indent: usize, out: &mut Vec<String>) {
    let pad = "  ".repeat(indent);
    match v {
        Value::Array(items) => {
            if items.is_empty() {
                let last = out.last_mut().expect("array attaches to a line");
                last.push_str(" []");
                return;
            }
            for item in items {
                if is_scalar(item) {
                    out.push(format!("{pad}- {}", format_scalar(item)));
                } else if let Value::Array(_) = item {
                    out.push(format!("{pad}-"));
                    emit_node(item, indent + 1, out);
                } else if let Value::Object(map) = item {
                    if map.is_empty() {
                        out.push(format!("{pad}- {{}}"));
                        continue;
                    }
                    let mut first = true;
                    for (k, val) in map {
                        let prefix = if first {
                            format!("{pad}- ")
                        } else {
                            format!("{pad}  ")
                        };
                        first = false;
                        emit_entry(&prefix, k, val, indent + 2, out);
                    }
                }
            }
        }
        Value::Object(map) => {
            if map.is_empty() {
                let last = out.last_mut().expect("map attaches to a line");
                last.push_str(" {}");
                return;
            }
            for (k, val) in map {
                emit_entry(&pad, k, val, indent + 1, out);
            }
        }
        _ => unreachable!("caller checked collection"),
    }
}

fn emit(v: &Value) -> String {
    if is_scalar(v) {
        return format!("{}\n", format_scalar(v));
    }
    // Top-level empty collections have no key line to attach to.
    match v {
        Value::Array(items) if items.is_empty() => return "[]\n".to_string(),
        Value::Object(map) if map.is_empty() => return "{}\n".to_string(),
        _ => {}
    }
    let mut out = Vec::new();
    emit_node(v, 0, &mut out);
    format!("{}\n", out.join("\n"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn scalars_resolve_like_yaml12_core() {
        assert_eq!(parse("x: null").unwrap(), json!({"x": null}));
        assert_eq!(parse("x: ~").unwrap(), json!({"x": null}));
        assert_eq!(parse("x:").unwrap(), json!({"x": null}));
        assert_eq!(parse("x: true").unwrap(), json!({"x": true}));
        assert_eq!(parse("x: False").unwrap(), json!({"x": false}));
        assert_eq!(parse("x: 42").unwrap(), json!({"x": 42}));
        assert_eq!(parse("x: -7").unwrap(), json!({"x": -7}));
        assert_eq!(parse("x: 0x1f").unwrap(), json!({"x": 31}));
        assert_eq!(parse("x: 3.5").unwrap(), json!({"x": 3.5}));
        assert_eq!(parse("x: 1e3").unwrap(), json!({"x": 1000.0}));
        assert_eq!(parse("x: yes").unwrap(), json!({"x": "yes"})); // 1.2, not 1.1
        assert_eq!(parse("x: on").unwrap(), json!({"x": "on"}));
        // Overflow-sized digit runs stay strings (JS parity).
        assert_eq!(
            parse("x: 070000004041424344454647").unwrap(),
            json!({"x": "070000004041424344454647"})
        );
    }

    #[test]
    fn block_structures() {
        let doc = "top:\n  list:\n    - a\n    - name: n1\n      value: 1\n    - - nested\n  map:\n    k: v\n";
        assert_eq!(
            parse(doc).unwrap(),
            json!({"top": {"list": ["a", {"name": "n1", "value": 1}, ["nested"]], "map": {"k": "v"}}})
        );
    }

    #[test]
    fn flow_structures() {
        assert_eq!(
            parse("x: [1, two, {k: v}, [3]]").unwrap(),
            json!({"x": [1, "two", {"k": "v"}, [3]]})
        );
        assert_eq!(
            parse("x: {a: 1, b: [2]}").unwrap(),
            json!({"x": {"a": 1, "b": [2]}})
        );
        // Multi-line flow.
        assert_eq!(
            parse("x: [1,\n   2,\n   3]").unwrap(),
            json!({"x": [1, 2, 3]})
        );
    }

    #[test]
    fn quoted_scalars() {
        assert_eq!(parse("x: 'it''s'").unwrap(), json!({"x": "it's"}));
        assert_eq!(parse("x: \"a\\nb\"").unwrap(), json!({"x": "a\nb"}));
        assert_eq!(parse("x: \"42\"").unwrap(), json!({"x": "42"}));
        assert_eq!(parse("\"a: b\": 1").unwrap(), json!({"a: b": 1}));
    }

    #[test]
    fn block_scalars() {
        assert_eq!(
            parse("x: |\n  line1\n  line2\ny: 1").unwrap(),
            json!({"x": "line1\nline2\n", "y": 1})
        );
        assert_eq!(
            parse("x: |-\n  line1\n  line2").unwrap(),
            json!({"x": "line1\nline2"})
        );
        assert_eq!(
            parse("x: >-\n  fold\n  ed\n\n  para").unwrap(),
            json!({"x": "fold ed\npara"})
        );
        // Body lines that look like structure stay text.
        assert_eq!(
            parse("x: |\n  key: value\n  - item\ny: 2").unwrap(),
            json!({"x": "key: value\n- item\n", "y": 2})
        );
    }

    #[test]
    fn comments_and_blanks() {
        let doc = "# header\nx: 1 # trailing\n\ny: \"# not a comment\"\nz: a#b\n";
        assert_eq!(
            parse(doc).unwrap(),
            json!({"x": 1, "y": "# not a comment", "z": "a#b"})
        );
    }

    #[test]
    fn subset_violations_rejected() {
        assert!(parse("x: &a 1").is_err());
        assert!(parse("x: *a").is_err());
        assert!(parse("x: !!str 1").is_err());
        assert!(parse("a: 1\n---\nb: 2").is_err());
        assert!(parse("x: 1\nx: 2").is_err());
    }

    #[test]
    fn emitter_round_trips() {
        let doc = json!({
            "name": "test",
            "count": 42,
            "pi": 3.5,
            "flag": true,
            "nothing": null,
            "digits": "0123456789012345678",
            "multiline": "first\nsecond",
            "list": [1, "two", {"k": "v", "nested": {"deep": [1, 2]}}],
            "looks_like_bool": "true",
            "empty_list": [],
            "empty_map": {},
            "weird key: yes": "value",
        });
        let text = to_string(&doc).unwrap();
        assert_eq!(parse(&text).unwrap(), doc, "emitted:\n{text}");
    }

    #[test]
    fn typed_from_str() {
        #[derive(serde::Deserialize, PartialEq, Debug)]
        struct T {
            name: String,
            values: Vec<i64>,
        }
        let t: T = from_str("name: x\nvalues: [1, 2]\n").unwrap();
        assert_eq!(
            t,
            T {
                name: "x".into(),
                values: vec![1, 2]
            }
        );
    }
}
