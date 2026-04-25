/**
 * BridgesRegistry — the runtime form of `.tf/bridges.yaml` (TF-0001 +
 * docs/bridges/). The daemon loads this file once at startup, uses
 * `resolveByIssuer` to map an incoming credential's `iss` / SPIFFE
 * trust-domain / Clerk publishable-key prefix to a `BridgeEntry`, and
 * falls back to the built-in defaults baked into the credential-resolver
 * (B2) when no entry matches.
 *
 * The schema is normative — `schemas/bridges-registry.schema.json` is
 * the source of truth. Any bridge_kind added here must also be added to
 * the schema enum AND to the Rust mirror in
 * `crates/tf-types/src/bridges_registry.rs`.
 */
import { readFileSync } from "node:fs";
import { parse as parseYAML } from "yaml";

export type BridgesRegistryKind =
  | "oauth"
  | "clerk"
  | "next-auth"
  | "better-auth"
  | "webauthn"
  | "tls"
  | "spiffe"
  | "did"
  | "gnap"
  | "mcp"
  | "matrix"
  | "webhook"
  | "grpc"
  | "service-mesh"
  | "a2a"
  | "session-cookie";

const VALID_KINDS = new Set<BridgesRegistryKind>([
  "oauth",
  "clerk",
  "next-auth",
  "better-auth",
  "webauthn",
  "tls",
  "spiffe",
  "did",
  "gnap",
  "mcp",
  "matrix",
  "webhook",
  "grpc",
  "service-mesh",
  "a2a",
  "session-cookie",
]);

const TRUST_LEVEL_PATTERN = /^T[0-7]$/;
const PROFILE_PATTERN = /^tf-[a-z][a-z0-9-]*-compatible$/;
const ACTION_NAME_PATTERN = /^[a-z][a-z0-9_]*(\.[a-z][a-z0-9_]*)+$/;

export interface BridgeEntry {
  kind: BridgesRegistryKind;
  issuer_match?: string;
  iss_pattern?: string;
  trust_domain?: string;
  trust_level?: `T${0 | 1 | 2 | 3 | 4 | 5 | 6 | 7}`;
  capability_map?: Record<string, string>;
  profile?: string;
}

export interface BridgesRegistryDocument {
  registry_version: "1";
  default_profile?: string;
  bridges: BridgeEntry[];
}

export class BridgesRegistryError extends Error {}

/** Validate a parsed YAML/JSON document against the bridges-registry
 *  schema rules. Throws BridgesRegistryError on the first violation —
 *  the caller can map this to a daemon-startup failure. */
export function validateBridgesRegistry(raw: unknown): BridgesRegistryDocument {
  if (!raw || typeof raw !== "object" || Array.isArray(raw)) {
    throw new BridgesRegistryError("registry root must be an object");
  }
  const r = raw as Record<string, unknown>;
  if (r.registry_version !== "1") {
    throw new BridgesRegistryError(`registry_version must be "1", got ${JSON.stringify(r.registry_version)}`);
  }
  if (!Array.isArray(r.bridges)) {
    throw new BridgesRegistryError("bridges must be an array");
  }
  if ("default_profile" in r && r.default_profile !== undefined) {
    if (typeof r.default_profile !== "string" || !PROFILE_PATTERN.test(r.default_profile)) {
      throw new BridgesRegistryError(`default_profile must match ${PROFILE_PATTERN.source}`);
    }
  }
  const allowed = new Set([
    "registry_version",
    "default_profile",
    "bridges",
  ]);
  for (const k of Object.keys(r)) {
    if (!allowed.has(k)) {
      throw new BridgesRegistryError(`unknown registry key: ${k}`);
    }
  }
  const bridges: BridgeEntry[] = [];
  for (let i = 0; i < r.bridges.length; i++) {
    const entry = r.bridges[i];
    bridges.push(validateEntry(entry, i));
  }
  const out: BridgesRegistryDocument = {
    registry_version: "1",
    bridges,
  };
  if (typeof r.default_profile === "string") out.default_profile = r.default_profile;
  return out;
}

function validateEntry(raw: unknown, index: number): BridgeEntry {
  if (!raw || typeof raw !== "object" || Array.isArray(raw)) {
    throw new BridgesRegistryError(`bridges[${index}] must be an object`);
  }
  const e = raw as Record<string, unknown>;
  const allowed = new Set([
    "kind",
    "issuer_match",
    "iss_pattern",
    "trust_domain",
    "trust_level",
    "capability_map",
    "profile",
  ]);
  for (const k of Object.keys(e)) {
    if (!allowed.has(k)) {
      throw new BridgesRegistryError(`bridges[${index}]: unknown key ${k}`);
    }
  }
  if (typeof e.kind !== "string" || !VALID_KINDS.has(e.kind as BridgesRegistryKind)) {
    throw new BridgesRegistryError(`bridges[${index}].kind invalid: ${JSON.stringify(e.kind)}`);
  }
  const out: BridgeEntry = { kind: e.kind as BridgesRegistryKind };
  if ("issuer_match" in e && e.issuer_match !== undefined) {
    if (typeof e.issuer_match !== "string" || e.issuer_match.length === 0) {
      throw new BridgesRegistryError(`bridges[${index}].issuer_match must be a non-empty string`);
    }
    out.issuer_match = e.issuer_match;
  }
  if ("iss_pattern" in e && e.iss_pattern !== undefined) {
    if (typeof e.iss_pattern !== "string" || e.iss_pattern.length === 0) {
      throw new BridgesRegistryError(`bridges[${index}].iss_pattern must be a non-empty string`);
    }
    out.iss_pattern = e.iss_pattern;
  }
  if ("trust_domain" in e && e.trust_domain !== undefined) {
    if (typeof e.trust_domain !== "string") {
      throw new BridgesRegistryError(`bridges[${index}].trust_domain must be a string`);
    }
    out.trust_domain = e.trust_domain;
  }
  if ("trust_level" in e && e.trust_level !== undefined) {
    if (typeof e.trust_level !== "string" || !TRUST_LEVEL_PATTERN.test(e.trust_level)) {
      throw new BridgesRegistryError(`bridges[${index}].trust_level must match T0..T7`);
    }
    out.trust_level = e.trust_level as BridgeEntry["trust_level"];
  }
  if ("capability_map" in e && e.capability_map !== undefined) {
    if (!e.capability_map || typeof e.capability_map !== "object" || Array.isArray(e.capability_map)) {
      throw new BridgesRegistryError(`bridges[${index}].capability_map must be an object`);
    }
    const map: Record<string, string> = {};
    for (const [k, v] of Object.entries(e.capability_map)) {
      if (typeof v !== "string" || !ACTION_NAME_PATTERN.test(v)) {
        throw new BridgesRegistryError(
          `bridges[${index}].capability_map[${k}] must be a dotted action name (got ${JSON.stringify(v)})`,
        );
      }
      map[k] = v;
    }
    out.capability_map = map;
  }
  if ("profile" in e && e.profile !== undefined) {
    if (typeof e.profile !== "string" || !PROFILE_PATTERN.test(e.profile)) {
      throw new BridgesRegistryError(`bridges[${index}].profile must match ${PROFILE_PATTERN.source}`);
    }
    out.profile = e.profile;
  }
  return out;
}

/** Loaded `.tf/bridges.yaml` registry. Cheap to keep in memory; the
 *  daemon constructs one at boot and queries it per-decide. */
export class BridgesRegistry {
  readonly registry_version: "1";
  readonly default_profile?: string;
  readonly bridges: ReadonlyArray<BridgeEntry>;

  constructor(doc: BridgesRegistryDocument) {
    this.registry_version = doc.registry_version;
    this.default_profile = doc.default_profile;
    this.bridges = doc.bridges.slice();
  }

  /** Load a `.tf/bridges.yaml` from disk. Returns an empty registry when
   *  the file is missing — the credential-resolver's built-in defaults
   *  cover that case. */
  static load(yamlPath: string): BridgesRegistry {
    let text: string;
    try {
      text = readFileSync(yamlPath, "utf8");
    } catch (err) {
      const code = (err as NodeJS.ErrnoException).code;
      if (code === "ENOENT") {
        return new BridgesRegistry({ registry_version: "1", bridges: [] });
      }
      throw err;
    }
    return BridgesRegistry.fromString(text);
  }

  /** Parse + validate a YAML/JSON registry from a string. */
  static fromString(text: string): BridgesRegistry {
    const raw = parseYAML(text);
    return new BridgesRegistry(validateBridgesRegistry(raw));
  }

  /** Resolve an incoming credential's issuer to a bridge entry. Returns
   *  `null` when no entry matches; the caller falls back to the
   *  resolver's built-in defaults. Match precedence:
   *    1. exact `issuer_match` (full string equality, NFC-normalized).
   *    2. `iss_pattern` substring match.
   *  First match wins. */
  resolveByIssuer(iss: string): BridgeEntry | null {
    if (typeof iss !== "string" || iss.length === 0) return null;
    const needle = iss.normalize("NFC");
    for (const entry of this.bridges) {
      if (entry.issuer_match !== undefined && entry.issuer_match.normalize("NFC") === needle) {
        return entry;
      }
    }
    for (const entry of this.bridges) {
      if (entry.iss_pattern !== undefined && needle.includes(entry.iss_pattern.normalize("NFC"))) {
        return entry;
      }
    }
    return null;
  }

  /** Resolve by bridge kind only — returns the first matching entry. */
  resolveByKind(kind: BridgesRegistryKind): BridgeEntry | null {
    for (const entry of this.bridges) {
      if (entry.kind === kind) return entry;
    }
    return null;
  }
}
