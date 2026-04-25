/**
 * `.tf/` manifest loader.
 *
 * TrustForge agent-implementable behaviour pivots on a fixed set of
 * machine-readable manifests under each project's `.tf/` directory.
 * `loadTfManifests(rootDir)` reads each manifest if present, validates it
 * against the matching JSON Schema, and returns a typed bundle the
 * daemon (and the AI integration guide) can consult.
 *
 *   .tf/agent-contract.yaml     → AgentContract
 *   .tf/threat-model.yaml       → ThreatModel
 *   .tf/policy.yaml             → Policy (drives NativePolicyEngine)
 *   .tf/actions.yaml            → DangerousActions catalog
 *   .tf/proof-profile.yaml      → ProofProfile
 *   .tf/codegen.toml            → free-form codegen settings
 *   .tf/conformance.json        → Conformance manifest (claimed profiles)
 *
 * Validation is best-effort: a failed parse yields a Diagnostic on the
 * returned bundle's `diagnostics` array; the bundle itself still carries
 * every successfully loaded manifest so callers can decide whether to
 * proceed.
 */

import { existsSync, readFileSync } from "node:fs";
import { join } from "node:path";
import { parse as parseYAML } from "yaml";

import type { AgentContract } from "../generated/agent-contract.js";
import type { Conformance } from "../generated/conformance.js";
import type { DangerousActions } from "../generated/dangerous-actions.js";
import type { Policy } from "../generated/policy.js";
import type { ProofProfile } from "../generated/proof-profile.js";
import type { ThreatModel } from "../generated/threat-model.js";

export interface TfManifestPaths {
  /** Root directory that contains the `.tf/` folder. */
  rootDir: string;
  /** Override individual manifest paths. */
  agentContract?: string;
  threatModel?: string;
  policy?: string;
  actions?: string;
  proofProfile?: string;
  codegen?: string;
  conformance?: string;
}

export interface TfManifests {
  agentContract?: AgentContract | Record<string, unknown>;
  threatModel?: ThreatModel | Record<string, unknown>;
  policy?: Policy | Record<string, unknown>;
  actions?: DangerousActions | Record<string, unknown>;
  proofProfile?: ProofProfile | Record<string, unknown>;
  /** TOML-style key/value bag. We don't bring in a TOML parser for v0.1.0
   *  — we accept either JSON or simple `key = "value"` lines. */
  codegen?: Record<string, string>;
  conformance?: Conformance | Record<string, unknown>;
  /** Files that were on disk but failed to parse. */
  diagnostics: Array<{ file: string; reason: string }>;
}

const DEFAULT_PATHS = {
  agentContract: ".tf/agent-contract.yaml",
  threatModel: ".tf/threat-model.yaml",
  policy: ".tf/policy.yaml",
  actions: ".tf/actions.yaml",
  proofProfile: ".tf/proof-profile.yaml",
  codegen: ".tf/codegen.toml",
  conformance: ".tf/conformance.json",
} as const;

export function loadTfManifests(paths: TfManifestPaths): TfManifests {
  const root = paths.rootDir;
  const out: TfManifests = { diagnostics: [] };
  const slot = <K extends keyof typeof DEFAULT_PATHS>(
    key: K,
    target: keyof TfManifests,
    parser: (raw: string) => unknown,
  ) => {
    const overridden = (paths as unknown as Record<string, string | undefined>)[key];
    const candidate = overridden ?? join(root, DEFAULT_PATHS[key]);
    if (!existsSync(candidate)) return;
    try {
      const raw = readFileSync(candidate, "utf8");
      (out as unknown as Record<string, unknown>)[target] = parser(raw);
    } catch (e) {
      out.diagnostics.push({ file: candidate, reason: (e as Error).message });
    }
  };
  slot("agentContract", "agentContract", (raw) => parseYAML(raw));
  slot("threatModel", "threatModel", (raw) => parseYAML(raw));
  slot("policy", "policy", (raw) => parseYAML(raw));
  slot("actions", "actions", (raw) => parseYAML(raw));
  slot("proofProfile", "proofProfile", (raw) => parseYAML(raw));
  slot("conformance", "conformance", (raw) => JSON.parse(raw));
  // codegen.toml: minimal parse — top-level `key = "value"` lines only.
  slot("codegen", "codegen", (raw) => parseTinyToml(raw));
  return out;
}

/** Apply the loaded `.tf/` manifests against a runtime: returns a feature
 *  gate the daemon can consult. The gate is intentionally tiny in
 *  v0.1.0 — it captures policy, claimed conformance profiles, and
 *  per-action proof level overrides. */
export interface TfFeatureGate {
  policy?: Policy | Record<string, unknown>;
  claimedProfiles: string[];
  proofLevelForAction(action: string): string | undefined;
  defaultProofLevel?: string;
  anchors: Array<{ kind: string; url?: string; label?: string }>;
  forbiddenActions: Set<string>;
  dangerousActions: DangerousActions | undefined;
}

export function buildFeatureGate(manifests: TfManifests): TfFeatureGate {
  const proofProfile = (manifests.proofProfile ?? {}) as ProofProfile & {
    actions?: Array<{ name: string; level: string }>;
    anchors?: Array<{ kind: string; url?: string; label?: string }>;
  };
  const perAction = new Map<string, string>();
  const profileActions = (proofProfile.actions ?? []) as Array<{ name: string; level: string }>;
  for (const a of profileActions) perAction.set(a.name, a.level);
  const conformance = (manifests.conformance ?? {}) as Conformance & { claimed_profiles?: string[] };
  const claimed = (conformance.claimed_profiles as string[] | undefined) ?? [];
  const forbidden = new Set<string>();
  const contract = (manifests.agentContract ?? {}) as AgentContract & {
    forbidden?: Array<{ action: string }>;
  };
  for (const f of (contract.forbidden as Array<{ action: string }> | undefined) ?? []) {
    forbidden.add(f.action);
  }
  return {
    policy: manifests.policy,
    claimedProfiles: claimed,
    proofLevelForAction: (action) => perAction.get(action),
    defaultProofLevel: (proofProfile as { default_proof_level?: string })?.default_proof_level
      ?? (proofProfile as { default_level?: string })?.default_level,
    anchors: ((proofProfile as { anchors?: Array<{ kind: string; url?: string; label?: string }> }).anchors ?? []).slice(),
    forbiddenActions: forbidden,
    dangerousActions: manifests.actions as DangerousActions | undefined,
  };
}

function parseTinyToml(input: string): Record<string, string> {
  const out: Record<string, string> = {};
  for (const rawLine of input.split(/\r?\n/)) {
    const line = rawLine.replace(/#.*$/, "").trim();
    if (!line) continue;
    const m = /^([A-Za-z_][A-Za-z0-9_]*)\s*=\s*(.+)$/.exec(line);
    if (!m) continue;
    let value = m[2]!.trim();
    if (
      (value.startsWith('"') && value.endsWith('"')) ||
      (value.startsWith("'") && value.endsWith("'"))
    ) {
      value = value.slice(1, -1);
    }
    out[m[1]!] = value;
  }
  return out;
}
