import { readFileSync, existsSync } from "node:fs";
import { parse as parseYAML } from "yaml";
import { buildAjv, getValidator } from "./loader";

export type Severity = "error" | "warning" | "info";

export interface Finding {
  severity: Severity;
  code: string;
  message: string;
  pointer: string;
}

export interface AgentContractReport {
  ok: boolean;
  contract_path: string;
  findings: Finding[];
}

export interface CheckOptions {
  libraryPath?: string;
  catalogPath?: string;
}

export async function checkAgentContract(
  contractPath: string,
  opts: CheckOptions = {},
): Promise<AgentContractReport> {
  const findings: Finding[] = [];
  if (!existsSync(contractPath)) {
    return {
      ok: false,
      contract_path: contractPath,
      findings: [
        {
          severity: "error",
          code: "contract-missing",
          message: `agent-contract file not found: ${contractPath}`,
          pointer: "",
        },
      ],
    };
  }

  const raw = readFileSync(contractPath, "utf8");
  const contract = parseYAML(raw) as Record<string, unknown>;

  // 1. JSON-Schema validation.
  const ajv = buildAjv();
  const validator = getValidator(ajv, "agent-contract");
  if (!validator(contract)) {
    for (const err of validator.errors ?? []) {
      findings.push({
        severity: "error",
        code: `schema/${err.keyword}`,
        message: err.message ?? "(no message)",
        pointer: err.instancePath || "/",
      });
    }
  }

  // Early-exit if the document didn't parse into our expected shape.
  const actions = (contract.actions as Record<string, unknown>[] | undefined) ?? [];
  const forbidden = (contract.forbidden as Record<string, unknown>[] | undefined) ?? [];
  const targetSets = (contract.target_sets as Record<string, unknown> | undefined) ?? {};

  // 2. Conflict check.
  const forbiddenNames = new Set(forbidden.map((f) => String(f.action)));
  for (const action of actions) {
    const name = String(action.name);
    if (forbiddenNames.has(name)) {
      findings.push({
        severity: "error",
        code: "conflict/forbidden-and-allowed",
        message: `action "${name}" appears in both actions[] and forbidden[]`,
        pointer: `/actions/${actions.indexOf(action)}/name`,
      });
    }
  }

  // 3. Target-set references.
  const declaredSets = new Set(Object.keys(targetSets));
  for (const [i, action] of actions.entries()) {
    for (const key of ["allow_targets", "deny_targets"] as const) {
      const list = (action[key] as string[] | undefined) ?? [];
      for (const [j, target] of list.entries()) {
        if (target.startsWith("@")) {
          const setName = target.slice(1);
          if (!declaredSets.has(setName)) {
            findings.push({
              severity: "error",
              code: "target-set/missing",
              message: `action "${String(action.name)}" references target set @${setName} which is not declared`,
              pointer: `/actions/${i}/${key}/${j}`,
            });
          }
        }
      }
    }
  }

  // 4. Action-library resolution (optional).
  if (opts.libraryPath && existsSync(opts.libraryPath)) {
    const libRaw = readFileSync(opts.libraryPath, "utf8");
    const lib = parseYAML(libRaw) as Record<string, unknown>;
    const libActions = (lib.actions as Record<string, unknown>[] | undefined) ?? [];
    const libNames = new Set(libActions.map((a) => String(a.name)));
    for (const [i, action] of actions.entries()) {
      const name = String(action.name);
      if (!libNames.has(name)) {
        findings.push({
          severity: "warning",
          code: "library/unknown-action",
          message: `action "${name}" is not declared in library ${opts.libraryPath}`,
          pointer: `/actions/${i}/name`,
        });
      }
    }
  }

  // 5. Danger-tag / reversibility rules.
  type CatalogEntry = {
    name: string;
    danger_tags?: string[];
    mandatory_tags?: string[];
  };
  let catalogEntries: CatalogEntry[] | undefined;
  if (opts.catalogPath && existsSync(opts.catalogPath)) {
    const catRaw = readFileSync(opts.catalogPath, "utf8");
    const cat = parseYAML(catRaw) as Record<string, unknown>;
    catalogEntries = (cat.actions as CatalogEntry[]) ?? [];
  }

  for (const [i, action] of actions.entries()) {
    const name = String(action.name);
    const tags = (action.danger_tags as string[] | undefined) ?? [];
    const reversible = action.reversible as boolean | undefined;
    const reversalNote = action.reversal_note as string | undefined;

    if (tags.includes("irreversible") && reversible !== false) {
      findings.push({
        severity: "error",
        code: "reversibility/irreversible-tag-requires-false",
        message: `action "${name}" is tagged irreversible but reversible is ${String(reversible)}`,
        pointer: `/actions/${i}/reversible`,
      });
    }
    if (
      tags.includes("destructive") &&
      reversible !== false &&
      (reversalNote === undefined || reversalNote.length === 0)
    ) {
      findings.push({
        severity: "warning",
        code: "reversibility/destructive-needs-reversal-note",
        message: `action "${name}" is tagged destructive; either mark reversible:false or add a reversal_note`,
        pointer: `/actions/${i}`,
      });
    }

    if (catalogEntries) {
      const entry = catalogEntries.find((e) => e.name === name);
      if (entry?.mandatory_tags) {
        for (const mustTag of entry.mandatory_tags) {
          if (!tags.includes(mustTag)) {
            findings.push({
              severity: "error",
              code: "danger-tag/mandatory-missing",
              message: `action "${name}" is listed in ${opts.catalogPath} and must declare danger_tag "${mustTag}"`,
              pointer: `/actions/${i}/danger_tags`,
            });
          }
        }
      }
    }
  }

  const errors = findings.filter((f) => f.severity === "error").length;
  return {
    ok: errors === 0,
    contract_path: contractPath,
    findings,
  };
}

export function formatReport(report: AgentContractReport): string {
  const lines = [`agent-contract-check: ${report.contract_path}`];
  if (report.findings.length === 0) {
    lines.push("  OK — no findings.");
  } else {
    for (const f of report.findings) {
      lines.push(`  [${f.severity}] ${f.code} @ ${f.pointer || "/"}: ${f.message}`);
    }
    const errors = report.findings.filter((f) => f.severity === "error").length;
    const warnings = report.findings.filter((f) => f.severity === "warning").length;
    lines.push(`  summary: ${errors} error(s), ${warnings} warning(s)`);
  }
  return lines.join("\n");
}
