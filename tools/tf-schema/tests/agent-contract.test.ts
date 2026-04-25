import { describe, expect, test } from "bun:test";
import { writeFileSync, mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { checkAgentContract } from "../src/agent_contract";

function writeTemp(yaml: string): string {
  const dir = mkdtempSync(join(tmpdir(), "tf-ac-"));
  const file = join(dir, "contract.yaml");
  writeFileSync(file, yaml);
  return file;
}

const REPO_ROOT = join(import.meta.dir, "..", "..", "..");
const CATALOG = join(REPO_ROOT, "examples", "dangerous-actions", "tf-dangerous-std.yaml");

describe("agent-contract-check", () => {
  test("full example passes with zero errors", async () => {
    const report = await checkAgentContract(
      join(REPO_ROOT, "examples", "agent-contracts", "full.yaml"),
      { catalogPath: CATALOG },
    );
    const errs = report.findings.filter((f) => f.severity === "error");
    if (errs.length > 0) console.error(JSON.stringify(errs, null, 2));
    expect(errs).toEqual([]);
  });

  test("detects action in both actions and forbidden", async () => {
    const file = writeTemp(`
contract_version: "1"
spec_version: TF-0006-draft
project: conflict
trust_domain: example.com
actions:
  - name: file.delete
    risk: R4
forbidden:
  - action: file.delete
    reason: "ambiguous"
`);
    const report = await checkAgentContract(file);
    expect(report.ok).toBe(false);
    expect(
      report.findings.some((f) => f.code === "conflict/forbidden-and-allowed"),
    ).toBe(true);
  });

  test("detects missing target set", async () => {
    const file = writeTemp(`
contract_version: "1"
spec_version: TF-0006-draft
project: bad-targets
trust_domain: example.com
target_sets:
  source: ["src/**"]
actions:
  - name: file.read
    risk: R0
    allow_targets: ["@nonexistent"]
`);
    const report = await checkAgentContract(file);
    expect(report.ok).toBe(false);
    expect(report.findings.some((f) => f.code === "target-set/missing")).toBe(true);
  });

  test("flags irreversible tag with reversible=true", async () => {
    const file = writeTemp(`
contract_version: "1"
spec_version: TF-0006-draft
project: bad-rev
trust_domain: example.com
actions:
  - name: file.delete
    risk: R4
    reversible: true
    danger_tags: [irreversible]
`);
    const report = await checkAgentContract(file);
    expect(report.ok).toBe(false);
    expect(
      report.findings.some((f) => f.code === "reversibility/irreversible-tag-requires-false"),
    ).toBe(true);
  });

  test("enforces catalog mandatory_tags", async () => {
    const file = writeTemp(`
contract_version: "1"
spec_version: TF-0006-draft
project: missing-mandatory
trust_domain: example.com
actions:
  - name: shell.exec
    risk: R4
    reversible: false
    danger_tags: [destructive]
`);
    const report = await checkAgentContract(file, { catalogPath: CATALOG });
    // shell.exec's mandatory_tags is [security-sensitive]; contract only has [destructive].
    expect(
      report.findings.some((f) => f.code === "danger-tag/mandatory-missing"),
    ).toBe(true);
  });

  test("warns on library/unknown-action but does not fail", async () => {
    const contract = writeTemp(`
contract_version: "1"
spec_version: TF-0006-draft
project: with-unknown
trust_domain: example.com
actions:
  - name: custom.thing
    risk: R1
`);
    const library = writeTemp(`
actions_library_version: "1"
library_id: tf-actions-std
actions:
  - name: file.read
    default_risk: R0
    default_proof: L0
    description: "Read a file."
`);
    const report = await checkAgentContract(contract, { libraryPath: library });
    expect(report.ok).toBe(true);
    expect(
      report.findings.some(
        (f) => f.severity === "warning" && f.code === "library/unknown-action",
      ),
    ).toBe(true);
  });
});
