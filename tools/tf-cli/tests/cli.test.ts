import { describe, expect, test } from "bun:test";
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

const CLI = join(import.meta.dir, "..", "src", "cli.ts");

async function runCli(args: string[]): Promise<{ code: number; stdout: string; stderr: string }> {
  const proc = Bun.spawn(["bun", "run", CLI, ...args], {
    stdout: "pipe",
    stderr: "pipe",
  });
  const stdout = await new Response(proc.stdout).text();
  const stderr = await new Response(proc.stderr).text();
  const code = await proc.exited;
  return { code, stdout, stderr };
}

describe("tf CLI", () => {
  test("policy simulate allows tf.ping against the example contract", async () => {
    const dir = mkdtempSync(join(tmpdir(), "tf-cli-"));
    try {
      const contract = join(dir, "contract.yaml");
      writeFileSync(
        contract,
        `contract_version: "1"
spec_version: TF-0006-draft
project: cli-test
trust_domain: example.com
actions:
  - name: tf.ping
    risk: R0
    approval: none
`,
      );
      const { code, stdout } = await runCli(["policy", "simulate", contract, "tf.ping"]);
      expect(code).toBe(0);
      expect(stdout).toContain('"allow"');
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });

  test("actor create writes a valid identity document", async () => {
    const dir = mkdtempSync(join(tmpdir(), "tf-cli-"));
    try {
      const out = join(dir, "actor.json");
      const { code } = await runCli([
        "actor",
        "create",
        "--name",
        "demo",
        "--type",
        "agent",
        "--out",
        out,
      ]);
      expect(code).toBe(0);
      const parsed = JSON.parse(readFileSync(out, "utf8"));
      expect(parsed.identity.actor_id).toBe("tf:actor:agent:local.example/demo");
      expect(parsed.identity.public_keys).toHaveLength(1);
      expect(parsed.private_key_base64.length).toBeGreaterThan(20);
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });

  test("actor inspect redacts the private key", async () => {
    const dir = mkdtempSync(join(tmpdir(), "tf-cli-"));
    try {
      const out = join(dir, "actor.json");
      await runCli(["actor", "create", "--name", "x", "--out", out]);
      const { code, stdout } = await runCli(["actor", "inspect", out]);
      expect(code).toBe(0);
      expect(stdout).not.toContain("private_key_base64");
      expect(stdout).toContain("actor_id");
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });

  test("unknown command prints usage and exits non-zero", async () => {
    const { code, stderr } = await runCli(["bogus"]);
    expect(code).toBe(2);
    expect(stderr).toContain("usage");
  });
});
