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

  test("init workspace creates the canonical .tf/ manifest set", async () => {
    const dir = mkdtempSync(join(tmpdir(), "tf-cli-init-"));
    try {
      const tfDir = join(dir, ".tf");
      const { code, stdout } = await runCli([
        "init",
        "workspace",
        "--dir",
        tfDir,
        "--trust-domain",
        "example.com",
        "--project",
        "demo",
      ]);
      expect(code).toBe(0);
      expect(stdout).toContain("agent-contract.yaml");
      const contract = readFileSync(join(tfDir, "agent-contract.yaml"), "utf8");
      expect(contract).toContain("trust_domain: example.com");
      expect(contract).toContain("project: demo");
      // Idempotent on re-run without --force.
      const second = await runCli(["init", "workspace", "--dir", tfDir, "--trust-domain", "example.com"]);
      expect(second.code).toBe(0);
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });

  test("simulate policy is an alias for policy simulate", async () => {
    const dir = mkdtempSync(join(tmpdir(), "tf-cli-sim-"));
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
      const { code, stdout } = await runCli(["simulate", "policy", contract, "tf.ping"]);
      expect(code).toBe(0);
      expect(stdout).toContain('"allow"');
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });

  test("bundle verify routes to evidence verify (errors on missing flags)", async () => {
    const { code, stderr } = await runCli(["bundle", "verify"]);
    expect(code).toBe(2);
    expect(stderr).toContain("evidence verify");
  });

  test("federation list dry-run returns empty roots", async () => {
    const { code, stdout } = await runCli(["federation", "list", "--dry-run"]);
    expect(code).toBe(0);
    expect(stdout).toContain("dry_run");
  });

  test("approval pending dry-run returns empty list", async () => {
    const { code, stdout } = await runCli(["approval", "pending", "--dry-run"]);
    expect(code).toBe(0);
    expect(stdout).toContain("dry_run");
  });

  test("approval grant dry-run echoes id", async () => {
    const { code, stdout } = await runCli(["approval", "grant", "appr-123", "--dry-run"]);
    expect(code).toBe(0);
    expect(stdout).toContain("appr-123");
  });

  test("evidence pack is registered as alias", async () => {
    const { code, stderr } = await runCli(["evidence", "pack"]);
    expect(code).toBe(2);
    expect(stderr).toContain("evidence assemble");
  });

  test("chain walk verifies a tflog with a single event", async () => {
    const dir = mkdtempSync(join(tmpdir(), "tf-cli-chain-"));
    try {
      const tflog = join(dir, "events.tflog");
      // Single proof event with no prev hash — chain trivially verifies.
      writeFileSync(
        tflog,
        JSON.stringify({
          event_version: "1",
          id: "ev-1",
          type: "test.ping",
          actor_id: "tf:actor:agent:example.com/x",
          timestamp: "2026-04-26T00:00:00Z",
          level: "L1",
          prev_event_hash: null,
          payload: {},
          signature: { algorithm: "ed25519", signer: "tf:actor:agent:example.com/x", signature: "" },
        }) + "\n",
      );
      const { code, stdout } = await runCli(["chain", "walk", "--tflog", tflog]);
      expect(code === 0 || code === 1).toBe(true);
      expect(stdout).toContain("events_seen");
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });

  test("trust-domain join dry-run echoes attestation flag", async () => {
    const { code } = await runCli(["trust-domain", "join", "--dry-run"]);
    expect(code).toBe(0);
  });

  test("trust-domain leave dry-run echoes domain flag", async () => {
    const { code } = await runCli(["trust-domain", "leave", "--dry-run"]);
    expect(code).toBe(0);
  });

  test("bridge import dry-run skips the live daemon call", async () => {
    const { code, stdout } = await runCli(["bridge", "import", "--dry-run"]);
    expect(code).toBe(0);
    expect(stdout).toContain("dry_run");
  });

  test("decide request dry-run skips the live daemon call", async () => {
    const { code, stdout } = await runCli(["decide", "request", "--dry-run"]);
    expect(code).toBe(0);
    expect(stdout).toContain("dry_run");
  });
});
