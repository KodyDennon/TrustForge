import { describe, expect, test } from "bun:test";
import { mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

function writeConfig(dir: string, extra = ""): string {
  const contractPath = join(dir, "contract.yaml");
  const vaultPath = join(dir, "vault.json");
  const proofLogPath = join(dir, "proof.tflog");
  writeFileSync(
    contractPath,
    `contract_version: "1"
spec_version: TF-0006-draft
project: cli-check
trust_domain: example.com
actions:
  - name: fs.read
    risk: R0
    approval: none
    reversible: true
`,
  );
  writeFileSync(vaultPath, "{}");
  const configPath = join(dir, "daemon.yaml");
  writeFileSync(
    configPath,
    `daemon_version: "1"
self_actor: "tf:actor:service:example.com/tf-daemon"
listen: { kind: websocket, bind: "127.0.0.1", port: 0 }
vault: { path: "${vaultPath}" }
contract_path: "${contractPath}"
proof_log_path: "${proofLogPath}"
${extra}
`,
  );
  return configPath;
}

async function runCli(args: string[]) {
  const proc = Bun.spawn(["bun", "run", "tools/tf-daemon/src/cli.ts", ...args], {
    cwd: join(import.meta.dir, "..", "..", ".."),
    stdout: "pipe",
    stderr: "pipe",
    env: { ...process.env, TF_VAULT_PASS: "" },
  });
  const [stdout, stderr, exitCode] = await Promise.all([
    new Response(proc.stdout).text(),
    new Response(proc.stderr).text(),
    proc.exited,
  ]);
  return { stdout, stderr, exitCode };
}

describe("tf-daemon CLI", () => {
  test("run --config --dry-run validates config without requiring TF_VAULT_PASS or booting listeners", async () => {
    const dir = mkdtempSync(join(tmpdir(), "tf-daemon-cli-"));
    try {
      const configPath = writeConfig(dir, "profile: tf-home-compatible");
      const result = await runCli(["run", "--config", configPath, "--dry-run"]);

      expect(result.exitCode).toBe(0);
      expect(result.stdout).toContain("config ok");
      expect(result.stdout).not.toContain("listening on port");
      expect(result.stderr).toBe("");
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });

  test("run --config --print-config prints effective config with secrets redacted", async () => {
    const dir = mkdtempSync(join(tmpdir(), "tf-daemon-cli-"));
    try {
      const configPath = writeConfig(
        dir,
        `admin: { enabled: true, token_env: TF_ADMIN_TOKEN }
http:
  tcp: { enabled: true, bind: "127.0.0.1", port: 8642, auth: bearer }
  unix: { enabled: true, path: "/run/trustforge/decide.sock", auth: local-peer }
`,
      );
      const result = await runCli(["run", "--config", configPath, "--print-config"]);

      expect(result.exitCode).toBe(0);
      const printed = JSON.parse(result.stdout) as Record<string, unknown>;
      expect(printed.admin).toEqual({ enabled: true, token_env: "TF_ADMIN_TOKEN", token: "<redacted>" });
      expect(printed.http).toEqual({
        tcp: { enabled: true, bind: "127.0.0.1", port: 8642, auth: "bearer" },
        unix: { enabled: true, path: "/run/trustforge/decide.sock", auth: "local-peer" },
      });
      expect(result.stderr).toBe("");
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });
});
