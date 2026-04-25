import { afterEach, describe, expect, test } from "bun:test";
import { mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { ed25519Generate, Vault } from "tf-types";
import { runDaemon, type DaemonHandle } from "../src/index";
import { setOtelTestExporter, type RecordedSpan } from "../src/otel";

interface BootedDaemon {
  daemon: DaemonHandle;
  dir: string;
  token: string;
  cleanup: () => void;
}

async function bootDaemon(): Promise<BootedDaemon> {
  const dir = mkdtempSync(join(tmpdir(), "tf-daemon-otel-"));
  const vault = await Vault.createAtPath(join(dir, "vault.json"), "dev-pw", {
    m_cost: 256,
    t_cost: 1,
    p_cost: 1,
  });
  const daemonId = await ed25519Generate();
  vault.store({
    id: "daemon-identity",
    purpose: "signing",
    algorithm: "ed25519",
    key_bytes: daemonId.privateKey,
  });

  const contractPath = join(dir, "contract.yaml");
  writeFileSync(
    contractPath,
    `contract_version: "1"
spec_version: TF-0006-draft
project: otel-e2e
trust_domain: example.com
actions:
  - name: fs.read
    risk: R0
    approval: none
    reversible: true
  - name: fs.write
    risk: R1
    approval: none
    reversible: true
`,
  );

  const configPath = join(dir, "daemon.yaml");
  const proofLogPath = join(dir, "proof.tflog");
  writeFileSync(
    configPath,
    `daemon_version: "1"
self_actor: "tf:actor:service:example.com/tf-daemon"
listen: { kind: websocket, bind: "127.0.0.1", port: 0 }
vault: { path: "${join(dir, "vault.json")}" }
contract_path: "${contractPath}"
proof_log_path: "${proofLogPath}"
`,
  );

  const token = `dev-${Math.random().toString(16).slice(2)}`;
  process.env.TF_ADMIN_TOKEN = token;

  const daemon = await runDaemon({
    configPath,
    passphrase: "dev-pw",
    daemonHttpPort: 0,
    daemonHttpSocket: "",
  });

  return {
    daemon,
    dir,
    token,
    cleanup: () => {
      delete process.env.TF_ADMIN_TOKEN;
      rmSync(dir, { recursive: true, force: true });
    },
  };
}

function decideUrl(daemon: DaemonHandle, path: string): string {
  return `http://127.0.0.1:${daemon.httpPort}${path}`;
}

describe("tf-daemon OTel /v1/decide tracing", () => {
  afterEach(() => {
    setOtelTestExporter(null);
  });

  test("emits one tf.decide span per /v1/decide call with the four standard attributes", async () => {
    const recorded: RecordedSpan[] = [];
    setOtelTestExporter((span) => recorded.push(span));

    const ctx = await bootDaemon();
    try {
      // Drive 5 decide calls; the test exporter records each span synchronously.
      const calls = [
        { actor: "tf:actor:agent:example.com/x", action: "fs.read", target: "/etc/hosts" },
        { actor: "tf:actor:agent:example.com/x", action: "fs.write", target: "/tmp/a" },
        { actor: "tf:actor:agent:example.com/y", action: "fs.read", target: "/var/log/x" },
        { actor: "tf:actor:agent:example.com/y", action: "fs.read", target: "/var/log/y" },
        { actor: "tf:actor:agent:example.com/z", action: "fs.write", target: "/tmp/b" },
      ];
      for (const c of calls) {
        const res = await fetch(decideUrl(ctx.daemon, "/v1/decide"), {
          method: "POST",
          headers: {
            authorization: `Bearer ${ctx.token}`,
            "content-type": "application/json",
          },
          body: JSON.stringify({ ...c, trace_id: "" }),
        });
        expect(res.status).toBe(200);
      }

      expect(recorded.length).toBe(5);
      for (let i = 0; i < calls.length; i++) {
        const span = recorded[i]!;
        const call = calls[i]!;
        expect(span.name).toBe("tf.decide");
        expect(span.attributes["tf.action"]).toBe(call.action);
        expect(span.attributes["tf.target"]).toBe(call.target);
        expect(span.attributes["tf.actor_resolved"]).toBe(call.actor);
        // Both fs.read and fs.write are declared with approval:none in
        // the test contract — every decision should be `allow`.
        expect(span.attributes["tf.decision"]).toBe("allow");
      }
    } finally {
      await ctx.daemon.stop();
      ctx.cleanup();
    }
  });

  test("setupOtel without OTEL_EXPORTER_OTLP_ENDPOINT silently no-ops on the SDK path", async () => {
    // No test exporter installed AND no env var set: spans must be
    // dropped without throwing or breaking decide.
    delete process.env.OTEL_EXPORTER_OTLP_ENDPOINT;
    const ctx = await bootDaemon();
    try {
      const res = await fetch(decideUrl(ctx.daemon, "/v1/decide"), {
        method: "POST",
        headers: {
          authorization: `Bearer ${ctx.token}`,
          "content-type": "application/json",
        },
        body: JSON.stringify({
          actor: "tf:actor:agent:example.com/x",
          action: "fs.read",
          target: "/etc/hosts",
          trace_id: "",
        }),
      });
      expect(res.status).toBe(200);
    } finally {
      await ctx.daemon.stop();
      ctx.cleanup();
    }
  });
});
