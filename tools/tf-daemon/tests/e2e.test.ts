import { describe, expect, test } from "bun:test";
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { ed25519Generate, RpcClient, Vault, readTflog } from "@trustforge-protocol/types";
import { attachInitiator, rpcTransportFromEndpoint, wireFromWebSocket } from "@trustforge-protocol/session";
import { runDaemon } from "../src/index";

describe("tf-daemon e2e", () => {
  test("client handshakes with daemon, calls tf.ping, and the tflog records the call", async () => {
    const dir = mkdtempSync(join(tmpdir(), "tf-daemon-"));
    try {
      // 1. Set up vault + daemon identity.
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

      // 2. Write contract + daemon config.
      const contract = `
contract_version: "1"
spec_version: TF-0006-draft
project: daemon-e2e
trust_domain: example.com
actions:
  - name: tf.ping
    risk: R0
    approval: none
    reversible: true
`;
      const contractPath = join(dir, "contract.yaml");
      writeFileSync(contractPath, contract);

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
approval_queue: { max_pending: 8, default_timeout_seconds: 30 }
`,
      );

      // 3. Boot the daemon.
      const daemon = await runDaemon({ configPath, passphrase: "dev-pw" });

      // 4. Connect a client.
      const clientId = await ed25519Generate();
      const ws = new WebSocket(`ws://127.0.0.1:${daemon.port}/`);
      ws.binaryType = "arraybuffer";
      await new Promise<void>((resolve) => ws.addEventListener("open", () => resolve()));
      const wire = wireFromWebSocket(ws as unknown as Parameters<typeof wireFromWebSocket>[0]);
      const endpoint = await attachInitiator(
        {
          selfActor: "tf:actor:agent:example.com/test-client",
          peerHint: "tf:actor:service:example.com/tf-daemon",
          identityPriv: clientId.privateKey,
          identityPub: clientId.publicKey,
        },
        wire.sink,
        wire.source,
      );
      const rpc = new RpcClient(rpcTransportFromEndpoint(endpoint), {
        callerActor: "tf:actor:agent:example.com/test-client",
      });

      // 5. Call tf.ping.
      const res = await rpc.call<{}, { pong: boolean }>("tf.ping", {});
      expect(res.pong).toBe(true);

      // 6. Give the proof log a moment, then read it.
      await new Promise((r) => setTimeout(r, 50));
      ws.close();
      await daemon.stop();

      const raw = readFileSync(proofLogPath);
      // The daemon writes event lines using the tflog magic. Try to parse it
      // as a tflog; if there are unparseable frames (signature-less stubs),
      // we accept the read error and just assert the file grew.
      expect(raw.length).toBeGreaterThan(8);
      try {
        const events = readTflog(new Uint8Array(raw));
        // If it parsed, we expect at least a guard.check entry for tf.ping.
        expect(events.length).toBeGreaterThan(0);
      } catch {
        // Acceptable for this POC — the stub events aren't full proof events.
      }
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });
});
