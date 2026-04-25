import { describe, expect, test } from "bun:test";
import { mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import {
  derivePeerActor,
  ed25519Generate,
  RpcClient,
  Vault,
} from "tf-types";
import { attachInitiator, rpcTransportFromEndpoint, wireFromWebSocket } from "tf-session";
import { runDaemon } from "../src/index";

describe("daemon propagates key-derived caller to AgentGuard", () => {
  test("a client allowed by allow_actors thumbprint can call the action", async () => {
    const dir = mkdtempSync(join(tmpdir(), "tf-daemon-actorauth-"));
    try {
      // 1. Vault + identity.
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

      // 2. Client identity. Compute its key-derived URI ahead of time.
      const clientId = await ed25519Generate();
      const clientActor = derivePeerActor(clientId.publicKey);

      // 3. Contract permits ONLY the client's thumbprint URI to call tf.ping.
      const contractPath = join(dir, "contract.yaml");
      writeFileSync(
        contractPath,
        `contract_version: "1"
spec_version: TF-0006-draft
project: actorauth-daemon-e2e
trust_domain: example.com
actions:
  - name: tf.ping
    risk: R0
    approval: none
    reversible: true
    allow_actors:
      - "${clientActor}"
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

      const daemon = await runDaemon({ configPath, passphrase: "dev-pw" });

      const ws = new WebSocket(`ws://127.0.0.1:${daemon.port}/`);
      ws.binaryType = "arraybuffer";
      await new Promise<void>((resolve) => ws.addEventListener("open", () => resolve()));
      const wire = wireFromWebSocket(ws as unknown as Parameters<typeof wireFromWebSocket>[0]);
      const endpoint = await attachInitiator(
        {
          selfActor: clientActor,
          identityPriv: clientId.privateKey,
          identityPub: clientId.publicKey,
        },
        wire.sink,
        wire.source,
      );
      const rpc = new RpcClient(rpcTransportFromEndpoint(endpoint), {
        callerActor: clientActor,
      });

      const res = await rpc.call<{}, { pong: boolean }>("tf.ping", {});
      expect(res.pong).toBe(true);

      ws.close();
      await daemon.stop();
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });

  test("a client NOT in allow_actors gets denied even with valid handshake", async () => {
    const dir = mkdtempSync(join(tmpdir(), "tf-daemon-actorauth-deny-"));
    try {
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

      const clientId = await ed25519Generate();
      // Contract permits ONLY a different thumbprint than the client's.
      const allowed = "tf:actor:process:key/0000000000000000";

      const contractPath = join(dir, "contract.yaml");
      writeFileSync(
        contractPath,
        `contract_version: "1"
spec_version: TF-0006-draft
project: actorauth-deny-e2e
trust_domain: example.com
actions:
  - name: tf.ping
    risk: R0
    approval: none
    reversible: true
    allow_actors:
      - "${allowed}"
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

      const daemon = await runDaemon({ configPath, passphrase: "dev-pw" });

      const ws = new WebSocket(`ws://127.0.0.1:${daemon.port}/`);
      ws.binaryType = "arraybuffer";
      await new Promise<void>((resolve) => ws.addEventListener("open", () => resolve()));
      const wire = wireFromWebSocket(ws as unknown as Parameters<typeof wireFromWebSocket>[0]);
      const endpoint = await attachInitiator(
        {
          selfActor: derivePeerActor(clientId.publicKey),
          identityPriv: clientId.privateKey,
          identityPub: clientId.publicKey,
        },
        wire.sink,
        wire.source,
      );
      const rpc = new RpcClient(rpcTransportFromEndpoint(endpoint), {
        callerActor: derivePeerActor(clientId.publicKey),
      });

      let denied = false;
      try {
        await rpc.call<{}, { pong: boolean }>("tf.ping", {});
      } catch (err) {
        denied = String(err).includes("permission_denied") || String(err).includes("allow_actors") || String(err).includes("approval denied");
      }
      expect(denied).toBe(true);

      ws.close();
      await daemon.stop();
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });
});
