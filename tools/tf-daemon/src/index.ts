/**
 * tf-daemon — long-running TrustForge session + RPC server.
 *
 * Responsibilities:
 *   - Listen for incoming WebSocket sessions and drive the Phase 3 handshake.
 *   - Enforce the bound agent-contract via AgentGuard on every incoming RPC.
 *   - Queue approval requests when the guard escalates.
 *   - Append every RPC call and guard event to a .tflog.
 */

import { appendFileSync, existsSync, readFileSync, writeFileSync } from "node:fs";
import { parse as parseYAML } from "yaml";
import {
  AgentGuard,
  ApprovalQueue,
  PluginRegistry,
  RpcServer,
  Vault,
  allowAllEnforcer,
  b64decode,
  canonicalize,
  ed25519PublicKey,
  type CapabilityEnforcer,
  type GuardDecision,
  type GuardEventStub,
  type PluginHost,
  type RpcProofEventStub,
  type SessionFrame,
} from "tf-types";
import type { DaemonConfig } from "tf-types";
import type { ApprovalRequest } from "tf-types";
import {
  attachResponder,
  rpcTransportFromEndpoint,
  type SessionEndpoint,
} from "tf-session";

export interface DaemonRuntimeOptions {
  configPath: string;
  passphrase: string;
  onApprovalRequest?: (req: ApprovalRequest) => void;
  /** Signed plugin manifests to load before the daemon starts accepting
   *  connections. Each manifest is verified and its handlers are registered
   *  on every new RpcServer instance. */
  plugins?: string[];
  /** Supplied to the plugin host when loading. Tests wire this to collect
   *  emitted plugin logs. */
  pluginHost?: PluginHost;
}

export interface DaemonHandle {
  port: number;
  stop(): Promise<void>;
  approvalQueue: ApprovalQueue;
  proofLogPath: string;
}

/** Build a CapabilityEnforcer that routes guarded actions through the approval
 *  queue. On approval-required / escalate the enforcer pushes an
 *  ApprovalRequest and awaits the response; approve → "allow", deny →
 *  "permission_denied". */
function enforcerFromGuard(
  guard: AgentGuard,
  queue: ApprovalQueue,
  opts: {
    onEvent?: (ev: GuardEventStub) => void;
  } = {},
): CapabilityEnforcer {
  return {
    check: async (caller, method, capability) => {
      const action = capability || method;
      const decision: GuardDecision = guard.check({
        actor: caller,
        action,
        target: undefined,
      });
      opts.onEvent?.({
        type: "guard.check",
        actor: caller,
        action,
        decision: decision.kind,
        danger_tags: decision.danger_tags,
      });
      switch (decision.kind) {
        case "allow":
        case "log-only":
          return "allow";
        case "deny":
          return { deny: decision.reason };
        case "approval-required":
        case "escalate": {
          const requestId = `req-${Date.now()}-${Math.floor(Math.random() * 1_000_000).toString(16)}`;
          try {
            const response = await queue.push({
              request_version: "1",
              id: requestId,
              actor: caller,
              action,
              danger_tags: decision.danger_tags as ApprovalRequest["danger_tags"],
              reason:
                decision.kind === "escalate"
                  ? `escalated: ${"reason" in decision ? decision.reason : "dangerous"}`
                  : `approval required for ${action}`,
              created_at: new Date().toISOString(),
            });
            if (response.decision === "approve") return "allow";
            return { deny: response.note ? `approval denied: ${response.note}` : "approval denied" };
          } catch (err) {
            return { deny: `approval queue error: ${(err as Error).message}` };
          }
        }
      }
    },
  };
}

export async function runDaemon(opts: DaemonRuntimeOptions): Promise<DaemonHandle> {
  const config = parseYAML(readFileSync(opts.configPath, "utf8")) as DaemonConfig;
  const contract = parseYAML(readFileSync(config.contract_path, "utf8")) as Record<string, unknown>;
  const proofLogPath = config.proof_log_path;
  if (!existsSync(proofLogPath)) {
    writeFileSync(proofLogPath, new Uint8Array([0x54, 0x46, 0x4c, 0x4f, 0x47, 0x01, 0x00, 0x00]));
  }

  const vault = await Vault.openAtPath(config.vault.path, opts.passphrase);
  const idEntry = vault.read("daemon-identity");
  const identityPub = await ed25519PublicKey(idEntry.key_bytes);

  const guard = AgentGuard.fromContract(contract, {
    onEvent: (ev) => appendEventLine(proofLogPath, ev),
  });
  const queue = new ApprovalQueue({
    maxPending: config.approval_queue?.max_pending ?? 32,
    defaultTimeoutMs: (config.approval_queue?.default_timeout_seconds ?? 300) * 1000,
    onPush: (req) => {
      appendEventLine(proofLogPath, {
        type: "approval.request",
        actor: req.actor,
        action: req.action,
        decision: "pending",
        danger_tags: req.danger_tags ?? [],
      });
      opts.onApprovalRequest?.(req);
    },
    onResolve: (req, decision, note) => {
      appendEventLine(proofLogPath, {
        type: `approval.${decision}`,
        actor: req.actor,
        action: req.action,
        decision,
        note: note ?? "",
      });
    },
  });

  const listeners: Array<{ close: () => void }> = [];

  // Optional plugins: load + verify all manifests once; registry instance is
  // shared across every incoming RpcServer.
  const pluginHost: PluginHost = opts.pluginHost ?? {
    log: (msg: unknown) => {
      appendEventLine(proofLogPath, { type: "plugin.log", message: String(msg) });
    },
  };
  const pluginRegistry = new PluginRegistry();
  for (const manifestPath of opts.plugins ?? []) {
    await pluginRegistry.load(manifestPath, pluginHost);
  }

  const listen = config.listen ?? { kind: "websocket", bind: "127.0.0.1", port: 0 };
  const server = Bun.serve({
    port: Number((listen as any).port ?? 0),
    hostname: String((listen as any).bind ?? "127.0.0.1"),
    fetch(req, server) {
      if (server.upgrade(req, { data: {} as never })) return;
      return new Response("expected websocket", { status: 400 });
    },
    websocket: {
      open(ws) {
        ws.binaryType = "uint8array";
        const wire = wireFromBunServerSocket(ws);
        (ws.data as any).wire = wire;
        attachResponder(
          {
            selfActor: config.self_actor,
            identityPriv: idEntry.key_bytes,
            identityPub,
          },
          wire.sink,
          wire.source,
        ).then((endpoint: SessionEndpoint) => {
          const rpc = new RpcServer(rpcTransportFromEndpoint(endpoint), {
            selfActor: config.self_actor,
            enforcer: enforcerFromGuard(guard, queue),
            onProofEvent: (ev: RpcProofEventStub) => appendEventLine(proofLogPath, ev),
          });
          listeners.push({ close: () => endpoint.close("daemon shutdown") });
          // Default built-in: a tiny "ping" unary so a client can verify the
          // pipeline without needing any registered plugin.
          rpc.registerUnary("tf.ping", "tf.ping", async () => ({ pong: true, at: new Date().toISOString() }));
          // Bind every loaded plugin's declared-capability handlers.
          pluginRegistry.registerOn(rpc);
        });
      },
      message(ws, message) {
        const w = (ws.data as any).wire as ReturnType<typeof wireFromBunServerSocket>;
        w.deliverMessage(message);
      },
      close(ws) {
        const w = (ws.data as any).wire as ReturnType<typeof wireFromBunServerSocket> | undefined;
        if (w) w.deliverClose();
      },
    },
  });

  return {
    port: server.port ?? 0,
    proofLogPath,
    approvalQueue: queue,
    stop: async () => {
      queue.drainDeny("daemon shutdown");
      for (const l of listeners) l.close();
      server.stop(true);
    },
  };
}

function appendEventLine(path: string, ev: unknown): void {
  const payload = new TextEncoder().encode(canonicalize(ev));
  // Write a 4-byte BE length prefix + canonical JSON bytes, matching the
  // Phase 2 .tflog framing for an appended "event" (signature-less stub).
  const header = new Uint8Array(4);
  new DataView(header.buffer).setUint32(0, payload.length, false);
  appendFileSync(path, Buffer.concat([header, payload]));
}

function wireFromBunServerSocket(ws: import("bun").ServerWebSocket<unknown>) {
  const messageListeners = new Set<(b: Uint8Array) => void>();
  const closeListeners = new Set<() => void>();
  return {
    sink: {
      send(bytes: Uint8Array) {
        ws.send(bytes);
      },
      close() {
        ws.close();
      },
    },
    source: {
      onMessage(l: (b: Uint8Array) => void) {
        messageListeners.add(l);
      },
      onClose(l: () => void) {
        closeListeners.add(l);
      },
    },
    deliverMessage(message: string | Uint8Array | Buffer) {
      let bytes: Uint8Array;
      if (typeof message === "string") bytes = new TextEncoder().encode(message);
      else bytes = new Uint8Array(message);
      for (const l of messageListeners) l(bytes);
    },
    deliverClose() {
      for (const l of closeListeners) l();
    },
  };
}
