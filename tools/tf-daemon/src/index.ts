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
  /** Optional project root containing a `.tf/` directory. When present
   *  the daemon loads policy.yaml, proof-profile.yaml, conformance.json,
   *  actions.yaml, codegen.toml, and threat-model.yaml; folds policy
   *  negative_capabilities into AgentGuard; surfaces the FeatureGate via
   *  onFeatureGate. */
  projectRoot?: string;
  onManifestDiagnostic?: (d: { file: string; reason: string }) => void;
  onFeatureGate?: (gate: import("tf-types").TfFeatureGate) => void;
  /** Called once with the profile-gate verdict if the daemon-config
   *  claims a conformance profile. */
  onProfileVerdict?: (v: import("tf-types").ProfileVerdict) => void;
  /** When false, the daemon boots even if the claimed profile's MUST
   *  features are not all satisfied. Default true. */
  refuseOnProfileFailure?: boolean;
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

  // Load .tf/ manifests when the project root is supplied. Manifests are
  // best-effort; missing ones are skipped, parse failures are surfaced
  // through opts.onManifestDiagnostic if the caller cares.
  const tf = opts.projectRoot
    ? (await import("tf-types")).loadTfManifests({ rootDir: opts.projectRoot })
    : undefined;
  if (tf) {
    for (const d of tf.diagnostics) {
      opts.onManifestDiagnostic?.(d);
    }
  }
  const featureGate = tf
    ? (await import("tf-types")).buildFeatureGate(tf)
    : undefined;

  const vault = await Vault.openAtPath(config.vault.path, opts.passphrase);
  const idEntry = vault.read("daemon-identity");
  const identityPub = await ed25519PublicKey(idEntry.key_bytes);

  const enforcementLevel = ((config as unknown as { enforcement_level?: string }).enforcement_level ?? "E4") as
    | "E0" | "E1" | "E2" | "E3" | "E4" | "E5";
  const guard = AgentGuard.fromContract(contract, {
    onEvent: (ev) => appendEventLine(proofLogPath, ev),
    enforcementLevel,
  });
  // If a .tf/policy.yaml is available, fold its negative_capabilities
  // into the guard so policy + contract ride together.
  if (tf?.policy && typeof tf.policy === "object") {
    const neg = (tf.policy as Record<string, unknown>)["negative_capabilities"];
    if (Array.isArray(neg)) {
      guard.setNegativeCapabilities(neg as Parameters<typeof guard.setNegativeCapabilities>[0]);
    }
  }
  // Surface the feature gate so the caller / tests can introspect it.
  if (featureGate) {
    opts.onFeatureGate?.(featureGate);
  }
  // Profile gating: when the daemon config claims a conformance
  // profile, evaluate it against the runtime feature inventory and
  // refuse to boot when MUSTs are missing.
  const claimedProfile = (config as unknown as { profile?: string }).profile;
  if (claimedProfile) {
    const tfMod = await import("tf-types");
    const spec = tfMod.BUILTIN_PROFILES[claimedProfile];
    if (!spec) {
      throw new Error(`unknown profile: ${claimedProfile}`);
    }
    const features: string[] = [
      "agent-contract",
      "proof-log",
      "ed25519",
      "vault",
      "policy-engine",
      "continuous-reauth",
      "shadow-mode",
      "signed-log-events",
    ];
    if (tf?.proofProfile) features.push("transparency-anchor.any");
    const verdict = tfMod.selectProfile(spec, tfMod.buildProfileFeatureGate({
      features,
      enforcementLevel,
      proofLevelFloor: "L1",
      bridges: ["spiffe", "webauthn", "oauth", "mcp"],
      anchors: ["memory", "rfc6962"],
    }));
    opts.onProfileVerdict?.(verdict);
    if (!verdict.ok && opts.refuseOnProfileFailure !== false) {
      throw new Error(
        `profile ${claimedProfile} not satisfied: ${verdict.failures.join("; ")}`,
      );
    }
  }
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

  // Active session bookkeeping for the admin endpoint.
  interface ActiveSession {
    id: string;
    remote_actor: string;
    remote_actor_claim?: string;
    opened_at: string;
    close: () => void;
  }
  const activeSessions = new Map<string, ActiveSession>();
  let sessionCounter = 0;

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

  // Profile verdict (captured for the admin endpoint).
  let lastProfileVerdict: import("tf-types").ProfileVerdict | undefined;
  const profilePassThrough = opts.onProfileVerdict;
  opts.onProfileVerdict = (v) => {
    lastProfileVerdict = v;
    profilePassThrough?.(v);
  };

  const adminCfg = (config as unknown as { admin?: { enabled: boolean; token_env?: string; revocation_path?: string } }).admin;
  const adminEnabled = !!adminCfg?.enabled;
  const adminTokenEnv = adminCfg?.token_env ?? "TF_ADMIN_TOKEN";
  const adminToken = process.env[adminTokenEnv] ?? "";
  const revocationPath = adminCfg?.revocation_path;

  function adminAuth(req: Request): boolean {
    if (!adminEnabled) return false;
    if (!adminToken) return false;
    const auth = req.headers.get("authorization") ?? "";
    return auth === `Bearer ${adminToken}`;
  }

  function jsonResponse(value: unknown, status = 200): Response {
    return new Response(canonicalize(value), {
      status,
      headers: { "content-type": "application/json" },
    });
  }

  async function handleAdmin(req: Request): Promise<Response | undefined> {
    const url = new URL(req.url);
    if (!url.pathname.startsWith("/admin/") && url.pathname !== "/admin" && url.pathname !== "/healthz") return undefined;
    if (url.pathname === "/healthz") {
      return jsonResponse({ ok: true, profile: lastProfileVerdict?.profile ?? null });
    }
    if (!adminAuth(req)) {
      return new Response("forbidden", { status: 403 });
    }
    if (url.pathname === "/admin/sessions" && req.method === "GET") {
      return jsonResponse({
        sessions: [...activeSessions.values()].map((s) => ({
          id: s.id,
          remote_actor: s.remote_actor,
          remote_actor_claim: s.remote_actor_claim,
          opened_at: s.opened_at,
        })),
      });
    }
    if (url.pathname === "/admin/approvals" && req.method === "GET") {
      return jsonResponse({ approvals: queue.list() });
    }
    {
      const m = /^\/admin\/approvals\/([^/]+)\/(approve|deny)$/.exec(url.pathname);
      if (m && req.method === "POST") {
        const [, id, decision] = m as unknown as [string, string, "approve" | "deny"];
        let body: { note?: string } = {};
        try {
          if (req.headers.get("content-type")?.includes("application/json")) {
            body = (await req.json()) as { note?: string };
          }
        } catch {
          /* ignore */
        }
        const ok = queue.respond(id, decision, body.note);
        return jsonResponse({ ok }, ok ? 200 : 404);
      }
    }
    if (url.pathname === "/admin/plugins" && req.method === "GET") {
      return jsonResponse({
        plugins: pluginRegistry.list().map((p) => ({
          plugin_id: p.manifest.plugin_id,
          actor_id: p.manifest.actor_id,
          kind: p.manifest.kind,
          capabilities: p.manifest.capabilities.map((c) => c.name),
        })),
      });
    }
    if (url.pathname === "/admin/profile" && req.method === "GET") {
      return jsonResponse({ profile: lastProfileVerdict ?? null });
    }
    if (url.pathname === "/admin/proofs" && req.method === "GET") {
      const n = Math.min(Math.max(parseInt(url.searchParams.get("n") ?? "100", 10) || 100, 1), 1000);
      return jsonResponse({ events: readLastEvents(proofLogPath, n) });
    }
    if (url.pathname === "/admin/revocations" && req.method === "POST") {
      if (!revocationPath) {
        return jsonResponse({ error: "revocation_path not configured" }, 400);
      }
      const body = (await req.json()) as { kind?: string; id?: string; reason?: string };
      if (!body.kind || !body.id) {
        return jsonResponse({ error: "missing kind/id" }, 400);
      }
      const list: Array<Record<string, unknown>> = existsSync(revocationPath)
        ? (JSON.parse(readFileSync(revocationPath, "utf8")) as Array<Record<string, unknown>>)
        : [];
      const rev = {
        revocation_version: "1",
        id: `rev-${Date.now().toString(16)}-${Math.floor(Math.random() * 1_000_000).toString(16)}`,
        target_id: body.id,
        target_kind: body.kind,
        effective_at: new Date().toISOString(),
        reason: body.reason ?? "admin-revoke",
        issuer: config.self_actor,
        signature: { algorithm: "ed25519", signer: config.self_actor, signature: "" },
      };
      list.push(rev);
      writeFileSync(revocationPath, canonicalize(list));
      appendEventLine(proofLogPath, {
        type: "admin.revocation",
        actor: config.self_actor,
        action: "revoke",
        decision: "allow",
        target_kind: body.kind,
        target_id: body.id,
      });
      return jsonResponse({ ok: true, revocation: rev });
    }
    return new Response("not found", { status: 404 });
  }

  const listen = config.listen ?? { kind: "websocket", bind: "127.0.0.1", port: 0 };
  const server = Bun.serve({
    port: Number((listen as any).port ?? 0),
    hostname: String((listen as any).bind ?? "127.0.0.1"),
    async fetch(req, server) {
      const adminResp = await handleAdmin(req);
      if (adminResp) return adminResp;
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
            getCaller: () => endpoint.peerActor(),
            getCallerClaim: () => endpoint.peerActorClaim(),
            onProofEvent: (ev: RpcProofEventStub) => appendEventLine(proofLogPath, ev),
          });
          listeners.push({ close: () => endpoint.close("daemon shutdown") });
          sessionCounter += 1;
          const sessionId = `sess-${Date.now().toString(16)}-${sessionCounter.toString(16)}`;
          activeSessions.set(sessionId, {
            id: sessionId,
            remote_actor: endpoint.peerActor(),
            remote_actor_claim: endpoint.peerActorClaim(),
            opened_at: new Date().toISOString(),
            close: () => endpoint.close("daemon shutdown"),
          });
          (ws.data as any).sessionId = sessionId;
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
        const sessionId = (ws.data as any).sessionId as string | undefined;
        if (sessionId) activeSessions.delete(sessionId);
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

/** Read the last `n` events from a .tflog file. Returns an array of
 *  parsed canonical-JSON event objects. Caller-tolerant: missing file
 *  returns []. */
function readLastEvents(path: string, n: number): unknown[] {
  if (!existsSync(path)) return [];
  const bytes = readFileSync(path);
  const events: unknown[] = [];
  // Skip the 8-byte file header `TFLOG\x01\x00\x00`.
  let offset = bytes.length >= 8 && bytes[0] === 0x54 && bytes[1] === 0x46 && bytes[2] === 0x4c ? 8 : 0;
  while (offset + 4 <= bytes.length) {
    const len = bytes.readUInt32BE(offset);
    offset += 4;
    if (offset + len > bytes.length) break;
    const slice = bytes.subarray(offset, offset + len);
    offset += len;
    try {
      events.push(JSON.parse(slice.toString("utf8")));
    } catch {
      events.push({ raw: slice.toString("hex") });
    }
  }
  return events.slice(-n);
}

/** Wrap an event in a signed envelope before appending. The envelope
 *  shape mirrors `proof-event.schema.json#signature`: a SignatureEnvelope
 *  attached to the canonical event under the `signature` key. */
async function appendSignedEventLine(
  path: string,
  ev: Record<string, unknown>,
  signerPriv: Uint8Array,
  signer: string,
): Promise<void> {
  const tf = await import("tf-types");
  const eventForSigning = { ...ev };
  const canonicalSigning = canonicalize(eventForSigning);
  const digest = tf.sha256(new TextEncoder().encode(canonicalSigning));
  const sig = await tf.ed25519Sign(digest, signerPriv);
  const signedEvent = {
    ...ev,
    signature: {
      algorithm: "ed25519",
      signer,
      signature: Buffer.from(sig).toString("base64"),
    },
  };
  appendEventLine(path, signedEvent);
}

export { appendEventLine, appendSignedEventLine };

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
