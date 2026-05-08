/**
 * tf-daemon — long-running TrustForge session + RPC server.
 *
 * Responsibilities:
 *   - Listen for incoming WebSocket sessions and drive the Phase 3 handshake.
 *   - Enforce the bound agent-contract via AgentGuard on every incoming RPC.
 *   - Queue approval requests when the guard escalates.
 *   - Append every RPC call and guard event to a .tflog.
 */

import { appendFileSync, existsSync, mkdtempSync, readFileSync, renameSync, writeFileSync } from "node:fs";
import { timingSafeEqual as nodeTimingSafeEqual } from "node:crypto";
import { dirname, resolve as resolvePath, join as joinPath } from "node:path";
import { parse as parseYAML } from "yaml";
import { BridgesRegistry } from "tf-types";
import {
  hostTokenKindToBridge,
  resolveCredential,
  type ResolvedCredential,
} from "./credential-resolver";
import {
  AgentGuard,
  ApprovalQueue,
  PluginRegistry,
  ProofChain,
  QuorumApprovalCollector,
  RpcServer,
  Vault,
  allowAllEnforcer,
  b64decode,
  buildProofEvent,
  canonicalize,
  ed25519PublicKey,
  signProofEvent,
  type BuiltProofEvent,
  type CapabilityEnforcer,
  type GuardDecision,
  type GuardEventStub,
  type PluginHost,
  type ProofChainLevel,
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
import { httpBridgeHandler } from "./http-bridge";
import { recordDecideSpan, setupOtel, type OtelHandle } from "./otel";

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
  /** TCP port for the v1 HTTP endpoint suite (`/v1/decide`,
   *  `/v1/import-credential`, `/v1/proof/*`). Default 8642. Pass 0 to
   *  let the OS pick (used by tests). Pass -1 to disable the TCP
   *  listener entirely. */
  daemonHttpPort?: number;
  /** Hostname for the v1 HTTP listener. Default 127.0.0.1. */
  daemonHttpHost?: string;
  /** Unix socket path for the v1 HTTP endpoint suite. Default
   *  `/run/trustforge/decide.sock`. Pass an empty string to disable
   *  Unix-socket binding (tests do this to avoid sharing the
   *  per-user socket across runs). */
  daemonHttpSocket?: string;
  /** Path to a `.tf/bridges.yaml` registry file. When omitted the
   *  resolver uses built-in defaults. When set the file is loaded once
   *  at boot and registry overrides apply per credential. */
  bridgesRegistryPath?: string;
  /** OTLP gRPC endpoint for OpenTelemetry tracing. Falls back to
   *  `OTEL_EXPORTER_OTLP_ENDPOINT`. When neither is set, tracing is off
   *  but `recordDecideSpan` still no-ops (and the test exporter, if
   *  installed, still receives spans). */
  otelEndpoint?: string;
}

export interface DaemonHandle {
  port: number;
  stop(): Promise<void>;
  approvalQueue: ApprovalQueue;
  proofLogPath: string;
  /** Resolved port for the v1 HTTP listener (8642 by default; 0 means
   *  the OS picked one — read this back in tests). `null` when the
   *  TCP listener was disabled via `daemonHttpPort: -1`. */
  httpPort: number | null;
  /** Resolved Unix-socket path for the v1 HTTP listener. `null` when
   *  the socket binding was disabled via `daemonHttpSocket: ""`. */
  httpSocketPath: string | null;
}

/** Risk classes that trigger the QuorumApprovalCollector instead of a
 *  single-approver queue. R4/R5 actions and explicit "irreversible" /
 *  "legal-exposure" / "financial" danger tags route through quorum per
 *  the enterprise + compliance profiles. */
const QUORUM_DANGER_TAGS = new Set(["irreversible", "legal-exposure", "financial"]);

function shouldRequireQuorum(decision: GuardDecision, action: string): boolean {
  if (decision.kind !== "approval-required" && decision.kind !== "escalate") return false;
  if (action.startsWith("admin.")) return true;
  if ("danger_tags" in decision) {
    for (const t of decision.danger_tags ?? []) if (QUORUM_DANGER_TAGS.has(t)) return true;
  }
  return false;
}

/** Build a CapabilityEnforcer that routes guarded actions through the
 *  approval queue OR the quorum collector based on the decision's risk +
 *  danger tags. Each path emits matching guard / approval-ceremony
 *  events into the proof log. */
function enforcerFromGuard(
  guard: AgentGuard,
  queue: ApprovalQueue,
  quorum: QuorumApprovalCollector | undefined,
  opts: {
    onGuardEvent?: (ev: GuardEventStub) => void;
    onCeremony?: (ev: { kind: string; request_id: string; action: string; actor: string }) => void;
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
      opts.onGuardEvent?.({
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
          const wantQuorum = shouldRequireQuorum(decision, action);
          try {
            if (wantQuorum && quorum) {
              opts.onCeremony?.({ kind: "quorum", request_id: requestId, action, actor: caller });
              const handle = quorum.push({
                request_version: "1",
                id: requestId,
                actor: caller,
                action,
                danger_tags: decision.danger_tags as ApprovalRequest["danger_tags"],
                reason:
                  decision.kind === "escalate"
                    ? `escalated: ${"reason" in decision ? decision.reason : "dangerous"}`
                    : `quorum required for ${action}`,
                created_at: new Date().toISOString(),
              });
              // Expose the collector handle on the queue so external admin
              // approvers can vote in via `respondAs`. This is the
              // integration point the daemon's admin endpoint uses; the
              // enforcer just waits for the outcome.
              (queue as unknown as { _quorum?: Map<string, typeof handle> })._quorum =
                ((queue as unknown as { _quorum?: Map<string, typeof handle> })._quorum
                  ?? new Map<string, typeof handle>());
              (queue as unknown as { _quorum: Map<string, typeof handle> })._quorum.set(requestId, handle);
              const outcome = await handle.outcome;
              (queue as unknown as { _quorum: Map<string, typeof handle> })._quorum.delete(requestId);
              if (outcome.decision === "approve") return "allow";
              return { deny: "quorum denied (insufficient approvers)" };
            }
            opts.onCeremony?.({ kind: "click", request_id: requestId, action, actor: caller });
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

/** Constant-time string comparison via node:crypto.timingSafeEqual, with
 *  early-return only on length mismatch (which is itself a binary fact
 *  about the supplied token, not a per-byte oracle). */
function constantTimeStringEqual(a: string, b: string): boolean {
  const ab = Buffer.from(a, "utf8");
  const bb = Buffer.from(b, "utf8");
  if (ab.length !== bb.length) return false;
  return nodeTimingSafeEqual(ab, bb);
}

/** Resolve `admin.bind` to a loopback decision. The admin endpoint
 *  defaults to 127.0.0.1; explicit non-loopback binds require operator
 *  intent. */
function isLoopback(host: string): boolean {
  return host === "127.0.0.1" || host === "::1" || host === "localhost";
}

/** Atomically write `bytes` to `path` via temp + rename. */
function atomicWrite(path: string, bytes: string | Uint8Array): void {
  const dir = dirname(resolvePath(path));
  const tmp = `${path}.tmp.${Date.now().toString(36)}.${Math.floor(Math.random() * 1_000_000).toString(36)}`;
  writeFileSync(tmp, bytes);
  renameSync(tmp, path);
  void dir;
}

export async function runDaemon(opts: DaemonRuntimeOptions): Promise<DaemonHandle> {
  const config = parseYAML(readFileSync(opts.configPath, "utf8")) as DaemonConfig;
  const contract = parseYAML(readFileSync(config.contract_path, "utf8")) as Record<string, unknown>;
  const proofLogPath = config.proof_log_path;
  if (!existsSync(proofLogPath)) {
    writeFileSync(proofLogPath, new Uint8Array([0x54, 0x46, 0x4c, 0x4f, 0x47, 0x01, 0x00, 0x00]));
  }

  // Initialize OpenTelemetry tracing if OTEL_EXPORTER_OTLP_ENDPOINT is
  // set (or the caller passed an endpoint). When neither is configured,
  // tracing is silently off and `recordDecideSpan` is a no-op. The
  // handle is held so the daemon can flush/shutdown OTel cleanly on
  // stop().
  const otelHandle: OtelHandle = await setupOtel(
    `tf-daemon:${config.self_actor}`,
    opts.otelEndpoint,
  );

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

  // Proof chain: every event the daemon writes is a schema-conforming
  // ProofEvent, signed by the daemon identity, with parent_hash linking
  // back to the previously-appended event. Replaces the unsigned ad-hoc
  // shape the daemon used in 0.0.0.
  const proofChain = new ProofChain();
  const enqueueSigned = async (input: { type: string; actor: string; level?: ProofChainLevel; context?: Record<string, unknown> }): Promise<BuiltProofEvent> => {
    const built = proofChain.bind(buildProofEvent(input));
    const signed = await signProofEvent(built, config.self_actor, idEntry.key_bytes);
    proofChain.commit(signed);
    appendEventBytes(proofLogPath, new TextEncoder().encode(canonicalize(signed)));
    return signed;
  };

  const enforcementLevel = ((config as unknown as { enforcement_level?: string }).enforcement_level ?? "E4") as
    | "E0" | "E1" | "E2" | "E3" | "E4" | "E5";
  const guard = AgentGuard.fromContract(contract, {
    onEvent: (ev) => {
      void enqueueSigned({
        type: ev.type,
        actor: ev.actor,
        level: "L2",
        context: {
          action: ev.action,
          target: ev.target,
          decision: ev.decision,
          danger_tags: ev.danger_tags,
        },
      });
    },
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
  const queue = new ApprovalQueue({
    maxPending: config.approval_queue?.max_pending ?? 32,
    defaultTimeoutMs: (config.approval_queue?.default_timeout_seconds ?? 300) * 1000,
    onPush: (req) => {
      void enqueueSigned({
        type: "approval.request",
        actor: req.actor,
        level: "L2",
        context: { action: req.action, request_id: req.id, danger_tags: req.danger_tags ?? [] },
      });
      opts.onApprovalRequest?.(req);
    },
    onResolve: (req, decision, note) => {
      void enqueueSigned({
        type: `approval.${decision}`,
        actor: req.actor,
        level: "L2",
        context: { action: req.action, request_id: req.id, decision, note: note ?? "" },
      });
    },
  });

  // Quorum collector — wired when the daemon config carries a
  // `quorum_default` block. Tests + tf-cli admin votes resolve outcomes
  // via the admin HTTP endpoint.
  const quorumCfg = (config as unknown as { quorum_default?: { min_approvers: number; of: string[] } })
    .quorum_default;
  const quorum: QuorumApprovalCollector | undefined = quorumCfg
    ? new QuorumApprovalCollector(queue, quorumCfg)
    : undefined;

  // Plugin registry must be constructed before the profile gate so the
  // bridge inventory can introspect what's actually loaded.
  const pluginHostEarly: PluginHost = opts.pluginHost ?? {
    log: (msg: unknown) => {
      void enqueueSigned({
        type: "plugin.log",
        actor: config.self_actor,
        context: { message: String(msg) },
      });
    },
  };
  const pluginUnsafeFlag = (config as unknown as { unsafe_allow_native_plugins?: boolean })
    .unsafe_allow_native_plugins ?? false;
  const pluginRegistry = new PluginRegistry({
    sandboxNative: !pluginUnsafeFlag,
    unsafeAllowInProcessNative: pluginUnsafeFlag,
    capabilityCheck: ({ caller, capability }) => {
      // The plugin capability gate is a SECOND-ORDER check that fires
      // ONLY for hard denies (revocation, negative_capabilities,
      // forbidden, deny_actors). Approval-required / escalate paths are
      // already handled by the RpcServer's primary enforcer; if we
      // re-blocked here, every plugin call would bypass the approval
      // flow and fail closed. Returning true on any non-deny verdict
      // hands authority back to the primary enforcer.
      const decision = guard.checkRaw({ actor: caller, action: capability });
      return decision.kind !== "deny";
    },
  });
  for (const manifestPath of opts.plugins ?? []) {
    await pluginRegistry.load(manifestPath, pluginHostEarly);
  }

  // Profile verdict capture wrapper installed BEFORE gating so the
  // admin /admin/profile endpoint can serve the verdict produced at
  // boot.
  let lastProfileVerdict: import("tf-types").ProfileVerdict | undefined;
  const profilePassThrough = opts.onProfileVerdict;
  opts.onProfileVerdict = (v) => {
    lastProfileVerdict = v;
    profilePassThrough?.(v);
  };

  // Profile gating: when the daemon config claims a conformance
  // profile, evaluate it against an inventory built from what the
  // daemon ACTUALLY loaded — not a hardcoded literal.
  const claimedProfile = (config as unknown as { profile?: string }).profile;
  if (claimedProfile) {
    const tfMod = await import("tf-types");
    const spec = tfMod.BUILTIN_PROFILES[claimedProfile];
    if (!spec) {
      throw new Error(`unknown profile: ${claimedProfile}`);
    }
    const features: string[] = ["agent-contract", "proof-log", "ed25519", "vault", "signed-log-events"];
    if (tf?.policy) features.push("policy-engine");
    if (enforcementLevel === "E0") features.push("shadow-mode");
    if (quorum) features.push("quorum-collector");
    // Continuous reauth wired downstream via opts.onContinuousReauth +
    // explicit reevaluate calls below; advertise it only when the
    // RpcServer is constructed with the matching triggers (always
    // populated by this build).
    features.push("continuous-reauth");
    // Transparency anchor: derived from the proof-profile manifest's
    // `anchors` field if the operator declared one.
    const anchorKinds: string[] = [];
    if (tf?.proofProfile && typeof tf.proofProfile === "object") {
      const anchors = (tf.proofProfile as Record<string, unknown>)["anchors"];
      if (Array.isArray(anchors)) {
        for (const a of anchors as Array<Record<string, unknown>>) {
          if (typeof a.kind === "string") anchorKinds.push(a.kind);
        }
      }
    }
    if (anchorKinds.length > 0) features.push("transparency-anchor.any");
    const bridgeKinds: string[] = [];
    // Bridges loaded by plugins surface via the registry's manifest list.
    for (const p of pluginRegistry.list()) {
      const k = p.manifest.kind;
      if (typeof k === "string") bridgeKinds.push(k);
    }
    // Profile floors: read proof_level_floor from the proof-profile
    // manifest if present; otherwise default by profile spec.
    const proofLevelFloor = (
      tf?.proofProfile && typeof tf.proofProfile === "object"
        ? ((tf.proofProfile as Record<string, unknown>)["min_proof_level"] as ProofChainLevel | undefined)
        : undefined
    ) ?? spec.min_proof_level ?? "L1";
    const verdict = tfMod.selectProfile(spec, tfMod.buildProfileFeatureGate({
      features,
      enforcementLevel,
      proofLevelFloor,
      bridges: bridgeKinds,
      anchors: anchorKinds,
    }));
    opts.onProfileVerdict?.(verdict);
    if (!verdict.ok && opts.refuseOnProfileFailure !== false) {
      throw new Error(
        `profile ${claimedProfile} not satisfied: ${verdict.failures.join("; ")}`,
      );
    }
  }

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
  // Track every live RpcServer so admin events (revocation, plugin
  // change) can fan out continuous-reauth triggers.
  const activeRpcServers = new Set<RpcServer>();

  // pluginRegistry constructed earlier so the profile gate can introspect it.
  const pluginHost = pluginHostEarly;

  const adminCfg = (config as unknown as {
    admin?: {
      enabled: boolean;
      token_env?: string;
      revocation_path?: string;
      bind?: string;
      max_body_bytes?: number;
    };
  }).admin;
  const adminEnabled = !!adminCfg?.enabled;
  const adminTokenEnv = adminCfg?.token_env ?? "TF_ADMIN_TOKEN";
  const adminBind = adminCfg?.bind ?? "127.0.0.1";
  const adminMaxBody = adminCfg?.max_body_bytes ?? 64 * 1024;
  const revocationPath = adminCfg?.revocation_path;

  /** Read the admin token at request time so a token rotation in the
   *  parent process takes effect on the next request. (Was captured at
   *  boot time in 0.0.0; per BUG-015 a rotated token wouldn't help.) */
  function currentAdminToken(): string {
    return process.env[adminTokenEnv] ?? "";
  }

  function adminAuth(req: Request): boolean {
    if (!adminEnabled) return false;
    const token = currentAdminToken();
    if (!token) return false;
    const auth = req.headers.get("authorization") ?? "";
    const expected = `Bearer ${token}`;
    return constantTimeStringEqual(auth, expected);
  }

  /** Admin endpoints reject requests whose Host header isn't the
   *  configured bind. Combined with the loopback default, this defeats
   *  basic DNS rebinding even when the operator forgets to firewall. */
  function adminHostAllowed(req: Request): boolean {
    const host = (req.headers.get("host") ?? "").split(":")[0]?.trim() ?? "";
    if (!host) return false;
    if (isLoopback(adminBind)) return isLoopback(host);
    return host === adminBind;
  }

  async function readBoundedJsonBody(req: Request): Promise<{ ok: true; value: unknown } | { ok: false; status: number; error: string }> {
    const lenHdr = req.headers.get("content-length");
    if (lenHdr && parseInt(lenHdr, 10) > adminMaxBody) {
      return { ok: false, status: 413, error: "body too large" };
    }
    let text = "";
    try {
      text = await req.text();
    } catch (err) {
      return { ok: false, status: 400, error: `read body: ${(err as Error).message}` };
    }
    if (text.length > adminMaxBody) return { ok: false, status: 413, error: "body too large" };
    if (!text) return { ok: true, value: {} };
    try {
      return { ok: true, value: JSON.parse(text) as unknown };
    } catch (err) {
      return { ok: false, status: 400, error: `malformed JSON: ${(err as Error).message}` };
    }
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
    if (!adminHostAllowed(req)) {
      return new Response("forbidden (host)", { status: 403 });
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
        const body = await readBoundedJsonBody(req);
        if (!body.ok) return jsonResponse({ error: body.error }, body.status);
        const note = (body.value as { note?: string }).note;
        // Quorum-collected requests resolve through `respondAs` instead of
        // the queue's single-resolution path.
        const quorumMap = (queue as unknown as { _quorum?: Map<string, { respondAs: (a: string, d: "approve" | "deny", s: { algorithm: string; signature: string }) => boolean }> })._quorum;
        if (quorumMap?.has(id)) {
          const handle = quorumMap.get(id)!;
          // The admin caller votes as the daemon's `self_actor`. In a
          // multi-approver build the dashboard would let each operator
          // sign individually; for v0.1.0 the daemon-side identity
          // suffices to drive single-approver tests.
          const ok = handle.respondAs(config.self_actor, decision, { algorithm: "ed25519", signature: "" });
          return jsonResponse({ ok, kind: "quorum", note: note ?? null }, ok ? 200 : 404);
        }
        const ok = queue.respond(id, decision, note);
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
      const body = await readBoundedJsonBody(req);
      if (!body.ok) return jsonResponse({ error: body.error }, body.status);
      const v = body.value as { kind?: string; id?: string; reason?: string };
      const VALID_KINDS = new Set(["actor", "capability", "delegation", "instance"]);
      if (!v.kind || !v.id || !VALID_KINDS.has(v.kind)) {
        return jsonResponse({ error: "missing/invalid kind or id (kind must be actor|capability|delegation|instance)" }, 400);
      }
      // Idempotency: same target → return existing entry without appending.
      const list: Array<Record<string, unknown>> = existsSync(revocationPath)
        ? (JSON.parse(readFileSync(revocationPath, "utf8")) as Array<Record<string, unknown>>)
        : [];
      const dup = list.find(
        (r) => r.target_kind === v.kind && r.target_id === v.id,
      );
      if (dup) {
        return jsonResponse({ ok: true, revocation: dup, deduped: true });
      }
      // Sign the canonical revocation bytes with the daemon identity.
      const tf = await import("tf-types");
      const baseRev = {
        revocation_version: "1",
        id: `rev-${Date.now().toString(16)}-${Math.floor(Math.random() * 1_000_000).toString(16)}`,
        target_id: v.id,
        target_kind: v.kind,
        effective_at: new Date().toISOString(),
        reason: v.reason ?? "admin-revoke",
        issuer: config.self_actor,
      };
      const digest = tf.sha256(new TextEncoder().encode(canonicalize(baseRev)));
      const sigBytes = await tf.ed25519Sign(digest, idEntry.key_bytes);
      const rev = {
        ...baseRev,
        signature: {
          algorithm: "ed25519",
          signer: config.self_actor,
          signature: Buffer.from(sigBytes).toString("base64"),
        },
      };
      list.push(rev);
      atomicWrite(revocationPath, canonicalize(list));
      // Continuous-reauth: a revocation invalidates any in-flight
      // server-streaming RPC the revoked actor is currently consuming.
      for (const r of activeRpcServers) {
        try {
          await r.reevaluate("revocation");
        } catch {
          /* best effort */
        }
      }
      await enqueueSigned({
        type: "admin.revocation",
        actor: config.self_actor,
        level: "L2",
        context: { target_kind: v.kind, target_id: v.id, reason: rev.reason },
      });
      return jsonResponse({ ok: true, revocation: rev });
    }
    return new Response("not found", { status: 404 });
  }

  /** Common session attachment and RPC setup logic used by both WS and TCP. */
  async function onSessionConnected(
    wire: { sink: any; source: any },
    sessionId: string,
    onEstablished?: (endpoint: SessionEndpoint) => void,
  ) {
    try {
      const endpoint = await attachResponder(
        {
          selfActor: config.self_actor,
          identityPriv: idEntry.key_bytes,
          identityPub,
        },
        wire.sink,
        wire.source,
      );

      const rpc = new RpcServer(rpcTransportFromEndpoint(endpoint), {
        selfActor: config.self_actor,
        enforcer: enforcerFromGuard(guard, queue, quorum, {
          onCeremony: (ev) => {
            void enqueueSigned({
              type: `approval.ceremony.${ev.kind}`,
              actor: ev.actor,
              level: "L2",
              context: { request_id: ev.request_id, action: ev.action, kind: ev.kind },
            });
          },
        }),
        getCaller: () => endpoint.peerActor(),
        getCallerClaim: () => endpoint.peerActorClaim(),
        onProofEvent: (ev: RpcProofEventStub) =>
          void enqueueSigned({
            type: ev.type,
            actor: ev.caller ?? config.self_actor,
            level: "L1",
            context: ev as unknown as Record<string, unknown>,
          }),
        continuousReevaluation: {
          triggers: ["revocation", "session_rekey", "delegation_change", "explicit_reauth"],
          intervalMs: 30_000,
        },
      });

      activeRpcServers.add(rpc);
      const entry = {
        id: sessionId,
        remote_actor: endpoint.peerActor(),
        remote_actor_claim: endpoint.peerActorClaim(),
        opened_at: new Date().toISOString(),
        close: () => {
          activeRpcServers.delete(rpc);
          endpoint.close("daemon shutdown");
        },
      };
      activeSessions.set(sessionId, entry);
      listeners.push({ close: entry.close });

      // Default built-in: a tiny "ping" unary so a client can verify the
      // pipeline without needing any registered plugin.
      rpc.registerUnary("tf.ping", "tf.ping", async () => ({
        pong: true,
        at: new Date().toISOString(),
      }));

      rpc.registerHttpBridge("http.proxy", "http.proxy", httpBridgeHandler);

      // Bind every loaded plugin's declared-capability handlers.
      pluginRegistry.registerOn(rpc);

      onEstablished?.(endpoint);
    } catch (err) {
      // Handshake failed; clean up the placeholder.
      activeSessions.delete(sessionId);
      wire.sink.close();
    }
  }

  // -------------------------------------------------------------------------
  // v1 HTTP endpoint suite (B1 + B2 + B3).
  // -------------------------------------------------------------------------
  const bridgesRegistry = (() => {
    const p = opts.bridgesRegistryPath
      ?? (opts.projectRoot ? joinPath(opts.projectRoot, ".tf", "bridges.yaml") : undefined);
    if (!p) return new BridgesRegistry({ registry_version: "1", bridges: [] });
    try {
      return BridgesRegistry.load(p);
    } catch (err) {
      // A malformed registry is a HARD failure — refusing to start is the
      // safe default (DECISIONS.md "fail-closed by default"). Tests that
      // want to test the malformed-registry path can catch this error.
      throw new Error(`bridges-registry load failed: ${(err as Error).message}`);
    }
  })();

  const trustDomainGuess = (() => {
    // self_actor format: tf:actor:<type>:<trust_domain>/<path>
    const m = /^tf:actor:[^:]+:([^/]+)\//.exec(config.self_actor);
    return m?.[1] ?? "local";
  })();

  function v1AdminAuth(req: Request): boolean {
    const token = currentAdminToken();
    if (!token) return false;
    const auth = req.headers.get("authorization") ?? "";
    const expected = `Bearer ${token}`;
    return constantTimeStringEqual(auth, expected);
  }

  /** Read + parse a JSON body for v1 endpoints with the same caps the
   *  admin endpoint uses. Returns a small tagged result the route can
   *  branch on. */
  async function readV1JsonBody(req: Request): Promise<{ ok: true; value: unknown } | { ok: false; status: number; error: string }> {
    const lenHdr = req.headers.get("content-length");
    if (lenHdr && parseInt(lenHdr, 10) > adminMaxBody) {
      return { ok: false, status: 413, error: "body too large" };
    }
    let text = "";
    try {
      text = await req.text();
    } catch (err) {
      return { ok: false, status: 400, error: `read body: ${(err as Error).message}` };
    }
    if (text.length > adminMaxBody) return { ok: false, status: 413, error: "body too large" };
    if (!text) return { ok: false, status: 400, error: "empty body" };
    try {
      return { ok: true, value: JSON.parse(text) as unknown };
    } catch (err) {
      return { ok: false, status: 400, error: `malformed JSON: ${(err as Error).message}` };
    }
  }

  const ACTION_NAME_RE = /^[a-z][a-z0-9_]*(\.[a-z][a-z0-9_]*)+$/;
  const VALID_HOST_TOKEN_KINDS = new Set([
    "oauth-jwt",
    "clerk-session",
    "next-auth-jwt",
    "better-auth-session",
    "webauthn-assertion",
    "mtls-cert-pem",
    "spiffe-svid",
    "session-cookie",
  ]);
  const VALID_DECISIONS = new Set(["allow", "deny", "escalate", "approval-required", "log-only"]);

  interface DecideRequest {
    actor: string | null;
    host_token: string | null;
    host_token_kind: string | null;
    action: string;
    target: string | null;
    context: Record<string, unknown>;
    trace_id: string;
  }

  function validateDecideRequest(value: unknown): { ok: true; value: DecideRequest } | { ok: false; error: string } {
    if (!value || typeof value !== "object" || Array.isArray(value)) {
      return { ok: false, error: "request must be a JSON object" };
    }
    const v = value as Record<string, unknown>;
    const action = v.action;
    if (typeof action !== "string" || !ACTION_NAME_RE.test(action)) {
      return { ok: false, error: "action must match dotted-action-name pattern" };
    }
    const actor = v.actor === undefined ? null : v.actor;
    if (actor !== null && typeof actor !== "string") {
      return { ok: false, error: "actor must be a string or null" };
    }
    const hostToken = v.host_token === undefined ? null : v.host_token;
    if (hostToken !== null && typeof hostToken !== "string") {
      return { ok: false, error: "host_token must be a string or null" };
    }
    const hostKind = v.host_token_kind === undefined ? null : v.host_token_kind;
    if (hostKind !== null && (typeof hostKind !== "string" || !VALID_HOST_TOKEN_KINDS.has(hostKind))) {
      return { ok: false, error: "host_token_kind invalid" };
    }
    const target = v.target === undefined ? null : v.target;
    if (target !== null && typeof target !== "string") {
      return { ok: false, error: "target must be a string or null" };
    }
    const context = v.context === undefined ? {} : v.context;
    if (!context || typeof context !== "object" || Array.isArray(context)) {
      return { ok: false, error: "context must be an object" };
    }
    const traceId = v.trace_id === undefined ? "" : v.trace_id;
    if (typeof traceId !== "string") {
      return { ok: false, error: "trace_id must be a string" };
    }
    if (actor === null && hostToken === null) {
      return { ok: false, error: "request must supply actor OR host_token" };
    }
    return {
      ok: true,
      value: {
        actor: actor as string | null,
        host_token: hostToken as string | null,
        host_token_kind: hostKind as string | null,
        action,
        target: target as string | null,
        context: context as Record<string, unknown>,
        trace_id: traceId,
      },
    };
  }

  function decisionTrustLevel(actor: string, resolved?: ResolvedCredential): "T0" | "T1" | "T2" | "T3" | "T4" | "T5" | "T6" | "T7" {
    if (resolved) return resolved.trust_level as "T0" | "T1" | "T2" | "T3" | "T4" | "T5" | "T6" | "T7";
    void actor;
    return "T2";
  }

  async function handleDecideOne(req: DecideRequest): Promise<Record<string, unknown>> {
    let resolved: ResolvedCredential | undefined;
    let actor = req.actor ?? "tf:actor:process:local/anonymous";
    if (req.host_token) {
      const hint = hostTokenKindToBridge(req.host_token_kind);
      try {
        resolved = resolveCredential(req.host_token, {
          hint,
          registry: bridgesRegistry,
          trustDomain: trustDomainGuess,
        });
        actor = resolved.actor;
      } catch (err) {
        // Soft failure: we still emit a decision so the caller has a
        // proof_id, but it MUST be a deny.
        resolved = {
          actor: "tf:actor:process:local/unresolved",
          capabilities: [],
          trust_level: "T0",
          bridge_kind: "unknown",
          expires_at: null,
          detection_reason: `host_token rejected: ${(err as Error).message}`,
        };
        actor = resolved.actor;
      }
    }
    const tf2 = await import("tf-types");
    const decision = guard.checkRaw({
      actor,
      action: req.action,
      target: req.target ?? undefined,
      context: req.context,
    });
    const adjusted = tf2.applyEnforcementLevel(decision, enforcementLevel);

    const proofEvent = await enqueueSigned({
      type: "decide.evaluated",
      actor,
      level: "L2",
      context: {
        decision_request: {
          actor: req.actor,
          action: req.action,
          target: req.target,
          host_token_kind: req.host_token_kind,
          trace_id: req.trace_id,
          bridge_kind: resolved?.bridge_kind ?? null,
        },
        decision_result: {
          decision: adjusted.kind,
          reason: "reason" in adjusted ? adjusted.reason : "matched declared action",
          danger_tags: adjusted.danger_tags,
        },
      },
    });

    // Emit one OTel span per /v1/decide call. recordDecideSpan is
    // fire-and-forget: it never throws and never blocks the response.
    recordDecideSpan({
      "tf.action": req.action,
      "tf.target": req.target ?? "",
      "tf.decision": adjusted.kind,
      "tf.actor_resolved": actor,
    });

    return {
      decision: adjusted.kind,
      reason: "reason" in adjusted ? adjusted.reason : `action ${req.action} permitted`,
      approval_id: null,
      proof_id: (await import("tf-types")).eventHashRef(proofEvent),
      actor_resolved: actor,
      trust_level: decisionTrustLevel(actor, resolved),
      authority_mode: "layered",
      danger_tags: adjusted.danger_tags,
    };
  }

  interface V1AuthContext {
    localDecisionTrust: boolean;
  }

  function v1DecisionAuth(req: Request, ctx: V1AuthContext): boolean {
    return ctx.localDecisionTrust || v1AdminAuth(req);
  }

  async function handleV1Decide(req: Request, ctx: V1AuthContext): Promise<Response> {
    if (!v1DecisionAuth(req, ctx)) return jsonResponse({ error: "unauthorized" }, 401);
    const body = await readV1JsonBody(req);
    if (!body.ok) return jsonResponse({ error: body.error }, body.status);
    const validated = validateDecideRequest(body.value);
    if (!validated.ok) return jsonResponse({ error: validated.error }, 400);
    const result = await handleDecideOne(validated.value);
    return jsonResponse(result);
  }

  async function handleV1DecideBatch(req: Request, ctx: V1AuthContext): Promise<Response> {
    if (!v1DecisionAuth(req, ctx)) return jsonResponse({ error: "unauthorized" }, 401);
    const body = await readV1JsonBody(req);
    if (!body.ok) return jsonResponse({ error: body.error }, body.status);
    if (!Array.isArray(body.value)) {
      return jsonResponse({ error: "batch body must be an array" }, 400);
    }
    if (body.value.length > 100) {
      return jsonResponse({ error: "batch exceeds 100 items" }, 400);
    }
    const out: unknown[] = [];
    for (const item of body.value) {
      const validated = validateDecideRequest(item);
      if (!validated.ok) {
        return jsonResponse({ error: validated.error }, 400);
      }
      out.push(await handleDecideOne(validated.value));
    }
    return jsonResponse(out);
  }

  async function handleV1ImportCredential(req: Request): Promise<Response> {
    if (!v1AdminAuth(req)) return jsonResponse({ error: "unauthorized" }, 401);
    const body = await readV1JsonBody(req);
    if (!body.ok) return jsonResponse({ error: body.error }, body.status);
    const v = body.value as Record<string, unknown> | null;
    if (!v || typeof v !== "object") {
      return jsonResponse({ error: "body must be an object" }, 400);
    }
    if (typeof v.credential !== "string") {
      return jsonResponse({ error: "credential must be a string" }, 400);
    }
    const hint = hostTokenKindToBridge(typeof v.hint === "string" ? v.hint : null);
    let resolved: ResolvedCredential;
    try {
      resolved = resolveCredential(v.credential, {
        hint,
        registry: bridgesRegistry,
        trustDomain: trustDomainGuess,
      });
    } catch (err) {
      return jsonResponse({ error: `credential rejected: ${(err as Error).message}` }, 400);
    }
    return jsonResponse({
      actor: resolved.actor,
      capabilities: resolved.capabilities,
      trust_level: resolved.trust_level,
      bridge_kind: resolved.bridge_kind,
      expires_at: resolved.expires_at,
    });
  }

  async function handleV1ProofSign(req: Request): Promise<Response> {
    if (!v1AdminAuth(req)) return jsonResponse({ error: "unauthorized" }, 401);
    const body = await readV1JsonBody(req);
    if (!body.ok) return jsonResponse({ error: body.error }, body.status);
    const draft = body.value as Record<string, unknown> | null;
    if (!draft || typeof draft !== "object") {
      return jsonResponse({ error: "body must be an object" }, 400);
    }
    // Daemon enforces the schema's required fields before signing.
    if (draft.event_version !== "1") {
      return jsonResponse({ error: "event_version must be \"1\"" }, 400);
    }
    if (typeof draft.id !== "string" || draft.id.length === 0) {
      return jsonResponse({ error: "id must be a non-empty string" }, 400);
    }
    if (typeof draft.type !== "string" || !/^[a-z][a-z0-9._-]*$/.test(draft.type)) {
      return jsonResponse({ error: "type must match dotted event-type pattern" }, 400);
    }
    if (typeof draft.actor_id !== "string" || draft.actor_id.length === 0) {
      return jsonResponse({ error: "actor_id must be a non-empty string" }, 400);
    }
    if (typeof draft.timestamp !== "string" || draft.timestamp.length === 0) {
      return jsonResponse({ error: "timestamp must be a non-empty string" }, 400);
    }
    if (typeof draft.level !== "string" || !/^L[0-5]$/.test(draft.level)) {
      return jsonResponse({ error: "level must be L0..L5" }, 400);
    }
    const tf = await import("tf-types");
    // Strip any signature the caller supplied — the daemon signs with
    // its own identity, never with an attacker-supplied envelope.
    const unsigned = { ...draft } as Record<string, unknown>;
    delete unsigned.signature;
    const built = unsigned as unknown as import("tf-types").BuiltProofEvent;
    const signed = await tf.signProofEvent(built, config.self_actor, idEntry.key_bytes);
    const eventHash = tf.eventHashRef(signed);
    return jsonResponse({
      event_hash: eventHash,
      signature: signed.signature,
      signed_event: signed,
    });
  }

  async function handleV1ProofVerify(req: Request): Promise<Response> {
    if (!v1AdminAuth(req)) return jsonResponse({ error: "unauthorized" }, 401);
    const body = await readV1JsonBody(req);
    if (!body.ok) return jsonResponse({ error: body.error }, body.status);
    const ev = body.value as Record<string, unknown> | null;
    if (!ev || typeof ev !== "object") {
      return jsonResponse({ error: "body must be an object" }, 400);
    }
    const sig = ev.signature as Record<string, unknown> | undefined;
    if (!sig || typeof sig !== "object") {
      return jsonResponse({ error: "missing signature" }, 400);
    }
    const algorithm = sig.algorithm;
    const signer = sig.signer;
    const sigB64 = sig.signature;
    if (algorithm !== "ed25519" || typeof signer !== "string" || typeof sigB64 !== "string") {
      return jsonResponse({ error: "unsupported signature envelope" }, 400);
    }
    // Recompute the digest over the unsigned canonical form. Only the
    // daemon's own identity key is recognized in v0.1; cross-signer
    // verification rides through the bridges registry once federation
    // attestations land.
    const tf = await import("tf-types");
    const unsigned = { ...ev } as Record<string, unknown>;
    delete unsigned.signature;
    const digest = tf.sha256(new TextEncoder().encode(tf.canonicalize(unsigned)));
    const sigBytes = new Uint8Array(Buffer.from(sigB64, "base64"));
    let ok = false;
    if (signer === config.self_actor) {
      ok = await tf.ed25519Verify(identityPub, digest, sigBytes);
    }
    return jsonResponse({
      ok,
      signer_actor: signer,
      trust_level: ok ? "T2" : "T0",
    });
  }

  /** Top-level v1 router. Returns `undefined` when the request isn't a
   *  v1 path, letting the WebSocket / admin handler take over. */
  async function handleV1(req: Request, ctx: V1AuthContext): Promise<Response | undefined> {
    const url = new URL(req.url);
    if (!url.pathname.startsWith("/v1/")) return undefined;
    if (req.method !== "POST") return jsonResponse({ error: "method not allowed" }, 405);
    switch (url.pathname) {
      case "/v1/decide":
        return handleV1Decide(req, ctx);
      case "/v1/decide-batch":
        return handleV1DecideBatch(req, ctx);
      case "/v1/import-credential":
        return handleV1ImportCredential(req);
      case "/v1/proof/sign":
        return handleV1ProofSign(req);
      case "/v1/proof/verify":
        return handleV1ProofVerify(req);
      default:
        return jsonResponse({ error: "not found" }, 404);
    }
  }

  // -------------------------------------------------------------------------
  // The HTTP listener that serves v1 routes is bound separately from the
  // admin/WebSocket listener so the operator can firewall it without
  // disabling the dashboard. TCP remains bearer-token protected. The
  // Unix socket is for local decision callers and relies on filesystem /
  // service-manager controls instead of bearer tokens for /v1/decide.
  // -------------------------------------------------------------------------
  const httpListeners: Array<{ stop: () => void; port: number | null; socket: string | null }> = [];
  const httpPortRequested = opts.daemonHttpPort ?? 8642;
  const httpHost = opts.daemonHttpHost ?? "127.0.0.1";
  const httpSocketRequested = opts.daemonHttpSocket
    ?? joinPath("/run", "trustforge", "decide.sock");

  if (httpPortRequested >= 0) {
    const tcpServer = Bun.serve({
      port: httpPortRequested,
      hostname: httpHost,
      async fetch(req) {
        return (await handleV1(req, { localDecisionTrust: false })) ?? new Response("not found", { status: 404 });
      },
    });
    httpListeners.push({
      stop: () => tcpServer.stop(true),
      port: tcpServer.port ?? null,
      socket: null,
    });
  }

  if (httpSocketRequested && httpSocketRequested.length > 0) {
    try {
      // Best-effort: ensure the directory exists. Then bind. If the
      // socket file already exists from a stale daemon, unlink it so
      // bind doesn't EADDRINUSE.
      const dir = dirname(httpSocketRequested);
      try {
        (await import("node:fs")).mkdirSync(dir, { recursive: true });
      } catch {
        /* tolerate */
      }
      try {
        if (existsSync(httpSocketRequested)) {
          (await import("node:fs")).unlinkSync(httpSocketRequested);
        }
      } catch {
        /* tolerate */
      }
      const unixServer = Bun.serve({
        unix: httpSocketRequested,
        async fetch(req: Request) {
          return (await handleV1(req, { localDecisionTrust: true })) ?? new Response("not found", { status: 404 });
        },
      } as unknown as Parameters<typeof Bun.serve>[0]);
      httpListeners.push({
        stop: () => unixServer.stop(true),
        port: null,
        socket: httpSocketRequested,
      });
    } catch (err) {
      // Unix-socket binding is non-fatal: the operator may not have
      // permission to write the socket directory in containerized
      // builds. The TCP listener is still up.
      void err;
    }
  }

  const httpListenerInfo = httpListeners.find((l) => l.port !== null);
  const httpSocketInfo = httpListeners.find((l) => l.socket !== null);

  const listen = config.listen ?? { kind: "websocket", bind: "127.0.0.1", port: 0 };
  let server: { port: number; stop: (closeActive?: boolean) => Promise<void> | void };

  if (listen.kind === "websocket") {
    const bunServer = Bun.serve({
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
          // Pre-register the session id at OPEN time (not after attachResponder
          // resolves) so a `close` arriving before the handshake completes
          // still cleans up the slot. (BUG-014)
          sessionCounter += 1;
          const sessionId = `sess-ws-${Date.now().toString(16)}-${sessionCounter.toString(16)}`;
          activeSessions.set(sessionId, {
            id: sessionId,
            remote_actor: "tf:actor:process:key/pending",
            opened_at: new Date().toISOString(),
            close: () => ws.close(),
          });
          (ws.data as any).sessionId = sessionId;

          void onSessionConnected(wire, sessionId, (endpoint) => {
            (ws.data as any).endpoint = endpoint;
          });
        },
        message(ws, message) {
          const w = (ws.data as any).wire as any;
          if (w) w.deliverMessage(message);
        },
        close(ws) {
          const w = (ws.data as any).wire as any;
          if (w) w.deliverClose();
          const sessionId = (ws.data as any).sessionId as string | undefined;
          if (sessionId) activeSessions.delete(sessionId);
        },
      },
    });
    server = {
      port: bunServer.port ?? 0,
      stop: (closeActive) => {
        bunServer.stop(closeActive);
      },
    };
  } else {
    // TCP or TLS
    const bunTcp = Bun.listen({
      port: Number((listen as any).port ?? 0),
      hostname: String((listen as any).bind ?? "127.0.0.1"),
      socket: {
        open(socket) {
          const wire = wireFromBunTcpSocket(socket);
          (socket.data as any).wire = wire;
          sessionCounter += 1;
          const sessionId = `sess-tcp-${Date.now().toString(16)}-${sessionCounter.toString(16)}`;
          activeSessions.set(sessionId, {
            id: sessionId,
            remote_actor: "tf:actor:process:key/pending",
            opened_at: new Date().toISOString(),
            close: () => socket.end(),
          });
          (socket.data as any).sessionId = sessionId;

          void onSessionConnected(wire, sessionId, (endpoint) => {
            (socket.data as any).endpoint = endpoint;
          });
        },
        data(socket, chunk) {
          const w = (socket.data as any).wire as any;
          if (w) w.deliverMessage(chunk);
        },
        close(socket) {
          const w = (socket.data as any).wire as any;
          if (w) w.deliverClose();
          const sessionId = (socket.data as any).sessionId as string | undefined;
          if (sessionId) activeSessions.delete(sessionId);
        },
      },
      tls: listen.kind === "tls" ? {
        // For v0.1.0 we expect the vault to hold the daemon's TLS cert.
        // If missing, Bun.listen will throw.
        cert: Buffer.from(vault.read("daemon-tls-cert")?.key_bytes ?? new Uint8Array()).toString("utf8"),
        key: Buffer.from(vault.read("daemon-tls-key")?.key_bytes ?? new Uint8Array()).toString("utf8"),
      } : undefined,
    });
    server = {
      port: bunTcp.port,
      stop: () => bunTcp.stop(),
    };
  }

  return {
    port: server.port ?? 0,
    proofLogPath,
    approvalQueue: queue,
    httpPort: httpListenerInfo?.port ?? null,
    httpSocketPath: httpSocketInfo?.socket ?? null,
    stop: async () => {
      queue.drainDeny("daemon shutdown");
      for (const l of listeners) l.close();
      for (const h of httpListeners) h.stop();
      // Best-effort: clean up the Unix socket file so a re-bind won't
      // fail with EADDRINUSE.
      if (httpSocketInfo?.socket) {
        try {
          (await import("node:fs")).unlinkSync(httpSocketInfo.socket);
        } catch {
          /* tolerate */
        }
      }
      await server.stop(true);
      // Flush + tear down any OTel SDK we brought up. Best effort.
      try {
        await otelHandle.flush();
        await otelHandle.shutdown();
      } catch {
        /* tolerate otel teardown errors */
      }
    },
  };
}

/**
 * Frame `payload` and append it to the .tflog: 4-byte big-endian length
 * prefix followed by the canonical-JSON bytes of the event. Matches the
 * Phase 2 .tflog framing.
 */
function appendEventBytes(path: string, payload: Uint8Array): void {
  const header = new Uint8Array(4);
  new DataView(header.buffer).setUint32(0, payload.length, false);
  try {
    appendFileSync(path, Buffer.concat([header, payload]));
  } catch (err) {
    // Tolerate fire-and-forget appends that race shutdown / test cleanup.
    // Anything destructive (vault, evidence, revocation) takes a different
    // (synchronously awaited) path; this only matters for the proof log.
    if ((err as NodeJS.ErrnoException).code !== "ENOENT") throw err;
  }
}

/**
 * Legacy unsigned-event append. Retained for callers that haven't been
 * migrated to ProofChain-routed signed events; new code MUST go through
 * `enqueueSigned()` in `runDaemon`.
 */
function appendEventLine(path: string, ev: unknown): void {
  appendEventBytes(path, new TextEncoder().encode(canonicalize(ev)));
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

export { appendEventBytes, appendEventLine, appendSignedEventLine };

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

function wireFromBunTcpSocket(socket: import("bun").Socket<unknown>) {
  const messageListeners = new Set<(b: Uint8Array) => void>();
  const closeListeners = new Set<() => void>();
  return {
    sink: {
      send(bytes: Uint8Array) {
        // Use a 4-byte BE length prefix for TCP streaming, matching tf-session's
        // LengthDelimitedCodec.
        const header = new Uint8Array(4);
        new DataView(header.buffer).setUint32(0, bytes.length, false);
        socket.write(header);
        socket.write(bytes);
      },
      close() {
        socket.end();
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
    // The Bun socket 'data' handler gets the raw stream; we need to buffer
    // and frame-split it here to match LengthDelimitedCodec.
    _buffer: new Uint8Array(0),
    deliverMessage(chunk: Uint8Array) {
      const next = new Uint8Array(this._buffer.length + chunk.length);
      next.set(this._buffer);
      next.set(chunk, this._buffer.length);
      this._buffer = next;

      while (this._buffer.length >= 4) {
        const len = new DataView(this._buffer.buffer, this._buffer.byteOffset, 4).getUint32(0, false);
        if (this._buffer.length < 4 + len) break;
        const frame = this._buffer.subarray(4, 4 + len);
        this._buffer = this._buffer.subarray(4 + len);
        for (const l of messageListeners) l(frame);
      }
    },
    deliverClose() {
      for (const l of closeListeners) l();
    },
  };
}
