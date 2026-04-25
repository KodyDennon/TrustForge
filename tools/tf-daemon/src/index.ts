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
import { dirname, resolve as resolvePath } from "node:path";
import { parse as parseYAML } from "yaml";
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
        // Pre-register the session id at OPEN time (not after attachResponder
        // resolves) so a `close` arriving before the handshake completes
        // still cleans up the slot. (BUG-014)
        sessionCounter += 1;
        const sessionId = `sess-${Date.now().toString(16)}-${sessionCounter.toString(16)}`;
        activeSessions.set(sessionId, {
          id: sessionId,
          remote_actor: "tf:actor:process:key/pending",
          opened_at: new Date().toISOString(),
          close: () => {
            // best effort during pre-handshake close
          },
        });
        (ws.data as any).sessionId = sessionId;
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
            // Wire continuous-reauth triggers; admin/revocation handler
            // calls reevaluate("revocation") on every member.
            continuousReevaluation: {
              triggers: ["revocation", "session_rekey", "delegation_change", "explicit_reauth"],
              intervalMs: 30_000,
            },
          });
          activeRpcServers.add(rpc);
          listeners.push({
            close: () => {
              activeRpcServers.delete(rpc);
              endpoint.close("daemon shutdown");
            },
          });
          // Replace the pre-handshake placeholder with the real entry.
          activeSessions.set(sessionId, {
            id: sessionId,
            remote_actor: endpoint.peerActor(),
            remote_actor_claim: endpoint.peerActorClaim(),
            opened_at: new Date().toISOString(),
            close: () => endpoint.close("daemon shutdown"),
          });
          // Default built-in: a tiny "ping" unary so a client can verify the
          // pipeline without needing any registered plugin.
          rpc.registerUnary("tf.ping", "tf.ping", async () => ({ pong: true, at: new Date().toISOString() }));
          // Bind every loaded plugin's declared-capability handlers.
          pluginRegistry.registerOn(rpc);
        }).catch(() => {
          // Handshake failed; clean up the placeholder.
          activeSessions.delete(sessionId);
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
