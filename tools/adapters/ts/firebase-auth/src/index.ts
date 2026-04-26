/**
 * @trustforge/firebase-auth — verifies a Firebase ID token via firebase-admin
 * (loaded dynamically) and projects the verified `uid` into a TrustForge
 * decide call with `host_token_kind: "firebase-id-token"`.
 *
 * Usage (Express):
 *   import { trustforgeFirebase } from "@trustforge/firebase-auth";
 *   app.use(trustforgeFirebase({ daemonUrl: "...", projectId: "my-proj" }));
 *
 * Usage (programmatic):
 *   const result = await decideForFirebaseToken(idToken, opts);
 *
 * The `firebase-admin` package is a *peerDependency* — it is loaded via
 * `await import("firebase-admin")` at runtime so this package can be installed
 * even when `firebase-admin` isn't present (e.g. in tests). Tests can inject a
 * mock verifier via `verifyIdToken` in the options.
 */
import {
  TrustForge,
  type AdapterMode,
  type DecideResponse,
} from "@trustforge/sdk";

export interface FirebaseDecodedToken {
  uid: string;
  email?: string;
  email_verified?: boolean;
  [k: string]: unknown;
}

export type FirebaseVerifier = (
  idToken: string,
) => Promise<FirebaseDecodedToken>;

export interface TfFirebaseOptions {
  daemonUrl: string;
  adminToken?: string;
  /** Firebase project ID (forwarded to `firebase-admin` initializeApp). */
  projectId?: string;
  /** Override the verifier (used by tests). When unset, firebase-admin is loaded dynamically. */
  verifyIdToken?: FirebaseVerifier;
  /** Pre-built TrustForge SDK instance. */
  client?: TrustForge;
  mode?: AdapterMode;
  defaultAction?: string;
}

interface AdminAppLike {
  auth: () => { verifyIdToken: (token: string) => Promise<FirebaseDecodedToken> };
}

let cachedAdminApp: AdminAppLike | null = null;

async function defaultVerifier(
  idToken: string,
  projectId?: string,
): Promise<FirebaseDecodedToken> {
  if (!cachedAdminApp) {
    // Indirect import keeps `firebase-admin` an optional peer-dependency that
    // is only required at runtime, not at type-check time.
    const moduleName = "firebase-admin";
    const adminMod: unknown = await import(/* @vite-ignore */ moduleName);
    const admin = (adminMod as { default?: unknown }).default ?? adminMod;
    const a = admin as {
      apps: AdminAppLike[];
      initializeApp: (cfg: { projectId?: string }) => AdminAppLike;
    };
    cachedAdminApp = a.apps.length > 0 ? a.apps[0]! : a.initializeApp({ projectId });
  }
  return cachedAdminApp.auth().verifyIdToken(idToken);
}

function newTraceId(): string {
  if (typeof crypto !== "undefined" && "randomUUID" in crypto) {
    return crypto.randomUUID();
  }
  return `tf-${Date.now()}-${Math.random().toString(36).slice(2, 10)}`;
}

/**
 * Verify a Firebase ID token and ask the daemon for a decision.
 */
export async function decideForFirebaseToken(
  idToken: string,
  opts: TfFirebaseOptions,
  ctx: {
    action?: string;
    target?: string | null;
    context?: Record<string, unknown>;
  } = {},
): Promise<{ decision: DecideResponse; uid: string }> {
  const verifier =
    opts.verifyIdToken ?? ((tok: string) => defaultVerifier(tok, opts.projectId));
  const decoded = await verifier(idToken);
  if (!decoded?.uid) {
    throw new Error("firebase-auth: verifier returned no uid");
  }
  const tf =
    opts.client ??
    new TrustForge({ daemonUrl: opts.daemonUrl, adminToken: opts.adminToken });
  const decision = await tf.decide({
    actor: null,
    host_token: idToken,
    host_token_kind: "firebase-id-token",
    action: ctx.action ?? opts.defaultAction ?? "http.request",
    target: ctx.target ?? null,
    context: {
      uid: decoded.uid,
      ...(decoded.email ? { email: decoded.email } : {}),
      ...(ctx.context ?? {}),
    },
    trace_id: newTraceId(),
  });
  return { decision, uid: decoded.uid };
}

// ---------------------------------------------------------------------------
// Express-style middleware (works with any framework that uses (req,res,next)).
// ---------------------------------------------------------------------------

interface ExpressLikeReq {
  headers: Record<string, string | string[] | undefined>;
  url?: string;
  originalUrl?: string;
  method?: string;
  tfActor?: string;
  tfDecision?: DecideResponse;
  tfProofId?: string;
  tfFirebaseUid?: string;
}
interface ExpressLikeRes {
  status: (code: number) => ExpressLikeRes;
  json: (body: unknown) => ExpressLikeRes;
  setHeader: (name: string, value: string) => void;
}
type NextFn = (err?: unknown) => void;

/**
 * Express middleware. Reads `Authorization: Bearer <id-token>`, verifies it,
 * calls /v1/decide, then attaches the decision to `req.tfDecision`.
 */
export function trustforgeFirebase(opts: TfFirebaseOptions) {
  const mode = opts.mode ?? "enforce";
  return async function trustforgeFirebaseMw(
    req: ExpressLikeReq,
    res: ExpressLikeRes,
    next: NextFn,
  ): Promise<void> {
    const auth = (req.headers["authorization"] as string | undefined) ?? "";
    if (!auth.toLowerCase().startsWith("bearer ")) {
      if (mode === "observe-only") return next();
      res.status(401).json({ error: "missing-bearer-token" });
      return;
    }
    const token = auth.slice(7).trim();
    let outcome: { decision: DecideResponse; uid: string };
    try {
      outcome = await decideForFirebaseToken(token, opts, {
        target: req.originalUrl ?? req.url ?? null,
        context: { method: req.method },
      });
    } catch (err) {
      if (mode === "observe-only") return next();
      res.status(401).json({
        error: "firebase-verify-failed",
        detail: (err as Error).message,
      });
      return;
    }

    req.tfActor = outcome.decision.actor_resolved;
    req.tfDecision = outcome.decision;
    req.tfProofId = outcome.decision.proof_id;
    req.tfFirebaseUid = outcome.uid;
    res.setHeader("x-tf-proof-id", outcome.decision.proof_id);

    if (mode === "observe-only") return next();

    switch (outcome.decision.decision) {
      case "allow":
      case "log-only":
        return next();
      case "deny":
      case "escalate":
        res.status(403).json({
          error: "forbidden",
          decision: outcome.decision.decision,
          reason: outcome.decision.reason,
          proof_id: outcome.decision.proof_id,
          danger_tags: outcome.decision.danger_tags,
        });
        return;
      case "approval-required":
        if (outcome.decision.approval_id) {
          res.setHeader(
            "location",
            `/approvals/${outcome.decision.approval_id}`,
          );
        }
        res.status(202).json({
          decision: "approval-required",
          approval_id: outcome.decision.approval_id,
          reason: outcome.decision.reason,
          proof_id: outcome.decision.proof_id,
        });
        return;
      default:
        res.status(500).json({
          error: "unknown-decision",
          decision: outcome.decision.decision,
        });
    }
  };
}

export type { DecideResponse } from "@trustforge/sdk";
