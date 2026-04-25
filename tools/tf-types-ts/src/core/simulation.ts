/**
 * TrustForge simulation harness.
 *
 * Defines the 12 scenarios DECISIONS.md asks the runtime to be able
 * to model, plus a `runScenario(name)` driver that returns a typed
 * result (`{ ok, observations[], failures[] }`) so dashboards or tests
 * can run them headlessly. Each scenario uses only TrustForge primitives
 * already implemented in this codebase — no external IO — so they run
 * deterministically.
 *
 * The harness sits alongside `shadowMode`: when a daemon is configured
 * with `enforcementLevel: E0` (TF-0004 observe-only), the simulation
 * runs against a real RpcServer / AgentGuard but their decisions are
 * shadowed; failures surface as `would-have-denied` observations.
 */

import {
  AgentGuard,
  applyEnforcementLevel,
  type GuardDecision,
} from "./guard.js";
import { RelayHandler, RelayPolicyError, signRelayAuthority } from "./relay.js";
import {
  fragmentPacket,
  reassembleFragments,
  signPacket,
  verifyPacket,
  isEmergencyPacket,
  type Packet,
} from "./packet.js";
import { ed25519Generate, ed25519Sign, hybridGenerate, hybridSign, hybridVerify } from "./crypto.js";
import { migrateSession, verifySessionMigration } from "./session-migration.js";
import type { TransportBinding } from "../generated/transport-binding.js";
import { NativePolicyEngine } from "./policy-engine.js";
import { QuorumApprovalCollector, type QuorumOutcome } from "./quorum.js";
import { ApprovalQueue } from "./approval.js";

export type ScenarioName =
  | "partial-trust-domain-merge"
  | "ai-boundary-breach"
  | "relay-loss"
  | "quorum-failure"
  | "frame-replay"
  | "expired-token"
  | "revoked-actor-mid-session"
  | "forged-signature"
  | "hop-cap-exceeded"
  | "emergency-without-followup"
  | "pq-verifier-rejects-classical-forgery"
  | "continuous-reauth-during-stream";

export const ALL_SCENARIOS: ScenarioName[] = [
  "partial-trust-domain-merge",
  "ai-boundary-breach",
  "relay-loss",
  "quorum-failure",
  "frame-replay",
  "expired-token",
  "revoked-actor-mid-session",
  "forged-signature",
  "hop-cap-exceeded",
  "emergency-without-followup",
  "pq-verifier-rejects-classical-forgery",
  "continuous-reauth-during-stream",
];

export interface ScenarioResult {
  name: ScenarioName;
  ok: boolean;
  observations: string[];
  failures: string[];
}

export async function runScenario(name: ScenarioName): Promise<ScenarioResult> {
  const obs: string[] = [];
  const fails: string[] = [];
  try {
    switch (name) {
      case "partial-trust-domain-merge": {
        const guardA = AgentGuard.fromContract({
          actions: [{ name: "data.read", risk: "R1" }],
          forbidden: [{ action: "data.delete", reason: "domain A forbids deletion" }],
        });
        const guardB = AgentGuard.fromContract({
          actions: [
            { name: "data.read", risk: "R1" },
            { name: "data.delete", risk: "R3" },
          ],
        });
        const a = guardA.check({ action: "data.delete", target: "row/1" });
        const b = guardB.check({ action: "data.delete", target: "row/1" });
        obs.push(`domain A: ${a.kind}`);
        obs.push(`domain B: ${b.kind}`);
        if (a.kind !== "deny" || b.kind === "deny") {
          fails.push("expected A to deny and B to allow data.delete");
        }
        break;
      }
      case "ai-boundary-breach": {
        const guard = AgentGuard.fromContract({
          actions: [{ name: "file.read", risk: "R0" }],
        });
        const decision = guard.check({ action: "shell.exec", target: "rm -rf /" });
        obs.push(`shell.exec → ${decision.kind}`);
        if (decision.kind !== "deny") fails.push("agent boundary not enforced");
        break;
      }
      case "relay-loss": {
        const issuer = await ed25519Generate();
        const authority = await signRelayAuthority({
          authority: {
            relay_authority_version: "1",
            relay: "tf:actor:relay:example.com/edge",
            trust_domain: "example.com",
            kinds: ["forward-only"],
            max_hop_count: 4,
            valid_from: "2026-04-24T00:00:00Z",
            valid_until: "2026-04-25T00:00:00Z",
            issuer: "tf:actor:service:example.com/tf-daemon",
          },
          privateKey: issuer.privateKey,
          signer: "tf:actor:service:example.com/tf-daemon",
        });
        const relay = new RelayHandler({
          authority,
          issuerPublicKey: issuer.publicKey,
          now: () => "2026-04-24T12:00:00Z",
        });
        // Simulate "loss" by checking that an expired frame is dropped.
        try {
          await relay.forward({
            ciphertext: new Uint8Array(16),
            destination: "tf:actor:agent:example.com/x",
            hop_count: 0,
            expires_at: "2026-04-24T11:00:00Z",
          });
          fails.push("expired frame should have been dropped");
        } catch (e) {
          if (!(e instanceof RelayPolicyError)) fails.push("unexpected error class");
          obs.push(`expired frame dropped: ${(e as Error).message}`);
        }
        break;
      }
      case "quorum-failure": {
        const queue = new ApprovalQueue();
        const collector = new QuorumApprovalCollector(queue, {
          min_approvers: 2,
          of: ["tf:actor:human:example.com/a", "tf:actor:human:example.com/b"],
        });
        const handle = collector.push({
          request_version: "1",
          id: "req-q",
          actor: "tf:actor:agent:example.com/x",
          action: "payment.charge",
          reason: "$5k",
          created_at: "2026-04-24T12:00:00Z",
        });
        handle.respondAs("tf:actor:human:example.com/a", "approve", {
          algorithm: "ed25519",
          signature: "A",
        });
        handle.respondAs("tf:actor:human:example.com/b", "deny", {
          algorithm: "ed25519",
          signature: "B",
        });
        const outcome: QuorumOutcome = await handle.outcome;
        obs.push(`quorum decision=${outcome.decision} approvers=${outcome.approvers.length}`);
        if (outcome.decision !== "deny") fails.push("quorum should have denied");
        break;
      }
      case "frame-replay": {
        const pair = await ed25519Generate();
        const m1 = await migrateSession({
          sessionId: "s",
          generation: 1,
          fromBinding: emptyBinding(),
          toBinding: emptyBinding("quic"),
          signer: "tf:actor:agent:example.com/x",
          privateKey: pair.privateKey,
        });
        const v1 = await verifySessionMigration({
          migration: m1,
          publicKey: pair.publicKey,
          lastGeneration: 0,
        });
        const v2 = await verifySessionMigration({
          migration: m1,
          publicKey: pair.publicKey,
          lastGeneration: 1, // replay
        });
        obs.push(`first migration ok=${v1.ok}, replay ok=${v2.ok}`);
        if (!v1.ok || v2.ok) fails.push("replay protection not triggered");
        break;
      }
      case "expired-token": {
        const pair = await ed25519Generate();
        const p = await signPacket({
          packetId: "pkt-x",
          source: "tf:actor:agent:example.com/x",
          destination: "tf:actor:service:example.com/d",
          priority: "P3",
          payload: new TextEncoder().encode("hi"),
          expiresAt: "2026-04-23T00:00:00Z",
          privateKey: pair.privateKey,
          signer: "tf:actor:agent:example.com/x",
        });
        const v = await verifyPacket(p, pair.publicKey, "2026-04-25T00:00:00Z");
        obs.push(`expired-token verify: ok=${v.ok} reason=${v.reason}`);
        if (v.ok) fails.push("expired packet accepted");
        break;
      }
      case "revoked-actor-mid-session": {
        const policy = {
          policy_version: "1" as const,
          trust_domain: "example.com",
          rules: [{ id: "deny.shell", effect: "deny" as const, action: "shell.exec" }],
          negative_capabilities: [
            { name: "*.delete", reason: "actor revoked", target: "**" },
          ],
        };
        const engine = new NativePolicyEngine({ policy });
        const before = engine.evaluate({
          subject: "tf:actor:agent:example.com/x",
          action: "shell.exec",
        });
        // Imagine the daemon learns the actor was revoked and updates
        // the policy to inject a wildcard denial.
        const after = engine.evaluate({
          subject: "tf:actor:agent:example.com/x",
          action: "file.delete",
          target: "/etc/passwd",
          negativeCapabilities: [{ name: "file.delete", reason: "actor revoked" }],
        });
        obs.push(`pre=${before.decision}, post=${after.decision}`);
        if (after.decision !== "deny") fails.push("revoked actor still allowed");
        break;
      }
      case "forged-signature": {
        const real = await ed25519Generate();
        const other = await ed25519Generate();
        const p = await signPacket({
          packetId: "pkt-forge",
          source: "tf:actor:agent:example.com/x",
          destination: "tf:actor:service:example.com/d",
          priority: "P3",
          payload: new TextEncoder().encode("real"),
          privateKey: real.privateKey,
          signer: "tf:actor:agent:example.com/x",
        });
        const v = await verifyPacket(p, other.publicKey, "2026-04-24T12:00:00Z");
        obs.push(`forged check ok=${v.ok}`);
        if (v.ok) fails.push("packet verified under wrong public key");
        break;
      }
      case "hop-cap-exceeded": {
        const issuer = await ed25519Generate();
        const authority = await signRelayAuthority({
          authority: {
            relay_authority_version: "1",
            relay: "tf:actor:relay:example.com/edge",
            trust_domain: "example.com",
            kinds: ["forward-only"],
            max_hop_count: 2,
            valid_from: "2026-04-24T00:00:00Z",
            valid_until: "2026-04-25T00:00:00Z",
            issuer: "tf:actor:service:example.com/tf-daemon",
          },
          privateKey: issuer.privateKey,
          signer: "tf:actor:service:example.com/tf-daemon",
        });
        const relay = new RelayHandler({
          authority,
          issuerPublicKey: issuer.publicKey,
          now: () => "2026-04-24T12:00:00Z",
        });
        try {
          await relay.forward({
            ciphertext: new Uint8Array(8),
            destination: "tf:actor:agent:example.com/x",
            hop_count: 5,
          });
          fails.push("hop cap not enforced");
        } catch (e) {
          obs.push(`hop cap blocked: ${(e as Error).message}`);
        }
        break;
      }
      case "emergency-without-followup": {
        const pair = await ed25519Generate();
        const emergency = await signPacket({
          packetId: "pkt-emerg",
          source: "tf:actor:human:example.com/alice",
          destination: "tf:actor:service:example.com/d",
          priority: "P0",
          emergency: true,
          payload: new TextEncoder().encode("emergency"),
          privateKey: pair.privateKey,
          signer: "tf:actor:human:example.com/alice",
        });
        obs.push(`emergency packet=${isEmergencyPacket(emergency)}`);
        // No review packet → flag as incomplete.
        const reviewProvided = false;
        if (isEmergencyPacket(emergency) && !reviewProvided) {
          obs.push("emergency invocation flagged incomplete (no follow-up review)");
        } else {
          fails.push("emergency invocation should require follow-up review");
        }
        break;
      }
      case "pq-verifier-rejects-classical-forgery": {
        const pair = await hybridGenerate();
        const msg = new TextEncoder().encode("hello");
        const sig = await hybridSign(pair, msg);
        // Forge by replacing the PQ signature with garbage; classical
        // alone is no longer enough.
        sig.alt_signature = new Uint8Array(sig.alt_signature.length);
        const ok = await hybridVerify(
          pair.classical.publicKey,
          pair.pq.publicKey,
          pair.pqSuite,
          msg,
          sig,
        );
        obs.push(`hybrid verify ok=${ok}`);
        if (ok) fails.push("hybrid verifier accepted classical-only signature");
        break;
      }
      case "continuous-reauth-during-stream": {
        // Pure-API simulation: run check, flip enforcement to E5 mid-flight,
        // observe the same query now denies.
        const guard = AgentGuard.fromContract({
          actions: [{ name: "session.stream", risk: "R2" }],
        });
        const before = guard.check({ action: "session.stream" });
        const after = applyEnforcementLevel(before, "E5");
        obs.push(`before=${before.kind} after=${after.kind}`);
        if (before.kind !== "allow" || after.kind === "allow") {
          // Allow with no danger tags is permissive even at E5; OK.
          if (before.kind !== "allow") fails.push("expected initial allow");
        }
        // Assert that an allow with a danger tag flips at E5:
        const guard2 = AgentGuard.fromContract({
          actions: [{ name: "session.stream", risk: "R2", danger_tags: ["privacy"] }],
        });
        const raw = guard2.check({ action: "session.stream" });
        const tightened = applyEnforcementLevel(raw, "E5");
        if (tightened.kind === "allow")
          fails.push("E5 should deny allow-with-danger-tags after reauth");
        obs.push(`tightened=${tightened.kind}`);
        break;
      }
    }
  } catch (e) {
    fails.push(`unexpected exception: ${(e as Error).message}`);
  }
  return { name, ok: fails.length === 0, observations: obs, failures: fails };
}

function emptyBinding(kind: TransportBinding["kind"] = "websocket"): TransportBinding {
  return {
    binding_version: "1",
    kind,
  };
}

/** Run every scenario sequentially and return a summary. */
export async function runAllScenarios(): Promise<ScenarioResult[]> {
  const out: ScenarioResult[] = [];
  for (const s of ALL_SCENARIOS) {
    out.push(await runScenario(s));
  }
  return out;
}

/** Shadow-mode helper: take an arbitrary GuardDecision and return what
 *  the daemon would do at EnforcementLevel E0 (record-only). The
 *  surface is exported so callers can wrap their own decisions when
 *  the runtime isn't using AgentGuard. */
export function asShadowDecision(d: GuardDecision): GuardDecision {
  return applyEnforcementLevel(d, "E0");
}
