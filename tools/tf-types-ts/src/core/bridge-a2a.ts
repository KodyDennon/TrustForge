/**
 * A2A (agent-to-agent) protocol bridge.
 *
 * A2A is the discovery + capability-exchange protocol an AI agent
 * uses when it negotiates with another agent for tool/resource access.
 * Where MCP focuses on tool catalogues, A2A focuses on agent
 * capability advertisements + per-call negotiation.
 *
 * The TrustForge A2A bridge:
 *   - Projects an A2A AgentCard into a TrustForge ActorIdentity.
 *   - Normalises A2A capability names into TrustForge action names
 *     under the `a2a.` prefix (mirror of the MCP normalisation).
 *   - Surfaces every advertised capability as a Capability the
 *     AgentGuard can authorize per call.
 *
 * The Rust mirror lives at `crates/tf-types/src/bridge_a2a.rs`.
 */

import type { ActionName, ActorId, Capability } from "../generated/_common.js";
import type { ActorIdentity } from "../generated/actor-identity.js";
import { type Bridge, type BridgeKind, BridgeFailure } from "./bridges.js";

export interface A2AAgentCard {
  /** Canonical A2A agent identifier (DNS-style: `agent.example.com`). */
  agent_id: string;
  /** Human-readable display name. */
  display_name?: string;
  /** Public key the remote agent uses to sign A2A messages. */
  public_key_b64?: string;
  /** Algorithm the public key uses. Default ed25519. */
  public_key_algorithm?: string;
  /** Capability advertisements. Each entry's `name` is the A2A
   *  capability id; the bridge normalises it into a TrustForge
   *  action name. */
  capabilities: Array<{
    name: string;
    description?: string;
    risk?: Capability["risk"];
  }>;
  /** Trust domain the agent runs under. */
  trust_domain: string;
}

export interface A2ABridgeConfig {
  bridgeId: string;
  trustDomain: string;
  /** Default risk class for capabilities the agent didn't specify one for. */
  defaultRisk?: Capability["risk"];
}

export interface A2ABridgeAcceptResult {
  identity: ActorIdentity;
  capabilities: Capability[];
  source: "a2a-agent-card";
}

const ACTION_NAME_RE = /^[a-z][a-z0-9_]*(\.[a-z][a-z0-9_]*)+$/;

/**
 * Normalise an A2A capability name into a TrustForge action name. The
 * rules mirror MCP's normaliseToolName but always prefix `a2a.`:
 *   - lowercase
 *   - non-alphanumeric runs collapse to a single `_`
 *   - leading / trailing `_` stripped
 *   - if the result has no `.`, prepend `a2a.`
 */
export function a2aNormaliseCapability(name: string, prefix?: string): string {
  const scrubbed = name
    .replace(/[^A-Za-z0-9]+/g, "_")
    .replace(/^_+|_+$/g, "")
    .toLowerCase();
  const withPrefix = prefix ? `${prefix}.${scrubbed}` : scrubbed;
  return withPrefix.includes(".") ? withPrefix : `a2a.${withPrefix}`;
}

export class A2ABridge implements Bridge {
  readonly kind: BridgeKind = "a2a";
  readonly bridgeId: string;
  readonly trustDomain: string;
  private readonly cfg: A2ABridgeConfig;

  constructor(cfg: A2ABridgeConfig) {
    this.bridgeId = cfg.bridgeId;
    this.trustDomain = cfg.trustDomain;
    this.cfg = cfg;
  }

  /** Project an A2A AgentCard into a TrustForge ActorIdentity +
   *  capability list. Throws BridgeFailure on malformed input. */
  acceptAgentCard(card: A2AAgentCard): A2ABridgeAcceptResult {
    if (!card.agent_id || !card.trust_domain || !Array.isArray(card.capabilities)) {
      throw new BridgeFailure({ code: "invalid-input", message: "A2A AgentCard missing required fields" });
    }
    const actor: ActorId = `tf:actor:agent:${card.trust_domain}/${card.agent_id}`;
    const algo = card.public_key_algorithm ?? "ed25519";
    const identity: ActorIdentity = {
      identity_version: "1",
      actor_id: actor,
      actor_type: "agent",
      public_keys: card.public_key_b64
        ? [
            {
              key_id: "a2a-agent-card",
              algorithm: algo,
              public_key: card.public_key_b64,
              purpose: "signing",
            },
          ]
        : [
            {
              key_id: "a2a-agent-card",
              algorithm: "external-attestation",
              // No key shipped on this AgentCard — mark explicitly so
              // callers don't treat the entry as a verified ed25519
              // key.
              public_key: `agent-card:${card.agent_id}`,
              purpose: "attestation",
            },
          ],
      trust_levels: ["T2"],
      authority_roots: [{ kind: "federation", id: card.trust_domain }],
      valid_from: new Date().toISOString(),
    };
    const capabilities: Capability[] = card.capabilities.map((c) => {
      const action = a2aNormaliseCapability(c.name) as ActionName;
      // Sanity-check the normalised name matches the schema regex; an
      // unrepresentable A2A name surfaces loudly rather than silently
      // breaking AgentGuard.
      if (!ACTION_NAME_RE.test(action)) {
        throw new BridgeFailure({
          code: "rejected",
          message: `A2A capability ${c.name} does not normalise to a valid action name (got ${action})`,
        });
      }
      return { name: action, risk: c.risk ?? this.cfg.defaultRisk ?? "R2" };
    });
    return { identity, capabilities, source: "a2a-agent-card" };
  }
}
