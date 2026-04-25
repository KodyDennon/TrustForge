/**
 * End-to-end test for dynamic permission negotiation:
 *   agent → daemon → policy engine → approval queue → signed grant →
 *   action executes → ProofEvent records full provenance chain.
 */

import { describe, expect, test } from "bun:test";
import {
  ApprovalQueue,
  ed25519Generate,
  makePermissionRequest,
  NativePolicyEngine,
  permissionGrantSigningBytes,
  provenanceFromRequest,
  signPermissionGrant,
  verifyPermissionGrant,
  type PermissionGrant,
  type PermissionRequest,
} from "../src/index";
import type { Policy } from "../src/generated/policy";

describe("Permission negotiation primitives", () => {
  test("makePermissionRequest fills required fields with sensible defaults", () => {
    const req = makePermissionRequest({
      id: "pr-1",
      agent: "tf:actor:agent:example.com/code-helper",
      action: "shell.exec",
      reason: "list /usr",
      human: "tf:actor:human:example.com/alice",
      target: "/usr/bin/ls -la",
      durationSeconds: 300,
    });
    expect(req.request_version).toBe("1");
    expect(req.action).toBe("shell.exec");
    expect(req.duration_seconds).toBe(300);
    expect(req.requested_at).toMatch(/Z$/);
  });

  test("provenanceFromRequest carries the chain of responsibility", () => {
    const req = makePermissionRequest({
      id: "pr-1",
      agent: "tf:actor:agent:example.com/code-helper",
      action: "shell.exec",
      reason: "x",
      human: "tf:actor:human:example.com/alice",
      instance: "tf:instance:agent:example.com/code-helper/laptop/abc",
      model: "anthropic:claude-opus-4-7",
      tool: "shell.exec",
    });
    const prov = provenanceFromRequest(req);
    expect(prov.human).toBe("tf:actor:human:example.com/alice");
    expect(prov.agent).toBe("tf:actor:agent:example.com/code-helper");
    expect(prov.model).toBe("anthropic:claude-opus-4-7");
    expect(prov.requested_action).toBe("shell.exec");
  });

  test("signed grant verifies with the issuer's key and detects tampering", async () => {
    const pair = await ed25519Generate();
    const req = makePermissionRequest({
      id: "pr-2",
      agent: "tf:actor:agent:example.com/code-helper",
      action: "file.read",
      reason: "x",
    });
    const grant = await signPermissionGrant({
      request: req,
      decision: "allow",
      issuer: "tf:actor:service:example.com/tf-daemon",
      privateKey: pair.privateKey,
      capability: { name: "file.read", risk: "R1" },
      validFrom: new Date(Date.now() - 1_000).toISOString(),
      validUntil: new Date(Date.now() + 60_000).toISOString(),
    });
    const ok = await verifyPermissionGrant({ grant, publicKey: pair.publicKey, request: req });
    expect(ok.ok).toBe(true);

    // Tamper the decision after signing → verification fails.
    const tampered: PermissionGrant = { ...grant, decision: "deny" };
    const bad = await verifyPermissionGrant({ grant: tampered, publicKey: pair.publicKey, request: req });
    expect(bad.ok).toBe(false);
  });

  test("verifyPermissionGrant rejects expired grants", async () => {
    const pair = await ed25519Generate();
    const req = makePermissionRequest({
      id: "pr-3",
      agent: "tf:actor:agent:example.com/code-helper",
      action: "file.read",
      reason: "x",
    });
    const grant = await signPermissionGrant({
      request: req,
      decision: "allow",
      issuer: "tf:actor:service:example.com/tf-daemon",
      privateKey: pair.privateKey,
      validFrom: "2026-04-23T00:00:00Z",
      validUntil: "2026-04-23T01:00:00Z",
    });
    const verdict = await verifyPermissionGrant({
      grant,
      publicKey: pair.publicKey,
      now: "2026-04-25T00:00:00Z",
    });
    expect(verdict.ok).toBe(false);
    expect(verdict.reason).toContain("window");
  });

  test("permissionGrantSigningBytes is stable", async () => {
    const pair = await ed25519Generate();
    const req = makePermissionRequest({
      id: "pr-4",
      agent: "tf:actor:agent:example.com/x",
      action: "file.read",
      reason: "x",
    });
    const grant = await signPermissionGrant({
      request: req,
      decision: "allow",
      issuer: "tf:actor:service:example.com/d",
      privateKey: pair.privateKey,
    });
    const a = permissionGrantSigningBytes(grant);
    const b = permissionGrantSigningBytes({ ...grant });
    expect(Buffer.from(a).toString("hex")).toBe(Buffer.from(b).toString("hex"));
  });
});

describe("End-to-end negotiation flow", () => {
  test("agent → daemon → human approve → signed grant → executes with provenance", async () => {
    const policy: Policy = {
      policy_version: "1",
      trust_domain: "example.com",
      engine_hint: "native",
      rules: [
        {
          id: "escalate.shell",
          effect: "escalate",
          action: "shell.exec",
          approval: "required",
          reason: "shell needs a human",
        } as Policy["rules"][number],
        {
          id: "allow.read",
          effect: "allow",
          action: "file.read",
          reason: "ok",
        } as Policy["rules"][number],
      ],
    };
    const engine = new NativePolicyEngine({ policy });
    const queue = new ApprovalQueue();
    const daemonKey = await ed25519Generate();

    // 1. Agent builds a permission request.
    const req: PermissionRequest = makePermissionRequest({
      id: "pr-e2e",
      agent: "tf:actor:agent:example.com/code-helper",
      action: "shell.exec",
      reason: "list working tree",
      human: "tf:actor:human:example.com/alice",
      tool: "shell.exec",
      target: "/usr/bin/ls -la",
      durationSeconds: 300,
    });

    // 2. Daemon evaluates policy.
    const decision = engine.evaluate({
      subject: req.agent,
      action: req.action,
      target: req.target,
    });
    expect(decision.decision).toBe("approval-required");

    // 3. Daemon enqueues approval, human approves.
    const approvalP = queue.push({
      request_version: "1",
      id: req.id,
      actor: req.agent,
      action: req.action,
      reason: decision.reason ?? "needs approval",
      created_at: new Date().toISOString(),
    });
    const accepted = queue.respond(req.id, "approve", "looks fine");
    expect(accepted).toBe(true);
    const approval = await approvalP;
    expect(approval.decision).toBe("approve");

    // 4. Daemon signs a grant.
    const grant = await signPermissionGrant({
      request: req,
      decision: "allow",
      issuer: "tf:actor:service:example.com/tf-daemon",
      privateKey: daemonKey.privateKey,
      capability: { name: "shell.exec", risk: "R3" },
      policyDecision: decision,
      ceremonyId: `cer-${req.id}-click`,
      validFrom: new Date(Date.now() - 1_000).toISOString(),
      validUntil: new Date(Date.now() + 300_000).toISOString(),
    });

    // 5. Agent verifies the grant and "executes" the action.
    const verdict = await verifyPermissionGrant({
      grant,
      publicKey: daemonKey.publicKey,
      request: req,
    });
    expect(verdict.ok).toBe(true);

    // 6. Build a ProofEvent that records the full provenance chain.
    const provenance = provenanceFromRequest(req);
    expect(provenance.human).toBe("tf:actor:human:example.com/alice");
    expect(provenance.agent).toBe("tf:actor:agent:example.com/code-helper");
    expect(provenance.requested_action).toBe("shell.exec");
  });
});
