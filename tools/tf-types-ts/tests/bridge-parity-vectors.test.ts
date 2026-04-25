/**
 * Cross-language parity tests for MCP normalization + WebAuthn projection
 * driven by `conformance/bridge-vectors.yaml`. Both this TS suite and the
 * matching Rust crates/tf-types/tests/bridge_{mcp,webauthn}.rs assertions
 * must produce identical outputs from identical inputs.
 */

import { describe, expect, test } from "bun:test";
import { readFileSync } from "node:fs";
import { join } from "node:path";
import { parse as parseYAML } from "yaml";

import { McpBridge, WebAuthnBridge, type WebAuthnCredential } from "../src/index";

interface VectorsFile {
  spiffe: unknown[];
  mcp_normalize: Array<{
    name: string;
    tool: string;
    prefix: string;
    action: string;
  }>;
  webauthn: Array<{
    name: string;
    credential: WebAuthnCredential;
    actor_id: string;
    trust_levels: string[];
    authority_root_kind: string;
    authority_root_id: string;
  }>;
}

function loadVectors(): VectorsFile {
  const path = join(import.meta.dir, "..", "..", "..", "conformance", "bridge-vectors.yaml");
  return parseYAML(readFileSync(path, "utf8")) as VectorsFile;
}

describe("MCP normalize parity", () => {
  for (const v of loadVectors().mcp_normalize) {
    test(v.name, () => {
      const bridge = new McpBridge("tf-mcp", "example.com", {
        bridgeId: "tf-mcp",
        namePrefix: v.prefix === "" ? undefined : v.prefix,
      });
      // The bridge does not expose the raw normalize fn, so we run an
      // import to extract the produced action name.
      const actions = bridge.importTools({
        tools: [{ name: v.tool }],
      });
      expect(actions[0]!.name).toBe(v.action);
    });
  }
});

describe("WebAuthn projection parity", () => {
  for (const v of loadVectors().webauthn) {
    test(v.name, () => {
      const bridge = new WebAuthnBridge("tf-webauthn", "example.com", {
        bridgeId: "tf-webauthn",
        rpId: v.credential.rp_id,
      });
      const identity = bridge.accept(v.credential);
      expect(identity.actor_id).toBe(v.actor_id);
      expect(identity.actor_type).toBe("human");
      expect(identity.trust_levels).toEqual(v.trust_levels as ("T0"|"T1"|"T2"|"T3"|"T4"|"T5"|"T6"|"T7")[]);
      expect(identity.authority_roots[0]!.kind).toBe(v.authority_root_kind as ("hardware-key"|"organization"|"federation"|"trust-domain"|"manufacturer"|"owner"|"compliance-issuer"|"local-emergency"|"transparency-anchor"));
      expect(identity.authority_roots[0]!.id).toBe(v.authority_root_id);
    });
  }
});
