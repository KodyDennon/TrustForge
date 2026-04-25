import { describe, expect, test } from "bun:test";
import { mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { stringify as yamlStringify } from "yaml";
import {
  PluginError,
  PluginRegistry,
  RevocationIndex,
  b64encode,
  canonicalize,
  ed25519Generate,
  ed25519Sign,
  type PluginHost,
  type PluginManifest,
} from "../src/index";

async function signManifest(manifest: PluginManifest, privKey: Uint8Array): Promise<PluginManifest> {
  const unsigned: PluginManifest = { ...manifest, signature: { ...manifest.signature, signature: "" } };
  const payload = new TextEncoder().encode(canonicalize(unsigned));
  const sig = await ed25519Sign(payload, privKey);
  return { ...manifest, signature: { ...manifest.signature, signature: b64encode(sig) } };
}

describe("Plugin sandbox + revocation", () => {
  test("revoked plugin actor is refused at load time", async () => {
    const dir = mkdtempSync(join(tmpdir(), "tf-plugin-revoked-"));
    try {
      const pair = await ed25519Generate();
      const nativePath = resolve(import.meta.dir, "plugins", "native-hello.ts");
      const manifest: PluginManifest = {
        plugin_version: "1",
        plugin_id: "com.example.revoked",
        actor_id: "tf:actor:plugin:example.com/revoked",
        kind: "native",
        entry: nativePath,
        identity_pub: b64encode(pair.publicKey),
        signature: {
          algorithm: "ed25519",
          signer: "tf:actor:plugin:example.com/revoked",
          signature: "",
        },
        capabilities: [{ name: "file.read", risk: "R0" }],
      };
      const signed = await signManifest(manifest, pair.privateKey);
      const manifestPath = join(dir, "plugin.yaml");
      writeFileSync(manifestPath, yamlStringify(signed));

      const revocations = RevocationIndex.from([
        {
          revocation_version: "1",
          id: "rev-1",
          target_kind: "actor",
          target_id: "tf:actor:plugin:example.com/revoked",
          reason: "test",
          issuer: "tf:actor:service:example.com/tf-daemon",
          effective_at: "2026-04-23T00:00:00Z",
          signature: { algorithm: "ed25519", signer: "tf:actor:service:example.com/tf-daemon", signature: "AAAA" },
        },
      ]);
      const registry = new PluginRegistry({ revocations });
      const host: PluginHost = { log: () => {} };
      await expect(registry.load(manifestPath, host)).rejects.toThrow(PluginError);
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });

  test("conformance_profile field is preserved on the manifest", async () => {
    const dir = mkdtempSync(join(tmpdir(), "tf-plugin-cp-"));
    try {
      const pair = await ed25519Generate();
      const nativePath = resolve(import.meta.dir, "plugins", "native-hello.ts");
      const manifest = {
        plugin_version: "1",
        plugin_id: "com.example.cp",
        actor_id: "tf:actor:plugin:example.com/cp",
        kind: "native",
        entry: nativePath,
        identity_pub: b64encode(pair.publicKey),
        signature: {
          algorithm: "ed25519",
          signer: "tf:actor:plugin:example.com/cp",
          signature: "",
        },
        capabilities: [{ name: "file.read", risk: "R0" }],
        conformance_profile: ["tf-plugin-compatible"],
      } as unknown as PluginManifest;
      const signed = await signManifest(manifest, pair.privateKey);
      const manifestPath = join(dir, "plugin.yaml");
      writeFileSync(manifestPath, yamlStringify(signed));
      const registry = new PluginRegistry();
      const host: PluginHost = { log: () => {} };
      const loaded = await registry.load(manifestPath, host);
      const m = loaded.manifest as unknown as { conformance_profile?: string[] };
      expect(m.conformance_profile).toEqual(["tf-plugin-compatible"]);
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });
});
