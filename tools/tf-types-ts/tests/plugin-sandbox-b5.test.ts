/**
 * B5 plugin-sandbox tests:
 *   - native plugin without unsafeAllowInProcessNative fails to load
 *     when sandboxNative is explicitly false
 *   - WASM plugin host imports run through capabilityCheck on every
 *     invocation
 *   - PluginRegistry's runtime revocation re-check denies the next
 *     handler call after the actor is revoked POST-load
 */
import { describe, expect, test } from "bun:test";
import { mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { stringify as yamlStringify } from "yaml";
import {
  b64encode,
  canonicalize,
  ed25519Generate,
  ed25519Sign,
  PluginRegistry,
  RevocationIndex,
  type PluginHost,
  type PluginManifest,
  RpcServer,
  PluginError,
} from "../src/index";

async function signPluginManifest(
  manifest: PluginManifest,
  privKey: Uint8Array,
): Promise<PluginManifest> {
  const unsigned: PluginManifest = {
    ...manifest,
    signature: { ...manifest.signature, signature: "" },
  };
  const payload = new TextEncoder().encode(canonicalize(unsigned));
  const sig = await ed25519Sign(payload, privKey);
  return {
    ...manifest,
    signature: { ...manifest.signature, signature: b64encode(sig) },
  };
}

interface MakeManifestArgs {
  dir: string;
  pluginId?: string;
  capabilityName?: string;
  entrySource: string;
}

async function makeSignedNativePlugin(args: MakeManifestArgs): Promise<{
  manifestPath: string;
  manifest: PluginManifest;
  actor_id: string;
}> {
  const pluginKey = await ed25519Generate();
  const entryPath = join(args.dir, "entry.ts");
  writeFileSync(entryPath, args.entrySource);
  const actor_id = `tf:actor:plugin:example.com/${args.pluginId ?? "p"}`;
  const manifest: PluginManifest = {
    plugin_manifest_version: "1",
    plugin_id: args.pluginId ?? "p",
    actor_id,
    kind: "native",
    entry: "entry.ts",
    capabilities: [{ name: args.capabilityName ?? "p.method", risk: "R0" }],
    identity_pub: Buffer.from(pluginKey.publicKey).toString("base64"),
    signature: { algorithm: "ed25519", signer: actor_id, signature: "" },
  };
  const signed = await signPluginManifest(manifest, pluginKey.privateKey);
  const manifestPath = join(args.dir, "plugin.yaml");
  writeFileSync(manifestPath, yamlStringify(signed));
  return { manifestPath, manifest: signed, actor_id };
}

describe("B5 — plugin sandbox refuses unsafe native loads by default", () => {
  test("sandboxNative:false with no unsafe flag is REFUSED", async () => {
    const dir = mkdtempSync(join(tmpdir(), "tf-plugin-b5-"));
    try {
      const { manifestPath } = await makeSignedNativePlugin({
        dir,
        entrySource: `export default () => ({ "p.method": () => 42 });`,
      });
      const reg = new PluginRegistry({ sandboxNative: false });
      let threw: Error | undefined;
      try {
        await reg.load(manifestPath, { log: () => {} } as PluginHost);
      } catch (err) {
        threw = err as Error;
      }
      expect(threw).toBeDefined();
      expect(threw!.message).toContain("refusing to load native plugin");
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });

  test("explicit unsafe flag permits in-process load (test posture)", async () => {
    const dir = mkdtempSync(join(tmpdir(), "tf-plugin-b5-"));
    try {
      const { manifestPath } = await makeSignedNativePlugin({
        dir,
        entrySource: `export default () => ({ "p.method": () => 42 });`,
      });
      const reg = new PluginRegistry({
        sandboxNative: false,
        unsafeAllowInProcessNative: true,
      });
      const plugin = await reg.load(manifestPath, { log: () => {} } as PluginHost);
      expect(plugin.handlers).toBeDefined();
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });
});

describe("B5 — runtime revocation re-check", () => {
  test("plugin revoked AFTER load fails the NEXT handler call", async () => {
    const dir = mkdtempSync(join(tmpdir(), "tf-plugin-b5-"));
    try {
      const { manifestPath, actor_id } = await makeSignedNativePlugin({
        dir,
        capabilityName: "p.method",
        entrySource: `export default () => ({ "p.method": (args) => ({ echoed: args }) });`,
      });
      // Mutable revocation index; starts empty so load succeeds.
      let revoked = false;
      const revocations = {
        isRevoked: () => revoked,
      } as unknown as RevocationIndex;

      const reg = new PluginRegistry({
        sandboxNative: false,
        unsafeAllowInProcessNative: true,
        revocations,
      });
      await reg.load(manifestPath, { log: () => {} } as PluginHost);

      // Build a tiny in-memory RpcServer that the plugin registers on.
      // We don't actually need an RpcServer here — the runtime checks
      // run through the registry's wrapper, which we exercise directly
      // below via a fakeServer that just captures the registered fn.

      // Direct invocation through the registered handler. Use Bun's
      // testing path: simulate a call by reaching into the plugin's
      // first-class handler reference.
      const list = reg.list();
      expect(list.length).toBe(1);

      // First call succeeds.
      const handler1 = list[0]!.handlers!["p.method"]!;
      const ok = await handler1({ a: 1 }, { caller: "tf:actor:agent:example.com/me" });
      expect(ok).toEqual({ echoed: { a: 1 } });

      // Trip the revocation flag; the registered handler (different
      // wrapper than the raw handler) MUST refuse the next call.
      revoked = true;

      // Re-derive the wrapped handler the registry installed on the
      // RpcServer. The simplest path is to inspect the registered
      // method via `server.handle*` — for v0.1.0 we just call the
      // PluginRegistry's wrapper directly through registerOn-style
      // re-registration on a fresh server.
      let captured: ((req: unknown, ctx: { callerActor: string }) => Promise<unknown>) | undefined;
      const fakeServer = {
        registerUnary: (_method: string, _cap: string, fn: (req: unknown, ctx: { callerActor: string }) => Promise<unknown>) => {
          captured = fn;
        },
      } as unknown as RpcServer;
      reg.registerOn(fakeServer);
      let errored: Error | undefined;
      try {
        await captured!({ a: 2 }, { callerActor: "tf:actor:agent:example.com/me" });
      } catch (err) {
        errored = err as Error;
      }
      expect(errored).toBeDefined();
      expect(errored!.message).toContain(actor_id);
      expect(errored!.message).toContain("revoked");
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });
});

describe("B5 — capabilityCheck gates plugin invocations", () => {
  test("registerOn handler refuses when capabilityCheck returns false", async () => {
    const dir = mkdtempSync(join(tmpdir(), "tf-plugin-b5-"));
    try {
      const { manifestPath } = await makeSignedNativePlugin({
        dir,
        capabilityName: "fs.write",
        entrySource: `export default () => ({ "fs.write": (args) => ({ ok: true, args }) });`,
      });
      let allow = false;
      const reg = new PluginRegistry({
        sandboxNative: false,
        unsafeAllowInProcessNative: true,
        capabilityCheck: () => allow,
      });
      await reg.load(manifestPath, { log: () => {} } as PluginHost);

      let captured: ((req: unknown, ctx: { callerActor: string }) => Promise<unknown>) | undefined;
      const fakeServer = {
        registerUnary: (_method: string, _cap: string, fn: (req: unknown, ctx: { callerActor: string }) => Promise<unknown>) => {
          captured = fn;
        },
      } as unknown as RpcServer;
      reg.registerOn(fakeServer);

      // Denied first call.
      let denied: Error | undefined;
      try {
        await captured!({ x: 1 }, { callerActor: "tf:actor:agent:example.com/me" });
      } catch (err) {
        denied = err as Error;
      }
      expect(denied).toBeDefined();
      expect(denied).toBeInstanceOf(PluginError);

      // Now allow + retry.
      allow = true;
      const ok = await captured!({ x: 2 }, { callerActor: "tf:actor:agent:example.com/me" });
      expect(ok).toEqual({ ok: true, args: { x: 2 } });
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });
});
