import { describe, expect, test } from "bun:test";
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { parse as parseYAML } from "yaml";
import { stringify as yamlStringify } from "yaml";
import {
  PluginError,
  PluginRegistry,
  RpcClient,
  RpcServer,
  allowAllEnforcer,
  b64decode,
  b64encode,
  canonicalize,
  ed25519Generate,
  ed25519Sign,
  type PluginHost,
  type PluginManifest,
  type SessionFrame,
} from "../src/index";
import { buildTinyWasm } from "./plugins/build-wasm";

function writeWithTempDir<T>(fn: (dir: string) => Promise<T> | T): Promise<T> {
  const dir = mkdtempSync(join(tmpdir(), "tf-plugin-"));
  return Promise.resolve(fn(dir)).finally(() => rmSync(dir, { recursive: true, force: true }));
}

async function signManifest(manifest: PluginManifest, privKey: Uint8Array): Promise<PluginManifest> {
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

function makePipe(): {
  client: { send: (f: SessionFrame) => void; onFrame: (l: (f: SessionFrame) => void) => void };
  server: { send: (f: SessionFrame) => void; onFrame: (l: (f: SessionFrame) => void) => void };
} {
  const clientListeners = new Set<(f: SessionFrame) => void>();
  const serverListeners = new Set<(f: SessionFrame) => void>();
  return {
    client: {
      send: (f) => serverListeners.forEach((l) => l(f)),
      onFrame: (l) => clientListeners.add(l),
    },
    server: {
      send: (f) => clientListeners.forEach((l) => l(f)),
      onFrame: (l) => serverListeners.add(l),
    },
  };
}

describe("PluginRegistry", () => {
  test("native plugin loads, verifies signature, and exposes its handler via RPC", async () => {
    await writeWithTempDir(async (dir) => {
      const pair = await ed25519Generate();
      const nativePath = resolve(import.meta.dir, "plugins", "native-hello.ts");
      const manifestBase: PluginManifest = {
        plugin_version: "1",
        plugin_id: "com.example.hello",
        actor_id: "tf:actor:plugin:example.com/hello",
        kind: "native",
        entry: nativePath,
        identity_pub: b64encode(pair.publicKey),
        signature: {
          algorithm: "ed25519",
          signer: "tf:actor:plugin:example.com/hello",
          signature: "",
        },
        capabilities: [{ name: "file.read", risk: "R0" }],
        description: "test",
      };
      const signed = await signManifest(manifestBase, pair.privateKey);
      const manifestPath = join(dir, "plugin.yaml");
      writeFileSync(manifestPath, yamlStringify(signed));

      const logs: string[] = [];
      const host: PluginHost = {
        log: (m: string) => logs.push(m),
      };

      const registry = new PluginRegistry();
      const loaded = await registry.load(manifestPath, host);
      expect(loaded.manifest.plugin_id).toBe("com.example.hello");
      expect(loaded.handlers).toBeDefined();

      // Register on an RpcServer and call it end-to-end.
      const pipe = makePipe();
      const server = new RpcServer(pipe.server, {
        selfActor: "tf:actor:service:example.com/daemon",
        enforcer: allowAllEnforcer,
      });
      registry.registerOn(server);
      const client = new RpcClient(pipe.client, {
        callerActor: "tf:actor:agent:example.com/test",
      });
      const resp = await client.call<{ path: string }, { path: string; contents: string; size: number }>(
        "file.read",
        { path: "README.md" },
      );
      expect(resp.path).toBe("README.md");
      expect(resp.contents).toBe("stub contents of README.md");
      expect(logs.length).toBeGreaterThan(0);
    });
  });

  test("tampered signature is rejected", async () => {
    await writeWithTempDir(async (dir) => {
      const pair = await ed25519Generate();
      const nativePath = resolve(import.meta.dir, "plugins", "native-hello.ts");
      const manifest: PluginManifest = {
        plugin_version: "1",
        plugin_id: "com.example.hello",
        actor_id: "tf:actor:plugin:example.com/hello",
        kind: "native",
        entry: nativePath,
        identity_pub: b64encode(pair.publicKey),
        signature: {
          algorithm: "ed25519",
          signer: "tf:actor:plugin:example.com/hello",
          signature: "",
        },
        capabilities: [{ name: "file.read", risk: "R0" }],
      };
      const signed = await signManifest(manifest, pair.privateKey);
      // Tamper with the signature.
      const tampered = {
        ...signed,
        signature: { ...signed.signature, signature: "AAAA" },
      };
      const manifestPath = join(dir, "plugin.yaml");
      writeFileSync(manifestPath, yamlStringify(tampered));

      const registry = new PluginRegistry();
      expect(registry.load(manifestPath, { log: () => {} })).rejects.toThrow(PluginError);
    });
  });

  test("WASM plugin loads with permission-gated imports and runs exported init", async () => {
    await writeWithTempDir(async (dir) => {
      const pair = await ed25519Generate();
      const wasmPath = join(dir, "plugin.wasm");
      writeFileSync(wasmPath, buildTinyWasm());

      const manifest: PluginManifest = {
        plugin_version: "1",
        plugin_id: "com.example.tiny-wasm",
        actor_id: "tf:actor:plugin:example.com/tiny-wasm",
        kind: "wasm",
        entry: "./plugin.wasm",
        identity_pub: b64encode(pair.publicKey),
        signature: {
          algorithm: "ed25519",
          signer: "tf:actor:plugin:example.com/tiny-wasm",
          signature: "",
        },
        capabilities: [{ name: "tf.log", risk: "R0" }],
        imports: ["env.log"],
      };
      const signed = await signManifest(manifest, pair.privateKey);
      const manifestPath = join(dir, "plugin.yaml");
      writeFileSync(manifestPath, yamlStringify(signed));

      const logged: number[] = [];
      const host: PluginHost = {
        log: (value: number) => logged.push(value),
      };
      const registry = new PluginRegistry();
      const loaded = await registry.load(manifestPath, host);
      expect(loaded.wasmInstance).toBeDefined();
      // Invoke the exported "run" — it imports env.log(i32) and should call log(42).
      const run = loaded.wasmInstance!.exports.run as () => void;
      run();
      expect(logged).toEqual([42]);
    });
  });

  test("WASM plugin is denied an import its manifest did not declare", async () => {
    await writeWithTempDir(async (dir) => {
      const pair = await ed25519Generate();
      const wasmPath = join(dir, "plugin.wasm");
      writeFileSync(wasmPath, buildTinyWasm());

      const manifest: PluginManifest = {
        plugin_version: "1",
        plugin_id: "com.example.bad-wasm",
        actor_id: "tf:actor:plugin:example.com/bad-wasm",
        kind: "wasm",
        entry: "./plugin.wasm",
        identity_pub: b64encode(pair.publicKey),
        signature: {
          algorithm: "ed25519",
          signer: "tf:actor:plugin:example.com/bad-wasm",
          signature: "",
        },
        capabilities: [{ name: "tf.log", risk: "R0" }],
        imports: [], // intentionally omit env.log
      };
      const signed = await signManifest(manifest, pair.privateKey);
      const manifestPath = join(dir, "plugin.yaml");
      writeFileSync(manifestPath, yamlStringify(signed));

      const registry = new PluginRegistry();
      await expect(
        registry.load(manifestPath, { log: () => {} }),
      ).rejects.toThrow();
    });
  });
});
