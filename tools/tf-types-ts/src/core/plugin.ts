/**
 * PluginRegistry — loads + verifies + registers TrustForge plugins.
 *
 * Flow:
 *   1. Parse manifest YAML, schema-validate it (caller responsibility via
 *      tf-schema validate; the registry also runs a minimal shape check).
 *   2. Verify the ed25519 signature over canonical(manifest with
 *      signature.signature cleared).
 *   3. Load the plugin body:
 *        - kind=native: dynamic-import the entry module; call its default
 *          export (a function that receives a PluginHost and returns an
 *          object of handler functions keyed by method name).
 *        - kind=wasm: WebAssembly.instantiate the entry bytes with an
 *          imports object restricted to the manifest's `imports` list.
 *   4. Expose register(rpcServer, enforcer): any declared capability names
 *      are registered as RpcServer methods backed by the plugin handlers.
 */

import { readFileSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { parse as parseYAML } from "yaml";
import { canonicalize } from "./canonical.js";
import {
  CryptoError,
  b64decode,
  ed25519Verify,
  utf8encode,
} from "./crypto.js";
import type { PluginManifest } from "../generated/plugin-manifest.js";
import type { RpcServer } from "./rpc.js";

export class PluginError extends Error {}

export interface PluginHost {
  /** Log into the host-controlled log surface. Argument type varies by
   *  plugin kind: a string for native plugins, an i32 for the minimal WASM
   *  POC. */
  log(message: unknown): void;
  /** Free-form host functions a manifest may have declared via `imports`. */
  [key: string]: unknown;
}

export type NativePluginEntry = (host: PluginHost) => NativePluginHandlers | Promise<NativePluginHandlers>;

export type NativePluginHandlers = Record<
  string,
  (args: unknown, ctx: { caller: string }) => unknown | Promise<unknown>
>;

export interface LoadedPlugin {
  manifest: PluginManifest;
  handlers?: NativePluginHandlers;
  wasmInstance?: WebAssembly.Instance;
}

export class PluginRegistry {
  private plugins: LoadedPlugin[] = [];

  async load(manifestPath: string, host: PluginHost): Promise<LoadedPlugin> {
    const manifestDir = dirname(resolve(manifestPath));
    const raw = readFileSync(manifestPath, "utf8");
    const parsed = parseYAML(raw) as PluginManifest;
    if (!parsed || typeof parsed !== "object") {
      throw new PluginError(`manifest at ${manifestPath} is not an object`);
    }
    const unsigned: PluginManifest = {
      ...parsed,
      signature: { ...parsed.signature, signature: "" },
    };
    const sigBytes = b64decode(parsed.signature.signature);
    const identityPub = b64decode(parsed.identity_pub);
    const payload = utf8encode(canonicalize(unsigned));
    const ok = await ed25519Verify(identityPub, payload, sigBytes);
    if (!ok) throw new PluginError(`plugin manifest signature invalid: ${parsed.plugin_id}`);

    const entryPath = resolve(manifestDir, parsed.entry);
    if (parsed.kind === "native") {
      const mod = (await import(entryPath)) as { default?: NativePluginEntry; tfPluginEntry?: NativePluginEntry };
      const entryFn = mod.default ?? mod.tfPluginEntry;
      if (typeof entryFn !== "function") {
        throw new PluginError(`native plugin ${parsed.plugin_id} has no default / tfPluginEntry export`);
      }
      const handlers = await entryFn(host);
      const plugin: LoadedPlugin = { manifest: parsed, handlers };
      this.plugins.push(plugin);
      return plugin;
    }
    if (parsed.kind === "wasm") {
      const wasmBytes = readFileSync(entryPath);
      const allowedImports = new Set<string>(parsed.imports ?? []);
      const importObject = buildRestrictedImports(host, allowedImports);
      const mod = await WebAssembly.instantiate(
        new Uint8Array(wasmBytes),
        importObject,
      );
      const plugin: LoadedPlugin = { manifest: parsed, wasmInstance: mod.instance };
      this.plugins.push(plugin);
      return plugin;
    }
    throw new PluginError(`unknown plugin kind: ${(parsed as PluginManifest).kind}`);
  }

  /** Register every native plugin's handlers onto an RpcServer using the
   *  manifest's declared capability names. */
  registerOn(server: RpcServer): void {
    for (const plugin of this.plugins) {
      if (!plugin.handlers) continue;
      for (const cap of plugin.manifest.capabilities) {
        const handler = plugin.handlers[cap.name];
        if (!handler) continue;
        server.registerUnary(cap.name, cap.name, async (req, ctx) =>
          handler(req, { caller: ctx.callerActor }),
        );
      }
    }
  }

  list(): LoadedPlugin[] {
    return [...this.plugins];
  }
}

/** Build the restricted imports object. Each top-level import namespace (e.g.
 *  "env") maps to an object whose keys are only the names in `allowedImports`.
 *  A manifest's import name of "env.log" is split on "." and produces:
 *   { env: { log: host.log } } */
function buildRestrictedImports(
  host: PluginHost,
  allowed: Set<string>,
): WebAssembly.Imports {
  const result: Record<string, Record<string, WebAssembly.ImportValue>> = {};
  for (const spec of allowed) {
    const parts = spec.split(".");
    if (parts.length !== 2) continue;
    const [ns, name] = parts as [string, string];
    const hostValue = host[name] ?? host[spec];
    if (hostValue === undefined) continue;
    const entry = result[ns] ?? {};
    entry[name] = hostValue as WebAssembly.ImportValue;
    result[ns] = entry;
  }
  return result;
}

export function verifyPluginSignature(
  manifestPath: string,
): Promise<{ plugin_id: string; ok: boolean; reason?: string }> {
  return (async () => {
    const raw = readFileSync(manifestPath, "utf8");
    const parsed = parseYAML(raw) as PluginManifest;
    try {
      const unsigned: PluginManifest = {
        ...parsed,
        signature: { ...parsed.signature, signature: "" },
      };
      const sigBytes = b64decode(parsed.signature.signature);
      const identityPub = b64decode(parsed.identity_pub);
      const payload = utf8encode(canonicalize(unsigned));
      const ok = await ed25519Verify(identityPub, payload, sigBytes);
      return { plugin_id: parsed.plugin_id, ok };
    } catch (err) {
      if (err instanceof CryptoError) return { plugin_id: parsed.plugin_id, ok: false, reason: err.message };
      throw err;
    }
  })();
}
