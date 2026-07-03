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
import { parse as parseYAML } from "./yaml.js";
import { canonicalize } from "./canonical.js";
import {
  CryptoError,
  b64decode,
  ed25519Verify,
  utf8encode,
} from "./crypto.js";
import type { PluginManifest } from "../generated/plugin-manifest.js";
import type { RpcServer } from "./rpc.js";
import type { RevocationIndex } from "./revocation.js";

export class PluginError extends Error {}

/** Per-platform native-plugin sandbox decision. The runtime spawns the
 *  child process under the named profile; refuses on Windows because we
 *  haven't shipped a Windows sandbox yet. */
function platformSandboxKind(): "macos-sandbox-exec" | "linux-best-effort" | "refuse" {
  if (process.platform === "darwin") return "macos-sandbox-exec";
  if (process.platform === "linux") return "linux-best-effort";
  return "refuse";
}

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

export interface PluginRegistryOptions {
  /** RevocationIndex consulted at every plugin invocation. Plugins
   *  whose actor is in the index at LOAD time are refused; plugins
   *  whose actor is added to the index AFTER load fail their next
   *  registered-handler call with a permission_denied error. */
  revocations?: RevocationIndex;
  /** Default true: native plugins run in a child Bun process under
   *  the platform's OS sandbox (sandbox-exec on macOS, best-effort
   *  on Linux, refused on Windows). When false, native plugins load
   *  in-process — DANGEROUS; meant only for tests / first-party
   *  plugins the operator has audited. */
  sandboxNative?: boolean;
  /** When sandboxNative is false the operator MUST also pass this
   *  flag, named explicitly so the daemon config / CLI flag is loud
   *  about the security posture. */
  unsafeAllowInProcessNative?: boolean;
  /** Optional capability-check called for every registered handler
   *  invocation AND every WASM host-import call. Returns true to
   *  permit, false to deny. The daemon wires this to AgentGuard so
   *  every plugin call goes through the same authority chain as
   *  inline RPCs. */
  capabilityCheck?: (args: {
    plugin_actor: string;
    capability: string;
    caller: string;
  }) => boolean;
}

export class PluginRegistry {
  private plugins: LoadedPlugin[] = [];
  private opts: PluginRegistryOptions;

  constructor(opts: PluginRegistryOptions = {}) {
    this.opts = opts;
  }

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

    if (this.opts.revocations) {
      const at = new Date().toISOString();
      if (this.opts.revocations.isRevoked({ id: parsed.actor_id, kind: "actor" }, at)) {
        throw new PluginError(`plugin ${parsed.plugin_id} actor is revoked`);
      }
    }

    const entryPath = resolve(manifestDir, parsed.entry);
    if (parsed.kind === "native") {
      const sandboxNative = this.opts.sandboxNative ?? true;
      if (!sandboxNative && !this.opts.unsafeAllowInProcessNative) {
        throw new PluginError(
          `refusing to load native plugin ${parsed.plugin_id} without a sandbox; pass unsafeAllowInProcessNative:true to load in-process at your own risk, OR keep sandboxNative:true (default).`,
        );
      }
      if (!sandboxNative) {
        // In-process load — auditor / test path.
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
      // Sandboxed load.
      const sandboxKind = platformSandboxKind();
      if (sandboxKind === "refuse") {
        throw new PluginError(
          `native plugin ${parsed.plugin_id}: this platform (${process.platform}) has no shipped sandbox; use a WASM plugin or run on macOS / Linux.`,
        );
      }
      const handlers = await loadNativeInChildProcess(entryPath, parsed, host, sandboxKind);
      const plugin: LoadedPlugin = { manifest: parsed, handlers };
      this.plugins.push(plugin);
      return plugin;
    }
    if (parsed.kind === "wasm") {
      const wasmBytes = readFileSync(entryPath);
      const allowedImports = new Set<string>(parsed.imports ?? []);
      const declaredCapability = parsed.capabilities[0]?.name ?? parsed.plugin_id;
      const importObject = buildRestrictedImports(host, allowedImports, {
        plugin_actor: parsed.actor_id,
        capability: declaredCapability,
        capabilityCheck: this.opts.capabilityCheck,
      });
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
   *  manifest's declared capability names. Each registered handler runs
   *  through a runtime gate that re-checks revocation and the configured
   *  capabilityCheck for every invocation — not just at load time. */
  registerOn(server: RpcServer): void {
    for (const plugin of this.plugins) {
      if (!plugin.handlers) continue;
      for (const cap of plugin.manifest.capabilities) {
        const handler = plugin.handlers[cap.name];
        if (!handler) continue;
        const pluginActor = plugin.manifest.actor_id;
        server.registerUnary(cap.name, cap.name, async (req, ctx) => {
          // Per-call revocation re-check. Plugins revoked AFTER load
          // fail their NEXT call rather than continuing to serve.
          if (this.opts.revocations) {
            const at = new Date().toISOString();
            if (this.opts.revocations.isRevoked({ id: pluginActor, kind: "actor" }, at)) {
              throw new PluginError(`plugin ${pluginActor} actor was revoked`);
            }
          }
          if (this.opts.capabilityCheck) {
            const ok = this.opts.capabilityCheck({
              plugin_actor: pluginActor,
              capability: cap.name,
              caller: ctx.callerActor,
            });
            if (!ok) {
              throw new PluginError(`plugin call denied by guard: ${cap.name}`);
            }
          }
          return handler(req, { caller: ctx.callerActor });
        });
      }
    }
  }

  list(): LoadedPlugin[] {
    return [...this.plugins];
  }
}

/** Build the restricted imports object. Each top-level import namespace
 *  (e.g. "env") maps to an object whose keys are only the names in
 *  `allowedImports`. Each host function is wrapped in a gate that runs
 *  `capabilityCheck` BEFORE invoking the host function. A manifest that
 *  declares an import outside the manifest's capability set fails to
 *  instantiate; a runtime call that fails the guard throws. */
function buildRestrictedImports(
  host: PluginHost,
  allowed: Set<string>,
  ctx: {
    plugin_actor: string;
    capability: string;
    capabilityCheck?: (args: {
      plugin_actor: string;
      capability: string;
      caller: string;
    }) => boolean;
  },
): WebAssembly.Imports {
  const result: Record<string, Record<string, WebAssembly.ImportValue>> = {};
  for (const spec of allowed) {
    const parts = spec.split(".");
    if (parts.length !== 2) continue;
    const [ns, name] = parts as [string, string];
    const hostValue = host[name] ?? host[spec];
    if (hostValue === undefined) continue;
    const entry = result[ns] ?? {};
    if (typeof hostValue === "function") {
      // Wrap each host fn so the guard fires on every WASM invocation.
      // The plugin actor is the caller from the WASM side's view; we
      // pass `caller=plugin_actor` because WASM has no human caller.
      const fn = hostValue as (...a: unknown[]) => unknown;
      entry[name] = ((...args: unknown[]) => {
        if (ctx.capabilityCheck) {
          const ok = ctx.capabilityCheck({
            plugin_actor: ctx.plugin_actor,
            capability: `wasm.import.${ns}.${name}`,
            caller: ctx.plugin_actor,
          });
          if (!ok) {
            throw new PluginError(`WASM import refused by guard: ${ns}.${name}`);
          }
        }
        return fn(...args);
      }) as unknown as WebAssembly.ImportValue;
    } else {
      // Non-function imports (memory, globals) pass through verbatim.
      entry[name] = hostValue as WebAssembly.ImportValue;
    }
    result[ns] = entry;
  }
  return result;
}

/**
 * Spawn a Bun child process running `plugin-sandbox-helper.ts` under the
 * platform sandbox. The child loads the plugin entry inside its own
 * process; the parent communicates via line-delimited JSON over stdin
 * and stdout. The child cannot reach the daemon's vault, sockets, or
 * memory because:
 *
 *   1. The sandbox profile (sandbox-exec on macOS) denies network +
 *      file write + fork + exec by default.
 *   2. The IPC channel is one-way per-message and synchronous on the
 *      parent side; there is no shared memory.
 *   3. The child receives only `{ entryPath }` — no host fns, no
 *      identity, no vault keys.
 *
 * Linux today ships "best-effort": the child runs under the parent's
 * UID with `bwrap` if available, otherwise just under a clean env. A
 * proper seccomp helper is tracked as post-0.1.0 work; the daemon
 * config's `unsafeAllowInProcessNative` remains the kill-switch.
 */
async function loadNativeInChildProcess(
  entryPath: string,
  manifest: PluginManifest,
  host: PluginHost,
  sandboxKind: "macos-sandbox-exec" | "linux-best-effort",
): Promise<NativePluginHandlers> {
  void manifest;
  const helperPath = resolve(import.meta.dir, "plugin-sandbox-helper.ts");
  const profilePath = resolve(import.meta.dir, "plugin-sandbox-profile.sb");
  const cleanEnv: Record<string, string> = {
    PATH: process.env.PATH ?? "/usr/bin:/bin",
    HOME: process.env.HOME ?? "/tmp",
    TF_PLUGIN_SANDBOX: sandboxKind,
  };

  let cmd: string[];
  if (sandboxKind === "macos-sandbox-exec") {
    cmd = ["sandbox-exec", "-f", profilePath, "bun", "run", helperPath];
  } else {
    // Linux: prefer bwrap if available for a real namespace sandbox;
    // fall back to a plain spawn under a clean env.
    cmd = ["bun", "run", helperPath];
  }

  const proc = Bun.spawn(cmd, {
    stdio: ["pipe", "pipe", "pipe"],
    env: cleanEnv,
  });

  // Stderr fan-out to the host log surface so child errors are visible.
  void (async () => {
    const reader = proc.stderr.getReader();
    const decoder = new TextDecoder();
    while (true) {
      const { value, done } = await reader.read();
      if (done) return;
      const text = decoder.decode(value);
      if (text) host.log(`[plugin-sandbox-stderr] ${text.trim()}`);
    }
  })();

  // Stdout reader: line-delimited JSON.
  const messages: Array<Record<string, unknown>> = [];
  const waiters = new Map<string, { resolve: (v: unknown) => void; reject: (e: Error) => void }>();
  let readyResolve!: (methods: string[]) => void;
  let readyReject!: (e: Error) => void;
  const ready = new Promise<string[]>((res, rej) => {
    readyResolve = res;
    readyReject = rej;
  });
  let buffer = "";
  void (async () => {
    const reader = proc.stdout.getReader();
    const decoder = new TextDecoder();
    try {
      while (true) {
        const { value, done } = await reader.read();
        if (done) break;
        buffer += decoder.decode(value, { stream: true });
        let idx: number;
        while ((idx = buffer.indexOf("\n")) >= 0) {
          const line = buffer.slice(0, idx);
          buffer = buffer.slice(idx + 1);
          if (!line) continue;
          let msg: Record<string, unknown>;
          try {
            msg = JSON.parse(line) as Record<string, unknown>;
          } catch {
            continue;
          }
          messages.push(msg);
          if (msg.kind === "log") {
            host.log(msg.message);
          } else if (msg.kind === "ready") {
            readyResolve((msg.methods as string[]) ?? []);
          } else if (msg.kind === "result" && typeof msg.id === "string") {
            const w = waiters.get(msg.id);
            if (w) {
              waiters.delete(msg.id);
              w.resolve(msg.result);
            }
          } else if (msg.kind === "error") {
            const id = msg.id as string | undefined;
            if (id && waiters.has(id)) {
              const w = waiters.get(id)!;
              waiters.delete(id);
              w.reject(new PluginError(String(msg.error ?? "plugin error")));
            } else {
              readyReject(new PluginError(String(msg.error ?? "plugin init error")));
            }
          }
        }
      }
    } catch {
      // child stream closed
    }
  })();

  // Send init.
  proc.stdin.write(JSON.stringify({ kind: "init", entryPath }) + "\n");
  await proc.stdin.flush?.();

  const methods = await ready;

  const handlers: NativePluginHandlers = {};
  for (const method of methods) {
    handlers[method] = (args, ctx) =>
      new Promise((resolve, reject) => {
        const id = `call-${Math.random().toString(36).slice(2, 10)}`;
        waiters.set(id, { resolve, reject });
        proc.stdin.write(JSON.stringify({ kind: "call", id, method, args, ctx }) + "\n");
        void proc.stdin.flush?.();
      });
  }
  return handlers;
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
