#!/usr/bin/env bun
/**
 * Child-process plugin sandbox helper. Spawned by `loadNativeInChildProcess`
 * (in `plugin.ts`) with a clean environment + platform sandbox profile
 * already applied (sandbox-exec on macOS, refused on Windows; Linux uses
 * a wrapper script when available). The helper:
 *
 *   1. Reads `init` over stdin: `{ kind: "init", entryPath, manifest }`.
 *   2. `await import(entryPath)`; calls the default / `tfPluginEntry`
 *      export with a host stub that posts `log` messages back over
 *      stdout. The host stub does NOT carry any other capabilities;
 *      every call back into the parent must go through the explicit
 *      JSON-line protocol below.
 *   3. Replies with `{ kind: "ready", methods: [...] }`.
 *   4. Handles `call` requests `{ kind: "call", id, method, args, ctx }`
 *      and replies with `{ kind: "result"|"error", id, ... }`.
 *
 * Wire format: one JSON object per line on stdin / stdout. Stdin EOF
 * terminates the helper.
 */

type IncomingMessage =
  | { kind: "init"; entryPath: string }
  | { kind: "call"; id: string; method: string; args: unknown; ctx: { caller: string } };

type OutgoingMessage =
  | { kind: "ready"; methods: string[] }
  | { kind: "log"; message: unknown }
  | { kind: "result"; id: string; result: unknown }
  | { kind: "error"; id?: string; error: string };

let entry: ((host: { log: (m: unknown) => void }) => unknown) | undefined;
let handlers: Record<string, (args: unknown, ctx: { caller: string }) => unknown | Promise<unknown>> | undefined;

function send(msg: OutgoingMessage): void {
  process.stdout.write(JSON.stringify(msg) + "\n");
}

async function handle(msg: IncomingMessage): Promise<void> {
  if (msg.kind === "init") {
    const mod = (await import(msg.entryPath)) as Record<string, unknown>;
    const fn = (mod.default ?? mod.tfPluginEntry) as
      | ((host: { log: (m: unknown) => void }) => unknown)
      | undefined;
    if (typeof fn !== "function") {
      send({ kind: "error", error: "plugin has no default / tfPluginEntry export" });
      return;
    }
    entry = fn;
    const result = await Promise.resolve(
      entry({ log: (m: unknown) => send({ kind: "log", message: m }) }),
    );
    handlers = result as typeof handlers;
    if (!handlers || typeof handlers !== "object") {
      send({ kind: "error", error: "plugin entry did not return a handler map" });
      return;
    }
    send({ kind: "ready", methods: Object.keys(handlers) });
    return;
  }
  if (msg.kind === "call") {
    if (!handlers) {
      send({ kind: "error", id: msg.id, error: "plugin not initialized" });
      return;
    }
    const fn = handlers[msg.method];
    if (typeof fn !== "function") {
      send({ kind: "error", id: msg.id, error: `unknown method: ${msg.method}` });
      return;
    }
    try {
      const r = await Promise.resolve(fn(msg.args, msg.ctx));
      send({ kind: "result", id: msg.id, result: r });
    } catch (err) {
      send({ kind: "error", id: msg.id, error: (err as Error).message });
    }
    return;
  }
}

let buffer = "";
process.stdin.setEncoding("utf8");
process.stdin.on("data", (chunk: string) => {
  buffer += chunk;
  let idx: number;
  while ((idx = buffer.indexOf("\n")) >= 0) {
    const line = buffer.slice(0, idx);
    buffer = buffer.slice(idx + 1);
    if (!line) continue;
    let msg: IncomingMessage;
    try {
      msg = JSON.parse(line) as IncomingMessage;
    } catch (err) {
      send({ kind: "error", error: `bad json line: ${(err as Error).message}` });
      continue;
    }
    void handle(msg).catch((err: Error) =>
      send({ kind: "error", error: err.message ?? String(err) }),
    );
  }
});
process.stdin.on("end", () => process.exit(0));
