// Demo plugin used by the full-stack test. Declares handlers for
// file.read and file.write; file.write requires human approval per the
// contract so we prove the plugin only runs when approval is granted.

import type { NativePluginHandlers, PluginHost } from "tf-types";

export default function tfPluginEntry(host: PluginHost): NativePluginHandlers {
  const writes: string[] = [];
  (host as unknown as { writes: string[] }).writes = writes;
  return {
    "file.read": async (args: unknown, ctx: { caller: string }) => {
      const { path } = args as { path: string };
      host.log(`plugin.file.read caller=${ctx.caller} path=${path}`);
      return { path, contents: `plugin contents of ${path}`, size: path.length };
    },
    "file.write": async (args: unknown, ctx: { caller: string }) => {
      const { path, contents } = args as { path: string; contents: string };
      host.log(`plugin.file.write caller=${ctx.caller} path=${path} size=${contents.length}`);
      writes.push(path);
      return { path, size: contents.length };
    },
    // Registered so incoming file.delete reaches the CapabilityEnforcer
    // (which consults the contract's forbidden list). The handler must
    // never actually execute — guard should deny first.
    "file.delete": async () => {
      throw new Error("file.delete handler should not run; contract forbids it");
    },
  };
}
