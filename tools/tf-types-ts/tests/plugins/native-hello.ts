// A minimal native TrustForge plugin. Receives the PluginHost and returns
// a handler map. The manifest's declared capabilities drive which handlers
// get registered on the RpcServer.

import type { PluginHost, NativePluginHandlers } from "../../src/core/plugin";

export default function tfPluginEntry(host: PluginHost): NativePluginHandlers {
  return {
    "file.read": async (args: unknown, ctx: { caller: string }) => {
      const { path } = args as { path: string };
      host.log(`native plugin received file.read from ${ctx.caller}: ${path}`);
      return { path, contents: `stub contents of ${path}`, size: path.length };
    },
  };
}
