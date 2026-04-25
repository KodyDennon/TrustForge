#!/usr/bin/env bun
/**
 * tf-dashboard CLI — boots the viewer-only dashboard and prints the URL.
 */

import { startDashboard } from "./index.js";

function arg(args: string[], flag: string): string | undefined {
  const i = args.indexOf(flag);
  return i >= 0 ? args[i + 1] : undefined;
}

async function main(): Promise<number> {
  const argv = process.argv.slice(2);
  const daemonUrl = arg(argv, "--daemon") ?? process.env.TF_ADMIN_URL ?? "http://127.0.0.1:8787";
  const port = parseInt(arg(argv, "--port") ?? "0", 10);
  const host = arg(argv, "--host") ?? "127.0.0.1";
  const refreshMs = parseInt(arg(argv, "--refresh-ms") ?? "2000", 10);
  if (!process.env.TF_ADMIN_TOKEN) {
    console.error("warning: TF_ADMIN_TOKEN is not set; daemon admin requests will be rejected");
  }
  const handle = startDashboard({ daemonUrl, port, host, refreshMs });
  console.log(`tf-dashboard listening at ${handle.url}`);
  console.log(`talking to daemon at ${daemonUrl}`);
  await new Promise<void>((resolve) => {
    const stop = () => {
      handle.stop();
      resolve();
    };
    process.on("SIGINT", stop);
    process.on("SIGTERM", stop);
  });
  return 0;
}

const exit = await main();
process.exit(exit);
