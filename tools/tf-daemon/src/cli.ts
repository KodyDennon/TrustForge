#!/usr/bin/env bun
import { runDaemon } from "./index.js";

function arg(args: string[], flag: string): string | undefined {
  const i = args.indexOf(flag);
  return i >= 0 ? args[i + 1] : undefined;
}

async function main(): Promise<number> {
  const [cmd, ...rest] = process.argv.slice(2);
  switch (cmd) {
    case "run": {
      const configPath = arg(rest, "--config");
      if (!configPath) {
        console.error("usage: tf-daemon run --config <daemon.yaml>");
        return 2;
      }
      const passphrase = process.env.TF_VAULT_PASS ?? "";
      if (!passphrase) {
        console.error("error: TF_VAULT_PASS environment variable must be set");
        return 2;
      }
      const handle = await runDaemon({ configPath, passphrase });
      console.log(`tf-daemon listening on port ${handle.port}`);
      console.log(`proof log: ${handle.proofLogPath}`);
      // Run until interrupted.
      await new Promise<void>((resolve) => {
        const signal = () => {
          handle.stop().then(resolve);
        };
        process.on("SIGINT", signal);
        process.on("SIGTERM", signal);
      });
      return 0;
    }
    default:
      console.error("usage: tf-daemon run --config <daemon.yaml>");
      return 2;
  }
}

const exit = await main();
process.exit(exit);
