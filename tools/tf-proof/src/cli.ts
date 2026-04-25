#!/usr/bin/env bun
import { inspectFile } from "./inspect.js";
import { runDerivePubkey, runKeygen } from "./keygen.js";
import { runSignCli } from "./sign.js";
import { verifyFile } from "./verify.js";

function arg(args: string[], flag: string): string | undefined {
  const i = args.indexOf(flag);
  if (i < 0) return undefined;
  return args[i + 1];
}

function flag(args: string[], name: string): boolean {
  return args.includes(name);
}

async function main(): Promise<number> {
  const [cmd, ...rest] = process.argv.slice(2);

  switch (cmd) {
    case "keygen": {
      const out = arg(rest, "--out") ?? ".";
      const { privatePath, publicPath } = await runKeygen(out);
      console.log(`private: ${privatePath}`);
      console.log(`public:  ${publicPath}`);
      return 0;
    }
    case "derive-pubkey": {
      const key = arg(rest, "--key");
      if (!key) {
        console.error("usage: tf-proof derive-pubkey --key <file> [--out <file>]");
        return 2;
      }
      const out = arg(rest, "--out");
      const res = await runDerivePubkey(key, out);
      console.log(res);
      return 0;
    }
    case "sign": {
      const events = arg(rest, "--events");
      const key = arg(rest, "--key");
      const signer = arg(rest, "--signer");
      const out = arg(rest, "--out");
      if (!events || !key || !signer) {
        console.error("usage: tf-proof sign --events <file> --key <file> --signer <actor-id> [--out <file>]");
        return 2;
      }
      return await runSignCli({ eventsFile: events, keyFile: key, signerActorId: signer, out });
    }
    case "verify": {
      const file = rest.find((a) => !a.startsWith("--"));
      const key = arg(rest, "--key");
      if (!file) {
        console.error("usage: tf-proof verify <file.tfproof|file.tflog> [--key <pubkey-file>]");
        return 2;
      }
      const report = await verifyFile(file, key);
      console.log(JSON.stringify(report, null, 2));
      return report.ok ? 0 : 1;
    }
    case "inspect": {
      const file = rest.find((a) => !a.startsWith("--"));
      if (!file) {
        console.error("usage: tf-proof inspect <file.tfproof|file.tflog> [--events]");
        return 2;
      }
      const output = inspectFile(file, flag(rest, "--events"));
      console.log(output);
      return 0;
    }
    default:
      console.error("usage: tf-proof <keygen|derive-pubkey|sign|verify|inspect> [args]");
      return 2;
  }
}

const exit = await main();
process.exit(exit);
