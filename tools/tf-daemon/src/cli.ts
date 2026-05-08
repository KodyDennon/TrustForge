#!/usr/bin/env bun
import { existsSync, readFileSync } from "node:fs";
import { parse as parseYAML } from "yaml";
import { BUILTIN_PROFILES, canonicalize } from "tf-types";
import { runDaemon } from "./index.js";

function arg(args: string[], flag: string): string | undefined {
  const i = args.indexOf(flag);
  return i >= 0 ? args[i + 1] : undefined;
}

function has(args: string[], flag: string): boolean {
  return args.includes(flag);
}

function loadConfig(path: string): Record<string, any> {
  return parseYAML(readFileSync(path, "utf8")) as Record<string, any>;
}

function validateConfig(path: string, config: Record<string, any>): string[] {
  const errors: string[] = [];
  if (config.daemon_version !== "1") errors.push("daemon_version must be \"1\"");
  if (typeof config.self_actor !== "string" || config.self_actor.length === 0) {
    errors.push("self_actor is required");
  }
  if (!config.listen || typeof config.listen !== "object") {
    errors.push("listen is required");
  } else if (!["websocket", "tcp", "tls"].includes(config.listen.kind)) {
    errors.push("listen.kind must be websocket, tcp, or tls");
  }
  if (!config.vault || typeof config.vault.path !== "string" || config.vault.path.length === 0) {
    errors.push("vault.path is required");
  } else if (!existsSync(config.vault.path)) {
    errors.push(`vault.path does not exist: ${config.vault.path}`);
  }
  if (typeof config.contract_path !== "string" || config.contract_path.length === 0) {
    errors.push("contract_path is required");
  } else if (!existsSync(config.contract_path)) {
    errors.push(`contract_path does not exist: ${config.contract_path}`);
  }
  if (typeof config.proof_log_path !== "string" || config.proof_log_path.length === 0) {
    errors.push("proof_log_path is required");
  }
  if (config.profile && !BUILTIN_PROFILES[config.profile as keyof typeof BUILTIN_PROFILES]) {
    errors.push(`unknown profile: ${config.profile}`);
  }
  if (config.http) {
    const tcpAuth = config.http.tcp?.auth;
    const unixAuth = config.http.unix?.auth;
    if (tcpAuth && tcpAuth !== "bearer") errors.push("http.tcp.auth must be bearer");
    if (unixAuth && unixAuth !== "local-peer") errors.push("http.unix.auth must be local-peer");
  }
  void path;
  return errors;
}

function effectiveConfig(config: Record<string, any>): Record<string, any> {
  const admin = config.admin
    ? {
        enabled: !!config.admin.enabled,
        token_env: config.admin.token_env ?? "TF_ADMIN_TOKEN",
        token: "<redacted>",
      }
    : { enabled: false, token_env: "TF_ADMIN_TOKEN", token: "<redacted>" };
  return {
    ...config,
    admin,
    http: config.http ?? {
      tcp: { enabled: true, bind: "127.0.0.1", port: 8642, auth: "bearer" },
      unix: { enabled: true, path: "/run/trustforge/decide.sock", auth: "local-peer" },
    },
  };
}

async function main(): Promise<number> {
  const [cmd, ...rest] = process.argv.slice(2);
  switch (cmd) {
    case "run": {
      const configPath = arg(rest, "--config");
      if (!configPath) {
        console.error("usage: tf-daemon run --config <daemon.yaml> [--dry-run|--print-config]");
        return 2;
      }
      const config = loadConfig(configPath);
      const errors = validateConfig(configPath, config);
      if (errors.length > 0) {
        for (const e of errors) console.error(`error: ${e}`);
        return 2;
      }
      if (has(rest, "--dry-run")) {
        console.log("config ok");
        return 0;
      }
      if (has(rest, "--print-config")) {
        console.log(canonicalize(effectiveConfig(config)));
        return 0;
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
