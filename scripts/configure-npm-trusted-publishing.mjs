#!/usr/bin/env node
import fs from "node:fs";
import os from "node:os";
import path from "node:path";

const REGISTRY = "https://registry.npmjs.org";
const DEFAULT_REPOSITORY = "KodyDennon/TrustForge";
const DEFAULT_WORKFLOW = "release.yml";
const DEFAULT_PERMISSIONS = ["createPackage"];

function usage() {
  console.log(`Configure npm trusted publishing for TrustForge packages.

Usage:
  NPM_TOKEN=... NPM_OTP=123456 node scripts/configure-npm-trusted-publishing.mjs [options]

Options:
  --dry-run             Print intended changes without calling npm.
  --replace             Delete mismatched existing trusted publisher configs.
  --package <name>      Configure one package instead of all npm workspaces.
  --repository <owner/repo>
                        GitHub repository claim. Default: ${DEFAULT_REPOSITORY}
  --workflow <file>     GitHub Actions workflow filename. Default: ${DEFAULT_WORKFLOW}
  --permissions <csv>   npm trust permissions. Default: ${DEFAULT_PERMISSIONS.join(",")}

Environment:
  NPM_TOKEN             npm access token with write access to every package.
  NPM_OTP               Current npm two-factor one-time password.
  NPM_TRUST_REPOSITORY  Optional default for --repository.
  NPM_TRUST_WORKFLOW    Optional default for --workflow.
  NPM_TRUST_PERMISSIONS Optional default for --permissions.

The npm trust API requires 2FA for read/write operations. The script never
prints the token or OTP.
`);
}

function parseArgs(argv) {
  const args = {
    dryRun: false,
    replace: false,
    onlyPackage: null,
    repository: process.env.NPM_TRUST_REPOSITORY || DEFAULT_REPOSITORY,
    workflow: process.env.NPM_TRUST_WORKFLOW || DEFAULT_WORKFLOW,
    permissions: (process.env.NPM_TRUST_PERMISSIONS || DEFAULT_PERMISSIONS.join(","))
      .split(",")
      .map((permission) => permission.trim())
      .filter(Boolean),
  };

  for (let i = 0; i < argv.length; i += 1) {
    const arg = argv[i];
    if (arg === "--help" || arg === "-h") {
      usage();
      process.exit(0);
    }
    if (arg === "--dry-run") {
      args.dryRun = true;
      continue;
    }
    if (arg === "--replace") {
      args.replace = true;
      continue;
    }
    if (arg === "--package") {
      args.onlyPackage = requireValue(argv, ++i, arg);
      continue;
    }
    if (arg === "--repository") {
      args.repository = requireValue(argv, ++i, arg);
      continue;
    }
    if (arg === "--workflow") {
      args.workflow = requireValue(argv, ++i, arg);
      continue;
    }
    if (arg === "--permissions") {
      args.permissions = requireValue(argv, ++i, arg)
        .split(",")
        .map((permission) => permission.trim())
        .filter(Boolean);
      continue;
    }
    throw new Error(`unknown argument: ${arg}`);
  }

  if (!/^[^/\s]+\/[^/\s]+$/.test(args.repository)) {
    throw new Error(`invalid GitHub repository: ${args.repository}`);
  }
  if (!/^[^/\s]+\.ya?ml$/.test(args.workflow)) {
    throw new Error(`workflow must be a filename ending in .yml or .yaml: ${args.workflow}`);
  }
  for (const permission of args.permissions) {
    if (!["createPackage", "createStagedPackage"].includes(permission)) {
      throw new Error(`unsupported npm trust permission: ${permission}`);
    }
  }
  if (args.permissions.length === 0) {
    throw new Error("at least one permission is required");
  }

  return args;
}

function requireValue(argv, index, flag) {
  const value = argv[index];
  if (!value || value.startsWith("--")) {
    throw new Error(`${flag} requires a value`);
  }
  return value;
}

function readJson(file) {
  return JSON.parse(fs.readFileSync(file, "utf8"));
}

function workspacePackageDirs(rootDir) {
  const rootPackage = readJson(path.join(rootDir, "package.json"));
  const dirs = new Set();

  if (!rootPackage.private && rootPackage.name) {
    dirs.add(rootDir);
  }

  for (const pattern of rootPackage.workspaces || []) {
    if (!pattern.endsWith("/*")) {
      throw new Error(`unsupported workspace pattern: ${pattern}`);
    }
    const parent = path.join(rootDir, pattern.slice(0, -2));
    if (!fs.existsSync(parent)) {
      continue;
    }
    for (const entry of fs.readdirSync(parent, { withFileTypes: true })) {
      if (!entry.isDirectory()) {
        continue;
      }
      const candidate = path.join(parent, entry.name);
      if (fs.existsSync(path.join(candidate, "package.json"))) {
        dirs.add(candidate);
      }
    }
  }

  return [...dirs].sort();
}

function packageNames(rootDir, onlyPackage) {
  if (onlyPackage) {
    return [onlyPackage];
  }

  const names = [];
  for (const dir of workspacePackageDirs(rootDir)) {
    const pkg = readJson(path.join(dir, "package.json"));
    if (!pkg.private && pkg.name) {
      names.push(pkg.name);
    }
  }
  return [...new Set(names)].sort();
}

function trustedConfig(args) {
  return {
    type: "github",
    claims: {
      repository: args.repository,
      workflow_ref: {
        file: args.workflow,
      },
    },
    permissions: args.permissions,
  };
}

function sameConfig(left, right) {
  return (
    left?.type === right.type &&
    left?.claims?.repository === right.claims.repository &&
    left?.claims?.workflow_ref?.file === right.claims.workflow_ref.file &&
    normalizeArray(left?.permissions).join("\0") === normalizeArray(right.permissions).join("\0") &&
    (left?.claims?.environment || "") === (right.claims.environment || "")
  );
}

function normalizeArray(values) {
  return [...(values || [])].sort();
}

function loadToken(rootDir) {
  if (process.env.NPM_TOKEN) {
    return process.env.NPM_TOKEN.trim();
  }

  for (const file of [path.join(rootDir, ".npmrc"), path.join(os.homedir(), ".npmrc")]) {
    if (!fs.existsSync(file)) {
      continue;
    }
    for (const line of fs.readFileSync(file, "utf8").split(/\r?\n/)) {
      const match = line.match(/^\/\/registry\.npmjs\.org\/:_authToken=(.+)$/);
      if (match?.[1]) {
        return match[1].trim();
      }
    }
  }

  throw new Error("NPM_TOKEN is required, or an npm auth token must exist in .npmrc");
}

async function npmJson(method, packageName, token, otp, body) {
  const response = await fetch(`${REGISTRY}/-/package/${encodeURIComponent(packageName)}/trust`, {
    method,
    headers: {
      Authorization: `Bearer ${token}`,
      "Content-Type": "application/json",
      "User-Agent": "TrustForge trusted-publishing setup",
      "npm-otp": otp,
    },
    body: body === undefined ? undefined : JSON.stringify(body),
  });
  const text = await response.text();
  let data = null;
  if (text) {
    try {
      data = JSON.parse(text);
    } catch {
      data = { message: text };
    }
  }
  if (!response.ok) {
    const message = data?.message || data?.error || text || response.statusText;
    throw new Error(`${method} ${packageName} failed (${response.status}): ${message}`);
  }
  return data;
}

async function npmDelete(packageName, configId, token, otp) {
  const response = await fetch(
    `${REGISTRY}/-/package/${encodeURIComponent(packageName)}/trust/${encodeURIComponent(configId)}`,
    {
      method: "DELETE",
      headers: {
        Authorization: `Bearer ${token}`,
        "User-Agent": "TrustForge trusted-publishing setup",
        "npm-otp": otp,
      },
    },
  );
  if (!response.ok) {
    const text = await response.text();
    throw new Error(`DELETE ${packageName}/${configId} failed (${response.status}): ${text}`);
  }
}

async function main() {
  const args = parseArgs(process.argv.slice(2));
  const rootDir = process.cwd();
  const names = packageNames(rootDir, args.onlyPackage);
  const desired = trustedConfig(args);

  if (names.length === 0) {
    throw new Error("no packages found");
  }

  console.log(`Configuring ${names.length} package(s) for ${args.repository} / ${args.workflow}`);

  if (args.dryRun) {
    for (const name of names) {
      console.log(`[dry-run] ${name}: would ensure ${JSON.stringify(desired)}`);
    }
    return;
  }

  const token = loadToken(rootDir);
  const otp = (process.env.NPM_OTP || "").trim();
  if (!otp) {
    throw new Error("NPM_OTP is required because npm trust API operations require 2FA");
  }

  let configured = 0;
  let skipped = 0;
  for (const name of names) {
    const existing = await npmJson("GET", name, token, otp);
    if (existing.some((config) => sameConfig(config, desired))) {
      console.log(`${name}: already configured`);
      skipped += 1;
      continue;
    }

    if (existing.length > 0) {
      if (!args.replace) {
        throw new Error(
          `${name}: has a different trusted publisher config; re-run with --replace to replace it`,
        );
      }
      for (const config of existing) {
        console.log(`${name}: deleting existing config ${config.id}`);
        await npmDelete(name, config.id, token, otp);
      }
    }

    await npmJson("POST", name, token, otp, [desired]);
    console.log(`${name}: configured`);
    configured += 1;
  }

  console.log(`Done. configured=${configured} skipped=${skipped}`);
}

main().catch((error) => {
  console.error(error.message);
  process.exit(1);
});
