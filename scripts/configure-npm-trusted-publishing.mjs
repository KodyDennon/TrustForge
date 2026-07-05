#!/usr/bin/env node
import childProcess from "node:child_process";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";

const REGISTRY = "https://registry.npmjs.org";
const DEFAULT_WORKFLOW = "release.yml";
const DEFAULT_PERMISSIONS = ["createPackage"];
const REQUIRED_REPOSITORY_URL_PREFIX = "git+https://github.com/";
const EXPECTED_PACKAGES = [
  "@trustforge-protocol/auth0",
  "@trustforge-protocol/better-auth",
  "@trustforge-protocol/bun-serve",
  "@trustforge-protocol/clerk",
  "@trustforge-protocol/cli",
  "@trustforge-protocol/conformance",
  "@trustforge-protocol/core",
  "@trustforge-protocol/daemon",
  "@trustforge-protocol/dashboard",
  "@trustforge-protocol/evidence",
  "@trustforge-protocol/express",
  "@trustforge-protocol/fastify",
  "@trustforge-protocol/firebase-auth",
  "@trustforge-protocol/h3",
  "@trustforge-protocol/hono",
  "@trustforge-protocol/iron-session",
  "@trustforge-protocol/kinde",
  "@trustforge-protocol/koa",
  "@trustforge-protocol/logto",
  "@trustforge-protocol/lucia",
  "@trustforge-protocol/nestjs",
  "@trustforge-protocol/next",
  "@trustforge-protocol/next-auth",
  "@trustforge-protocol/packet",
  "@trustforge-protocol/passport",
  "@trustforge-protocol/proof",
  "@trustforge-protocol/remix",
  "@trustforge-protocol/schema",
  "@trustforge-protocol/sdk",
  "@trustforge-protocol/session",
  "@trustforge-protocol/stack-auth",
  "@trustforge-protocol/supabase-auth",
  "@trustforge-protocol/sveltekit",
  "@trustforge-protocol/test-utils",
  "@trustforge-protocol/types",
  "@trustforge-protocol/workos",
];

class NpmApiError extends Error {
  constructor(message, details = {}) {
    super(message);
    this.name = "NpmApiError";
    this.status = details.status;
    this.data = details.data;
    this.headers = details.headers;
  }
}

class WebAuthChallenge extends Error {
  constructor(packageName, challenge) {
    super(`${packageName}: npm requires web/passkey authentication`);
    this.name = "WebAuthChallenge";
    this.packageName = packageName;
    this.challenge = challenge;
  }
}

function usage() {
  console.log(`Configure npm trusted publishing for all TrustForge npm packages.

Usage:
  node scripts/configure-npm-trusted-publishing.mjs [options]

Common:
  node scripts/configure-npm-trusted-publishing.mjs --dry-run
  node scripts/configure-npm-trusted-publishing.mjs
  NPM_OTP=123456 node scripts/configure-npm-trusted-publishing.mjs

Options:
  --dry-run                 Print intended changes without mutating npm.
  --replace                 Delete mismatched existing trusted publisher configs.
  --package <name>          Configure one npm package instead of all workspaces.
  --repository <owner/repo> GitHub repository claim. Default: inferred from gh.
  --workflow <file>         GitHub Actions workflow filename. Default: ${DEFAULT_WORKFLOW}
  --environment <name>      Optional GitHub environment claim.
  --permissions <csv>       npm trust permissions. Default: ${DEFAULT_PERMISSIONS.join(",")}
  --otp <code>              npm OTP. Prefer NPM_OTP to avoid shell history.
  --no-open                 Print passkey URL instead of opening it.
  --no-login                Do not run npm login --auth-type=web on auth failure.
  --no-published-check      Skip npm registry package-existence validation.
  --no-gh-verify            Skip local GitHub workflow validation.
  --no-package-verify       Skip local package repository metadata validation.

Environment:
  NPM_TOKEN                 npm access token with write access to every package.
  NPM_OTP                   Current npm OTP. Passkey users can omit this.
  NPM_TRUST_REPOSITORY      Optional default for --repository.
  NPM_TRUST_WORKFLOW        Optional default for --workflow.
  NPM_TRUST_ENVIRONMENT     Optional default for --environment.
  NPM_TRUST_PERMISSIONS     Optional default for --permissions.

Passkey behavior:
  If NPM_OTP is omitted, the script asks npm for a web/passkey challenge. When
  npm returns authUrl/doneUrl, the script opens authUrl, waits for you to touch
  the passkey in the browser, polls doneUrl for the temporary OTP, then continues
  configuring every package.

The script never prints npm tokens or OTPs.
`);
}

function parseArgs(argv) {
  const args = {
    dryRun: false,
    replace: false,
    onlyPackage: null,
    repository: process.env.NPM_TRUST_REPOSITORY || null,
    workflow: process.env.NPM_TRUST_WORKFLOW || DEFAULT_WORKFLOW,
    environment: process.env.NPM_TRUST_ENVIRONMENT || "",
    permissions: (process.env.NPM_TRUST_PERMISSIONS || DEFAULT_PERMISSIONS.join(","))
      .split(",")
      .map((permission) => permission.trim())
      .filter(Boolean),
    otp: process.env.NPM_OTP || "",
    allowLogin: true,
    openBrowser: true,
    verifyPublished: true,
    verifyGithub: true,
    verifyPackages: true,
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
    if (arg === "--no-open") {
      args.openBrowser = false;
      continue;
    }
    if (arg === "--no-login") {
      args.allowLogin = false;
      continue;
    }
    if (arg === "--no-published-check") {
      args.verifyPublished = false;
      continue;
    }
    if (arg === "--no-gh-verify") {
      args.verifyGithub = false;
      continue;
    }
    if (arg === "--no-package-verify") {
      args.verifyPackages = false;
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
    if (arg === "--environment") {
      args.environment = requireValue(argv, ++i, arg);
      continue;
    }
    if (arg === "--permissions") {
      args.permissions = requireValue(argv, ++i, arg)
        .split(",")
        .map((permission) => permission.trim())
        .filter(Boolean);
      continue;
    }
    if (arg === "--otp") {
      args.otp = requireValue(argv, ++i, arg);
      continue;
    }
    throw new Error(`unknown argument: ${arg}`);
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

function run(command, args, options = {}) {
  try {
    return childProcess
      .execFileSync(command, args, {
        encoding: "utf8",
        stdio: ["ignore", "pipe", options.inheritStderr ? "inherit" : "pipe"],
      })
      .trim();
  } catch (error) {
    if (options.optional) {
      return "";
    }
    const stderr = error.stderr?.toString().trim();
    throw new Error(stderr || `${command} ${args.join(" ")} failed`);
  }
}

function inferRepository() {
  const output = run("gh", ["repo", "view", "--json", "nameWithOwner"], { optional: true });
  if (!output) {
    return null;
  }
  return JSON.parse(output).nameWithOwner || null;
}

function validateArgs(args) {
  if (!args.repository) {
    args.repository = inferRepository();
  }
  if (!args.repository) {
    throw new Error("could not infer GitHub repository; pass --repository owner/repo");
  }
  if (!/^[^/\s]+\/[^/\s]+$/.test(args.repository)) {
    throw new Error(`invalid GitHub repository: ${args.repository}`);
  }
  if (!/^[^/\s]+\.ya?ml$/.test(args.workflow)) {
    throw new Error(`workflow must be a filename ending in .yml or .yaml: ${args.workflow}`);
  }
  if (args.environment && /\s/.test(args.environment)) {
    throw new Error("environment names containing whitespace are not supported by this script");
  }
  for (const permission of args.permissions) {
    if (!["createPackage", "createStagedPackage"].includes(permission)) {
      throw new Error(`unsupported npm trust permission: ${permission}`);
    }
  }
  if (args.permissions.length === 0) {
    throw new Error("at least one permission is required");
  }
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

function workspacePackages(rootDir, onlyPackage) {
  const packages = [];
  for (const dir of workspacePackageDirs(rootDir)) {
    const manifestPath = path.join(dir, "package.json");
    const manifest = readJson(manifestPath);
    if (!manifest.private && manifest.name) {
      packages.push({
        dir,
        manifest,
        manifestPath,
        name: manifest.name,
      });
    }
  }

  const unique = new Map(packages.map((pkg) => [pkg.name, pkg]));
  if (onlyPackage) {
    const pkg = unique.get(onlyPackage);
    if (pkg) {
      return [pkg];
    }
    return [
      {
        dir: rootDir,
        manifest: { name: onlyPackage },
        manifestPath: null,
        name: onlyPackage,
      },
    ];
  }
  return [...unique.values()].sort((left, right) => left.name.localeCompare(right.name));
}

function assertExpectedPackageSet(packages, onlyPackage) {
  if (onlyPackage) {
    if (!EXPECTED_PACKAGES.includes(onlyPackage)) {
      throw new Error(`${onlyPackage} is not in the TrustForge npm trusted-publishing package inventory`);
    }
    return;
  }

  const actual = packages.map((pkg) => pkg.name).sort();
  const expected = [...EXPECTED_PACKAGES].sort();
  const missing = expected.filter((name) => !actual.includes(name));
  const extra = actual.filter((name) => !expected.includes(name));
  if (missing.length > 0 || extra.length > 0) {
    const lines = [];
    if (missing.length > 0) {
      lines.push(`missing expected packages: ${missing.join(", ")}`);
    }
    if (extra.length > 0) {
      lines.push(`unexpected publishable packages: ${extra.join(", ")}`);
    }
    throw new Error(`npm package inventory mismatch; refusing partial trusted-publishing setup:\n${lines.join("\n")}`);
  }
}

function trustedConfig(args) {
  const claims = {
    repository: args.repository,
    workflow_ref: {
      file: args.workflow,
    },
  };
  if (args.environment) {
    claims.environment = args.environment;
  }
  return {
    type: "github",
    claims,
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

function expectedRepositoryUrl(repository) {
  return `${REQUIRED_REPOSITORY_URL_PREFIX}${repository}.git`;
}

function manifestRepositoryUrl(manifest) {
  if (typeof manifest.repository === "string") {
    return manifest.repository;
  }
  return manifest.repository?.url || "";
}

function validatePackageMetadata(packages, args) {
  const expected = expectedRepositoryUrl(args.repository);
  const failures = [];
  for (const pkg of packages) {
    if (!pkg.manifestPath) {
      continue;
    }
    const actual = manifestRepositoryUrl(pkg.manifest);
    if (actual !== expected) {
      failures.push(`${pkg.name}: repository.url is ${JSON.stringify(actual)}, expected ${expected}`);
    }
  }
  if (failures.length > 0) {
    throw new Error(`package repository metadata does not match npm OIDC requirements:\n${failures.join("\n")}`);
  }
}

function validateGithubWorkflow(rootDir, args) {
  const ghRepo = inferRepository();
  if (ghRepo && ghRepo !== args.repository) {
    throw new Error(`gh is pointed at ${ghRepo}, but trusted publishing repository is ${args.repository}`);
  }

  const workflowPath = path.join(rootDir, ".github", "workflows", args.workflow);
  if (!fs.existsSync(workflowPath)) {
    throw new Error(`workflow file does not exist: ${workflowPath}`);
  }

  const workflow = fs.readFileSync(workflowPath, "utf8");
  const checks = [
    [/id-token:\s*write/, "workflow must grant permissions.id-token: write"],
    [/npm\s+publish/, "workflow must run npm publish"],
    [/setup-node@/, "workflow should use actions/setup-node for npm registry setup"],
    [/node-version:\s*['"]?(2[4-9]|2[2-9]\.[1-9]|22\.(1[4-9]|[2-9][0-9]))/, "workflow should use Node 22.14+ or 24+"],
    [/npm\s+install\s+-g\s+npm@latest/, "workflow should install npm@latest for trusted publishing support"],
  ];

  const failures = checks
    .filter(([pattern]) => !pattern.test(workflow))
    .map(([, message]) => message);
  if (failures.length > 0) {
    throw new Error(`GitHub release workflow is not trusted-publishing ready:\n${failures.join("\n")}`);
  }
}

async function validatePublishedPackages(packages) {
  const failures = [];
  for (const pkg of packages) {
    const response = await fetch(`${REGISTRY}/${encodeURIComponent(pkg.name)}`, {
      headers: {
        "User-Agent": "TrustForge trusted-publishing setup",
      },
    });
    if (!response.ok) {
      failures.push(`${pkg.name}: registry lookup failed (${response.status})`);
    }
  }
  if (failures.length > 0) {
    throw new Error(`npm registry package validation failed:\n${failures.join("\n")}`);
  }
}

function tokenConfigFiles(rootDir, preferHome = false) {
  const project = path.join(rootDir, ".npmrc");
  const home = path.join(os.homedir(), ".npmrc");
  return preferHome ? [home, project] : [project, home];
}

function loadToken(rootDir, required = true, preferHome = false) {
  if (process.env.NPM_TOKEN) {
    return process.env.NPM_TOKEN.trim();
  }

  for (const file of tokenConfigFiles(rootDir, preferHome)) {
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

  if (!required) {
    return "";
  }
  throw new Error("NPM_TOKEN is required, or an npm auth token must exist in .npmrc.");
}

function authHeaders(auth, body) {
  const headers = {
    Authorization: `Bearer ${auth.token}`,
    "User-Agent": "TrustForge trusted-publishing setup",
  };
  if (body !== undefined) {
    headers["Content-Type"] = "application/json";
  }
  if (auth.otp) {
    headers["npm-otp"] = auth.otp;
  } else {
    headers["npm-auth-type"] = "web";
    headers["npm-command"] = "trust";
  }
  return headers;
}

async function npmJson(method, packageName, auth, body) {
  const result = await rawNpm(method, packageName, auth, body);
  if (result.ok) {
    return result.data;
  }

  const challenge = extractWebAuthChallenge(result.data, result.headers);
  if (!auth.otp && challenge) {
    throw new WebAuthChallenge(packageName, challenge);
  }

  const message = result.data?.message || result.data?.error || result.text || result.statusText;
  throw new NpmApiError(`${method} ${packageName} failed (${result.status}): ${message}`, {
    data: result.data,
    headers: result.headers,
    status: result.status,
  });
}

async function rawNpm(method, packageName, auth, body) {
  const response = await fetch(`${REGISTRY}/-/package/${encodeURIComponent(packageName)}/trust`, {
    method,
    headers: authHeaders(auth, body),
    body: body === undefined ? undefined : JSON.stringify(body),
  });
  const text = await response.text();
  return responseResult(response, text);
}

async function npmDelete(packageName, configId, auth) {
  const response = await fetch(
    `${REGISTRY}/-/package/${encodeURIComponent(packageName)}/trust/${encodeURIComponent(configId)}`,
    {
      method: "DELETE",
      headers: authHeaders(auth),
    },
  );
  const result = responseResult(response, await response.text());
  if (result.ok) {
    return;
  }

  const challenge = extractWebAuthChallenge(result.data, result.headers);
  if (!auth.otp && challenge) {
    throw new WebAuthChallenge(packageName, challenge);
  }

  const message = result.data?.message || result.data?.error || result.text || result.statusText;
  throw new NpmApiError(`DELETE ${packageName}/${configId} failed (${result.status}): ${message}`, {
    data: result.data,
    headers: result.headers,
    status: result.status,
  });
}

function responseResult(response, text) {
  let data = null;
  if (text) {
    try {
      data = JSON.parse(text);
    } catch {
      data = { message: text };
    }
  }

  const headers = Object.fromEntries(response.headers.entries());
  return {
    data,
    headers,
    ok: response.ok,
    status: response.status,
    statusText: response.statusText,
    text,
  };
}

function extractWebAuthChallenge(data, headers) {
  const authUrl = findUrl(data, ["authUrl", "auth_url", "auth", "url"]) || findUrl(headers, ["npm-notice"]);
  const doneUrl = findUrl(data, ["doneUrl", "done_url", "done", "statusUrl", "status_url"]);
  if (!authUrl && !doneUrl) {
    return null;
  }
  return { authUrl, doneUrl, raw: data };
}

function findUrl(value, preferredKeys = []) {
  const urls = [];
  visit(value, (key, child) => {
    if (typeof child === "string" && /^https?:\/\//.test(child)) {
      const score = preferredKeys.some((preferred) => key.toLowerCase().includes(preferred.toLowerCase()))
        ? 0
        : 1;
      urls.push({ score, url: child });
    }
    if (typeof child === "string") {
      for (const match of child.matchAll(/https?:\/\/[^\s"'<>]+/g)) {
        urls.push({ score: 2, url: match[0] });
      }
    }
  });
  urls.sort((left, right) => left.score - right.score);
  return urls[0]?.url || "";
}

function visit(value, callback, key = "") {
  callback(key, value);
  if (Array.isArray(value)) {
    for (const [index, child] of value.entries()) {
      visit(child, callback, String(index));
    }
    return;
  }
  if (value && typeof value === "object") {
    for (const [childKey, child] of Object.entries(value)) {
      visit(child, callback, childKey);
    }
  }
}

async function resolveWebAuthOtp(challenge, args) {
  if (!challenge.authUrl || !challenge.doneUrl) {
    throw new Error(
      "npm requested web/passkey auth, but did not return both authUrl and doneUrl. Re-run with NPM_OTP if your account has TOTP fallback.",
    );
  }

  console.log("npm requested passkey/WebAuthn confirmation.");
  console.log(`Open: ${challenge.authUrl}`);
  if (args.openBrowser) {
    openUrl(challenge.authUrl);
  }

  const deadline = Date.now() + 180_000;
  while (Date.now() < deadline) {
    const otp = await pollDoneUrl(challenge.doneUrl);
    if (otp) {
      console.log("Passkey confirmation accepted by npm.");
      return otp;
    }
    await sleep(2_000);
  }
  throw new Error("timed out waiting for npm passkey confirmation");
}

function openUrl(url) {
  const command =
    process.platform === "darwin" ? "open" : process.platform === "win32" ? "cmd" : "xdg-open";
  const args = process.platform === "win32" ? ["/c", "start", "", url] : [url];
  const result = childProcess.spawnSync(command, args, { stdio: "ignore" });
  if (result.error || result.status !== 0) {
    console.log("Could not open browser automatically; use the URL above.");
  }
}

async function pollDoneUrl(doneUrl) {
  const response = await fetch(doneUrl, {
    headers: {
      "User-Agent": "TrustForge trusted-publishing setup",
    },
  });
  const text = await response.text();
  if (!response.ok && response.status !== 202 && response.status !== 400) {
    return "";
  }

  let data = null;
  if (text) {
    try {
      data = JSON.parse(text);
    } catch {
      data = { message: text };
    }
  }
  return findOtp(data) || findOtp(text);
}

function findOtp(value) {
  let found = "";
  visit(value, (key, child) => {
    if (found || typeof child !== "string") {
      return;
    }
    if (/otp|code|token/i.test(key)) {
      const preferred = child.match(/\b\d{6,16}\b/);
      if (preferred) {
        found = preferred[0];
      }
    }
    const fallback = child.match(/\b\d{16}\b/);
    if (fallback) {
      found = fallback[0];
    }
  });
  return found;
}

function sleep(ms) {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

async function withWebAuthRetry(operation, auth, args) {
  try {
    return await operation();
  } catch (error) {
    if (error instanceof WebAuthChallenge) {
      auth.otp = await resolveWebAuthOtp(error.challenge, args);
      return operation();
    }
    if (shouldAttemptNpmLogin(error, auth, args)) {
      await runInteractiveNpmLogin();
      const token = loadToken(auth.rootDir, true, true);
      if (token === auth.token) {
        throw new Error("npm login completed, but the npm auth token did not change; refusing to retry with the same token");
      }
      auth.token = token;
      auth.loginAttempted = true;
      auth.otp = "";
      return operation();
    }
    if (error instanceof NpmApiError && error.status === 403 && !auth.otp && !args.allowLogin) {
      throw new Error(
        `${error.message}\nPasskey setup needs an npm web-login token here. Re-run without --no-login, or run npm login --auth-type=web first.`,
      );
    }
    if (!(error instanceof WebAuthChallenge)) {
      throw error;
    }
  }
}

function shouldAttemptNpmLogin(error, auth, args) {
  return (
    args.allowLogin &&
    !process.env.NPM_TOKEN &&
    !auth.otp &&
    !auth.loginAttempted &&
    error instanceof NpmApiError &&
    (error.status === 401 || error.status === 403)
  );
}

async function runInteractiveNpmLogin() {
  console.log("npm trust API rejected the current token. Starting npm web login for passkey authentication...");
  const result = childProcess.spawnSync(
    "npm",
    ["login", "--auth-type=web", "--registry", REGISTRY],
    {
      stdio: "inherit",
    },
  );
  if (result.error) {
    throw result.error;
  }
  if (result.status !== 0) {
    throw new Error(`npm login failed with exit code ${result.status}`);
  }
  console.log("npm web login completed; retrying trusted publishing setup with the refreshed token.");
}

async function configurePackage(pkg, desired, auth, args) {
  const existing = await withWebAuthRetry(() => npmJson("GET", pkg.name, auth), auth, args);
  if (existing.some((config) => sameConfig(config, desired))) {
    console.log(`${pkg.name}: already configured`);
    return "skipped";
  }

  if (existing.length > 0) {
    if (!args.replace) {
      throw new Error(`${pkg.name}: has a different trusted publisher config; re-run with --replace to replace it`);
    }
    for (const config of existing) {
      console.log(`${pkg.name}: deleting existing config ${config.id}`);
      await withWebAuthRetry(() => npmDelete(pkg.name, config.id, auth), auth, args);
    }
  }

  await withWebAuthRetry(() => npmJson("POST", pkg.name, auth, [desired]), auth, args);
  console.log(`${pkg.name}: configured`);
  return "configured";
}

async function verifyConfiguredPackages(packages, desired, auth, args) {
  const failures = [];
  for (const pkg of packages) {
    const configs = await withWebAuthRetry(() => npmJson("GET", pkg.name, auth), auth, args);
    if (!configs.some((config) => sameConfig(config, desired))) {
      failures.push(pkg.name);
    }
  }
  if (failures.length > 0) {
    throw new Error(`trusted publishing verification failed for: ${failures.join(", ")}`);
  }
}

async function main() {
  const args = parseArgs(process.argv.slice(2));
  validateArgs(args);

  const rootDir = process.cwd();
  const packages = workspacePackages(rootDir, args.onlyPackage);
  const desired = trustedConfig(args);

  if (packages.length === 0) {
    throw new Error("no packages found");
  }
  assertExpectedPackageSet(packages, args.onlyPackage);

  if (args.verifyGithub) {
    validateGithubWorkflow(rootDir, args);
  }
  if (args.verifyPackages && !args.onlyPackage) {
    validatePackageMetadata(packages, args);
  }
  if (args.verifyPublished) {
    await validatePublishedPackages(packages);
  }

  console.log(`Repository: ${args.repository}`);
  console.log(`Workflow: .github/workflows/${args.workflow}`);
  console.log(`Permissions: ${args.permissions.join(",")}`);
  if (args.environment) {
    console.log(`Environment: ${args.environment}`);
  }
  console.log(`Packages: ${packages.length}`);

  if (args.dryRun) {
    for (const pkg of packages) {
      console.log(`[dry-run] ${pkg.name}: would ensure ${JSON.stringify(desired)}`);
    }
    return;
  }

  const auth = {
    loginAttempted: false,
    otp: args.otp.trim(),
    rootDir,
    token: loadToken(rootDir, false),
  };
  if (!auth.token) {
    if (!args.allowLogin) {
      throw new Error("NPM_TOKEN is required, or an npm auth token must exist in .npmrc");
    }
    await runInteractiveNpmLogin();
    auth.loginAttempted = true;
    auth.token = loadToken(rootDir);
  }

  let configured = 0;
  let skipped = 0;
  for (const pkg of packages) {
    const result = await configurePackage(pkg, desired, auth, args);
    if (result === "configured") {
      configured += 1;
    } else {
      skipped += 1;
    }
  }

  await verifyConfiguredPackages(packages, desired, auth, args);
  console.log(`Done. configured=${configured} skipped=${skipped}`);
  console.log(`Verified trusted publishing for ${packages.length} package(s).`);
}

main().catch((error) => {
  console.error(error.message);
  if (error instanceof NpmApiError && error.status === 403 && !process.env.NPM_OTP) {
    console.error("npm returned 403 without a web/passkey challenge. If this account has TOTP fallback, re-run with NPM_OTP.");
  }
  process.exit(1);
});
