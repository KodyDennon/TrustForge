#!/usr/bin/env bun
/**
 * tf-conformance CLI. Drives every conformance runner and renders a
 * single canonical-JSON report. Designed for CI and for developers
 * cutting a v0.1.0 release tag.
 */

import { canonicalize } from "tf-types";
import { resolve } from "node:path";
import {
  runAll,
  runAiImplementationSuite,
  runBridgeVectors,
  runCompatibilityLabel,
  runFuzzCorpus,
  runGuardVectors,
  runInteropVectors,
  runProfileVectors,
  runSchemaVectors,
  runSecurityRegressions,
  runSignatureVectors,
  runTrustOverlayVectors,
} from "./runner.js";

function arg(args: string[], flag: string): string | undefined {
  const i = args.indexOf(flag);
  return i >= 0 ? args[i + 1] : undefined;
}

function root(args: string[]): string {
  return resolve(arg(args, "--root") ?? ".");
}

async function main(): Promise<number> {
  const argv = process.argv.slice(2);
  const cmd = argv[0];
  const rest = argv.slice(1);
  const r = root(argv);

  switch (cmd) {
    case "schema": {
      const report = runSchemaVectors(r);
      console.log(canonicalize(report));
      return report.failed === 0 ? 0 : 1;
    }
    case "signature": {
      const report = await runSignatureVectors(r);
      console.log(canonicalize(report));
      return report.failed === 0 ? 0 : 1;
    }
    case "guard": {
      const report = runGuardVectors(r);
      console.log(canonicalize(report));
      return report.failed === 0 ? 0 : 1;
    }
    case "trust-overlay": {
      const report = runTrustOverlayVectors(r);
      console.log(canonicalize(report));
      return report.failed === 0 ? 0 : 1;
    }
    case "bridge": {
      const report = runBridgeVectors(r);
      console.log(canonicalize(report));
      return report.failed === 0 ? 0 : 1;
    }
    case "interop": {
      const report = runInteropVectors(r);
      console.log(canonicalize(report));
      return report.failed === 0 ? 0 : 1;
    }
    case "fuzz": {
      const report = runFuzzCorpus(r);
      console.log(canonicalize(report));
      return report.failed === 0 ? 0 : 1;
    }
    case "profile": {
      const profileId = arg(rest, "--profile");
      const report = runProfileVectors(r, profileId);
      console.log(canonicalize(report));
      return report.failed === 0 ? 0 : 1;
    }
    case "security": {
      const report = await runSecurityRegressions();
      console.log(canonicalize(report));
      return report.failed === 0 ? 0 : 1;
    }
    case "ai-impl": {
      const report = runAiImplementationSuite(r);
      console.log(canonicalize(report));
      return report.failed === 0 ? 0 : 1;
    }
    case "label": {
      const profileId = arg(rest, "--profile");
      const daemonUrl = arg(rest, "--daemon");
      if (!profileId) {
        console.error("usage: tf-conformance label --profile <tf-...-compatible> [--daemon <url>]");
        return 2;
      }
      const report = await runCompatibilityLabel({
        profileId,
        daemonUrl,
        adminToken: process.env.TF_ADMIN_TOKEN,
      });
      console.log(canonicalize(report));
      return report.failed === 0 ? 0 : 1;
    }
    case "run":
    case undefined: {
      const profileId = arg(argv, "--profile");
      const daemonUrl = arg(argv, "--daemon");
      const result = await runAll({
        root: r,
        profileId,
        daemonUrl,
        adminToken: process.env.TF_ADMIN_TOKEN,
      });
      console.log(canonicalize(result));
      return result.failed === 0 ? 0 : 1;
    }
    default: {
      console.error(
        "usage: tf-conformance <run|schema|signature|guard|trust-overlay|bridge|interop|fuzz|profile|security|ai-impl|label> [--root <dir>] [--profile <id>] [--daemon <url>]",
      );
      return 2;
    }
  }
}

const exit = await main();
process.exit(exit);
