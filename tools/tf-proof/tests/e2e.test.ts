import { describe, expect, test } from "bun:test";
import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { runKeygen, runDerivePubkey } from "../src/keygen";
import { runSignCli } from "../src/sign";
import { verifyFile } from "../src/verify";
import { inspectFile } from "../src/inspect";

function withTempDir<T>(fn: (dir: string) => Promise<T> | T): Promise<T> {
  const dir = mkdtempSync(join(tmpdir(), "tf-proof-"));
  return Promise.resolve(fn(dir)).finally(() => {
    rmSync(dir, { recursive: true, force: true });
  });
}

const SIGNER = "tf:actor:organization:example.com";

const EVENTS = [
  {
    event_version: "1",
    id: "evt-a",
    type: "session.established",
    actor_id: "tf:actor:agent:example.com/a",
    timestamp: "2026-04-24T12:00:00Z",
    level: "L1",
    signature: {
      algorithm: "ed25519",
      signer: "tf:actor:agent:example.com/a",
      signature: "AAAA",
    },
  },
  {
    event_version: "1",
    id: "evt-b",
    type: "action.proposed",
    actor_id: "tf:actor:agent:example.com/a",
    timestamp: "2026-04-24T12:01:00Z",
    level: "L2",
    signature: {
      algorithm: "ed25519",
      signer: "tf:actor:agent:example.com/a",
      signature: "BBBB",
    },
  },
];

describe("tf-proof end-to-end", () => {
  test("keygen → sign → verify → inspect round-trip", async () => {
    await withTempDir(async (dir) => {
      const { privatePath, publicPath } = await runKeygen(dir);

      const eventsFile = join(dir, "events.json");
      writeFileSync(eventsFile, JSON.stringify(EVENTS));

      const out = join(dir, "bundle.tfproof");
      const signCode = await runSignCli({
        eventsFile,
        keyFile: privatePath,
        signerActorId: SIGNER,
        out,
      });
      expect(signCode).toBe(0);

      const report = await verifyFile(out, publicPath);
      if (!report.ok) console.error(JSON.stringify(report, null, 2));
      expect(report.ok).toBe(true);
      expect(report.events).toBe(2);
      expect(report.checks.find((c) => c.name === "chain")?.ok).toBe(true);
      expect(report.checks.find((c) => c.name === "merkle_root")?.ok).toBe(true);
      expect(report.checks.find((c) => c.name === "bundle_signature_envelope")?.ok).toBe(true);
      expect(report.checks.find((c) => c.name === "bundle_signature_trailer")?.ok).toBe(true);

      const inspected = inspectFile(out, false);
      const parsed = JSON.parse(inspected);
      expect(parsed.format).toBe("tfproof");
      expect(parsed.events.count).toBe(2);
      expect(parsed.events.head_id).toBe("evt-a");
      expect(parsed.events.tail_id).toBe("evt-b");
    });
  });

  test("tampered bundle fails verification", async () => {
    await withTempDir(async (dir) => {
      const { privatePath, publicPath } = await runKeygen(dir);
      const eventsFile = join(dir, "events.json");
      writeFileSync(eventsFile, JSON.stringify(EVENTS));
      const out = join(dir, "bundle.tfproof");
      await runSignCli({ eventsFile, keyFile: privatePath, signerActorId: SIGNER, out });

      // Flip a byte late in the file (outside the magic).
      const fs = await import("node:fs");
      const buf = fs.readFileSync(out);
      buf[buf.length - 10]! ^= 0xff;
      fs.writeFileSync(out, buf);

      const report = await verifyFile(out, publicPath);
      expect(report.ok).toBe(false);
    });
  });

  test("wrong public key fails verification", async () => {
    await withTempDir(async (dir) => {
      const { privatePath } = await runKeygen(dir);
      const eventsFile = join(dir, "events.json");
      writeFileSync(eventsFile, JSON.stringify(EVENTS));
      const out = join(dir, "bundle.tfproof");
      await runSignCli({ eventsFile, keyFile: privatePath, signerActorId: SIGNER, out });

      // Generate a second, unrelated key pair.
      const dir2 = join(dir, "other");
      mkdirSync(dir2);
      const other = await runKeygen(dir2);

      const report = await verifyFile(out, other.publicPath);
      expect(report.ok).toBe(false);
    });
  });

  test("derive-pubkey round-trips", async () => {
    await withTempDir(async (dir) => {
      const { privatePath, publicPath } = await runKeygen(dir);
      const derivedOut = join(dir, "derived.pub.json");
      await runDerivePubkey(privatePath, derivedOut);

      const fs = await import("node:fs");
      const a = JSON.parse(fs.readFileSync(publicPath, "utf8"));
      const b = JSON.parse(fs.readFileSync(derivedOut, "utf8"));
      expect(b.algorithm).toBe(a.algorithm);
      expect(b.key_bytes).toBe(a.key_bytes);
    });
  });
});
