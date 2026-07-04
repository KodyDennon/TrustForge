import { readFileSync, writeFileSync } from "node:fs";
import { parseYaml as parseYAML } from "@trustforge-protocol/types";
import {
  canonicalize,
  ed25519PublicKey,
  ed25519Sign,
  b64encode,
  eventHash,
  merkleRoot,
  chainHash,
  utf8encode,
  writeTfproof,
} from "@trustforge-protocol/types";
import type { ProofBundle, ProofEvent, SignatureEnvelope } from "@trustforge-protocol/types";
import { readKeyFile } from "./keyfile.js";

export interface SignArgs {
  events: ProofEvent[];
  privateKey: Uint8Array;
  signerActorId: string;
}

export async function signBundle(args: SignArgs): Promise<{ bundle: ProofBundle; signature: Uint8Array }> {
  // Compute the hash-chain: set parent_hash on every event after the first.
  const linked: ProofEvent[] = [];
  for (let i = 0; i < args.events.length; i++) {
    const e = { ...args.events[i]! };
    if (i > 0 && !e.parent_hash) {
      e.parent_hash = eventHash(linked[i - 1]!);
    }
    linked.push(e);
  }

  // Build the unsigned bundle body.
  const bundleShell: ProofBundle = {
    bundle_version: "1",
    events: linked,
    merkle_root: merkleRoot(linked),
    chain_hash: chainHash(linked),
    signature: {
      algorithm: "ed25519",
      signer: args.signerActorId,
      signature: "",
    } as SignatureEnvelope,
  };

  // Sign the canonical JSON of the bundle with the signature's `signature`
  // field zeroed out — standard construction.
  const toSign = { ...bundleShell, signature: { ...bundleShell.signature, signature: "" } };
  const signingPayload = utf8encode(canonicalize(toSign));
  const sig = await ed25519Sign(signingPayload, args.privateKey);

  const finalBundle: ProofBundle = {
    ...bundleShell,
    signature: {
      ...bundleShell.signature,
      signature: b64encode(sig),
    },
  };

  return { bundle: finalBundle, signature: sig };
}

export interface CliSignArgs {
  eventsFile: string;
  keyFile: string;
  signerActorId: string;
  out?: string;
}

export async function runSignCli(args: CliSignArgs): Promise<number> {
  const raw = readFileSync(args.eventsFile, "utf8");
  const parsed = args.eventsFile.endsWith(".json") ? JSON.parse(raw) : parseYAML(raw);
  const events: ProofEvent[] = Array.isArray(parsed) ? parsed : parsed.events;
  if (!Array.isArray(events) || events.length === 0) {
    console.error(`no events found in ${args.eventsFile}`);
    return 2;
  }

  const { bytes, kind } = readKeyFile(args.keyFile);
  if (kind !== "private") {
    console.error(`${args.keyFile} is a public key, not a private key`);
    return 2;
  }
  // Derive the public key so the caller can sanity-check.
  await ed25519PublicKey(bytes);

  const { bundle, signature } = await signBundle({
    events,
    privateKey: bytes,
    signerActorId: args.signerActorId,
  });

  const framed = writeTfproof(bundle, signature);
  if (args.out) {
    writeFileSync(args.out, framed);
    console.log(`wrote ${framed.length} bytes to ${args.out}`);
  } else {
    process.stdout.write(framed);
  }
  return 0;
}
