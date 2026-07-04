import { mkdirSync } from "node:fs";
import { join } from "node:path";
import { ed25519Generate, ed25519PublicKey } from "@trustforge-protocol/types";
import { writeKeyFile } from "./keyfile.js";

export async function runKeygen(outDir: string): Promise<{ privatePath: string; publicPath: string }> {
  mkdirSync(outDir, { recursive: true });
  const pair = await ed25519Generate();
  const privatePath = join(outDir, "tf.ed25519.key.json");
  const publicPath = join(outDir, "tf.ed25519.pub.json");
  writeKeyFile(privatePath, "private", pair.privateKey);
  writeKeyFile(publicPath, "public", pair.publicKey);
  return { privatePath, publicPath };
}

export async function runDerivePubkey(privateKeyFile: string, outFile?: string): Promise<string> {
  const { readKeyFile } = await import("./keyfile.js");
  const { bytes } = readKeyFile(privateKeyFile);
  const pub = await ed25519PublicKey(bytes);
  if (outFile) {
    writeKeyFile(outFile, "public", pub);
    return outFile;
  }
  const { b64encode } = await import("@trustforge-protocol/types");
  return b64encode(pub);
}
