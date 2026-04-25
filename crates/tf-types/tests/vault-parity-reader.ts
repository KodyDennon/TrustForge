// Helper spawned from the Rust vault parity test. Opens a vault at the
// given path with the supplied passphrase and prints the hex of the
// requested entry's key_bytes on stdout. Exit non-zero on any failure.
//
// Usage: bun run vault-parity-reader.ts <vault.json> <passphrase> <entry-id>

import { Vault, toHex } from "../../../tools/tf-types-ts/src/index.ts";

async function main(): Promise<number> {
  const [, , vaultPath, passphrase, entryId] = process.argv;
  if (!vaultPath || !passphrase || !entryId) {
    console.error("usage: vault-parity-reader.ts <vault.json> <passphrase> <entry-id>");
    return 2;
  }
  const vault = await Vault.openAtPath(vaultPath, passphrase);
  const entry = vault.read(entryId);
  console.log(toHex(entry.key_bytes));
  return 0;
}

const code = await main();
process.exit(code);
