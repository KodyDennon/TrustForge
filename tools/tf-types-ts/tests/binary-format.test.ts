/**
 * .tfbundle / .tfpkt round-trip tests. CBOR encoding parity with the
 * Rust mirror is enforced via `conformance/binary-format-vectors.yaml`
 * (consumed by tf-conformance).
 */

import { describe, expect, test } from "bun:test";
import {
  TFBUNDLE_MAGIC,
  TFPKT_MAGIC,
  writeTfbundle,
  readTfbundle,
  writeTfpkt,
  readTfpkt,
  BinaryFormatError,
  ed25519Generate,
  signPacket,
} from "../src/index";

describe(".tfbundle round-trip", () => {
  test("unsigned bundle: magic, body, no signature", () => {
    const bundle = {
      bundle_version: "1",
      events: [],
      bundle_id: "b1",
      issued_at: "2026-04-24T12:00:00Z",
    } as any;
    const buf = writeTfbundle(bundle);
    for (let i = 0; i < TFBUNDLE_MAGIC.length; i++) {
      expect(buf[i]).toBe(TFBUNDLE_MAGIC[i]!);
    }
    const parts = readTfbundle(buf);
    expect((parts.body as any).bundle_version).toBe("1");
    expect(parts.signature.length).toBe(0);
  });

  test("signed bundle preserves signature bytes", () => {
    const bundle = { bundle_version: "1", events: [] } as any;
    const sig = new Uint8Array(64).fill(0xa5);
    const buf = writeTfbundle(bundle, sig);
    const parts = readTfbundle(buf);
    expect(parts.signature).toEqual(sig);
  });

  test("bad magic rejected", () => {
    const buf = new Uint8Array(16);
    expect(() => readTfbundle(buf)).toThrow(BinaryFormatError);
  });
});

describe(".tfpkt round-trip", () => {
  test("packet envelope round-trips", async () => {
    const pair = await ed25519Generate();
    const p = await signPacket({
      packetId: "pkt-tfpkt",
      source: "tf:actor:agent:example.com/x",
      destination: "tf:actor:service:example.com/d",
      priority: "P3",
      payload: new TextEncoder().encode("hi"),
      privateKey: pair.privateKey,
      signer: "tf:actor:agent:example.com/x",
      createdAt: "2026-04-24T12:00:00Z",
    });
    const buf = writeTfpkt(p);
    for (let i = 0; i < TFPKT_MAGIC.length; i++) {
      expect(buf[i]).toBe(TFPKT_MAGIC[i]!);
    }
    const decoded = readTfpkt(buf);
    expect(decoded.packet.packet_id).toBe(p.packet_id);
    expect(decoded.packet.signature.signature).toBe(p.signature.signature);
  });

  test("truncated buffer rejected", () => {
    const truncated = new Uint8Array([
      ...TFPKT_MAGIC,
      0x00,
      0x00,
      0x10,
      0x00, // claims 4096 byte body
      0x00,
      0x01, // but only 2 bytes follow
    ]);
    expect(() => readTfpkt(truncated)).toThrow(BinaryFormatError);
  });
});
