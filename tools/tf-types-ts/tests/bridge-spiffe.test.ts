import { describe, expect, test } from "bun:test";
import { readFileSync } from "node:fs";
import { join } from "node:path";
import { parse as parseYAML } from "yaml";
import {
  BridgeFailure,
  BridgeRegistry,
  SpiffeBridge,
  actorIdToSpiffe,
  spiffeToActorId,
} from "../src/index";

const REPO_ROOT = join(import.meta.dir, "..", "..", "..");
const VECTORS = parseYAML(readFileSync(join(REPO_ROOT, "conformance", "bridge-vectors.yaml"), "utf8")) as {
  spiffe: { name: string; spiffe_id: string; actor_id: string }[];
};

describe("SPIFFE bridge", () => {
  for (const v of VECTORS.spiffe) {
    test(`${v.name} forward`, () => {
      expect(spiffeToActorId(v.spiffe_id)).toBe(v.actor_id);
    });
    test(`${v.name} reverse`, () => {
      expect(actorIdToSpiffe(v.actor_id)).toBe(v.spiffe_id);
    });
  }

  test("rejects non-spiffe schemes", () => {
    expect(() => spiffeToActorId("urn:spiffe:foo")).toThrow(BridgeFailure);
    expect(() => spiffeToActorId("")).toThrow(BridgeFailure);
    expect(() => spiffeToActorId("spiffe:///no-domain")).toThrow(BridgeFailure);
    expect(() => spiffeToActorId("spiffe://domain")).toThrow(BridgeFailure);
  });

  test("rejects non-service actor URIs on reverse", () => {
    expect(() => actorIdToSpiffe("tf:actor:human:example.com/kody")).toThrow(BridgeFailure);
    expect(() => actorIdToSpiffe("not an actor")).toThrow(BridgeFailure);
  });

  test("BridgeRegistry finds the SPIFFE bridge by kind", () => {
    const registry = new BridgeRegistry();
    const bridge = new SpiffeBridge("tf-spiffe-bridge", "example.org");
    registry.register(bridge);
    const found = registry.get<SpiffeBridge>("spiffe");
    expect(found).toBeDefined();
    expect(found?.bridgeId).toBe("tf-spiffe-bridge");
  });
});
