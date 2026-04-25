import { describe, expect, test } from "bun:test";
import { parseActorId, formatActorId, actorIdEquals, ActorIdParseError } from "../src/core/actor-id";
import { parseInstanceId, toActorId, formatInstanceId, InstanceIdParseError } from "../src/core/instance-id";
import { parseTrustDomain, trustDomainEquals, TrustDomainParseError } from "../src/core/trust-domain";

describe("parseActorId", () => {
  test("parses a valid agent id", () => {
    const p = parseActorId("tf:actor:agent:example.com/code-helper");
    expect(p.type).toBe("agent");
    expect(p.path).toBe("example.com/code-helper");
  });

  test("rejects unknown actor type", () => {
    expect(() => parseActorId("tf:actor:robot:example")).toThrow(ActorIdParseError);
  });

  test("rejects wrong scheme kind", () => {
    expect(() => parseActorId("tf:instance:agent:example/x")).toThrow(ActorIdParseError);
  });

  test("rejects missing path", () => {
    expect(() => parseActorId("tf:actor:agent:")).toThrow(ActorIdParseError);
  });

  test("formatActorId round-trips", () => {
    const s = formatActorId({ type: "human", path: "example.com/kody" });
    expect(s).toBe("tf:actor:human:example.com/kody");
    expect(parseActorId(s).path).toBe("example.com/kody");
  });

  test("actorIdEquals is exact", () => {
    expect(actorIdEquals("tf:actor:agent:example.com/a", "tf:actor:agent:example.com/a")).toBe(true);
    expect(actorIdEquals("tf:actor:agent:example.com/a", "tf:actor:agent:example.com/b")).toBe(false);
    expect(actorIdEquals("bogus", "tf:actor:agent:example.com/a")).toBe(false);
  });
});

describe("parseInstanceId", () => {
  test("parses a valid instance id", () => {
    const p = parseInstanceId("tf:instance:agent:example.com/code-helper/macbook/session-42");
    expect(p.type).toBe("agent");
    expect(p.actorPath).toBe("example.com/code-helper/macbook");
    expect(p.instancePath).toBe("session-42");
  });

  test("rejects missing instance path", () => {
    expect(() => parseInstanceId("tf:instance:agent:example.com/x")).not.toThrow();
    expect(() => parseInstanceId("tf:instance:agent:example.com")).toThrow(InstanceIdParseError);
  });

  test("toActorId strips instance suffix", () => {
    const id = toActorId("tf:instance:agent:example.com/code-helper/macbook/session-42");
    expect(id).toBe("tf:actor:agent:example.com/code-helper/macbook");
  });

  test("formatInstanceId round-trips", () => {
    const s = formatInstanceId({ type: "device", actorPath: "example.com/box-01", instancePath: "boot-9" });
    expect(s).toBe("tf:instance:device:example.com/box-01/boot-9");
  });
});

describe("parseTrustDomain", () => {
  test("parses a DNS domain", () => {
    const p = parseTrustDomain("Example.COM");
    expect(p.kind).toBe("dns");
    expect(p.value).toBe("example.com");
  });

  test("parses a local domain", () => {
    const p = parseTrustDomain("local/home");
    expect(p.kind).toBe("local");
    expect(p.value).toBe("home");
  });

  test("rejects malformed input", () => {
    expect(() => parseTrustDomain("")).toThrow(TrustDomainParseError);
    expect(() => parseTrustDomain("local/")).toThrow(TrustDomainParseError);
    expect(() => parseTrustDomain("a_b")).toThrow(TrustDomainParseError);
  });

  test("trustDomainEquals is case-insensitive for DNS, case-sensitive for local", () => {
    expect(trustDomainEquals("EXAMPLE.com", "example.COM")).toBe(true);
    expect(trustDomainEquals("local/Home", "local/home")).toBe(false);
  });
});
