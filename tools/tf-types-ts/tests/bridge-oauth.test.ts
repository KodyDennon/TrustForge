import { describe, expect, test } from "bun:test";
import { exportJWK, generateKeyPair, SignJWT } from "jose";
import { BridgeFailure, OAuthBridge } from "../src/index";

async function makeKeySet(alg: "ES256" | "RS256" | "EdDSA") {
  const { privateKey, publicKey } = await generateKeyPair(alg);
  const jwk = await exportJWK(publicKey);
  jwk.kid = `test-kid-${alg}`;
  jwk.alg = alg;
  return { privateKey, publicKey, jwk };
}

async function mintToken(
  // Jose returns KeyLike — opaque; SignJWT.sign accepts it directly.
  privateKey: any,
  alg: "ES256" | "RS256" | "EdDSA",
  kid: string,
  subject: string,
  scope: string,
): Promise<string> {
  return new SignJWT({ scope })
    .setProtectedHeader({ alg, kid })
    .setIssuer("https://issuer.example.com/")
    .setAudience("trustforge")
    .setSubject(subject)
    .setIssuedAt()
    .setExpirationTime("5m")
    .sign(privateKey);
}

describe("OAuth bridge — real JWT verification", () => {
  test("ES256 token verifies and projects an identity + capabilities", async () => {
    const { privateKey, jwk } = await makeKeySet("ES256");
    const bridge = new OAuthBridge({
      bridgeId: "tf-oauth-bridge",
      trustDomain: "example.com",
      jwks: { keys: [jwk] } as any,
      allowedAlgorithms: ["ES256"],
      issuer: "https://issuer.example.com/",
      audience: "trustforge",
    });
    const token = await mintToken(privateKey, "ES256", jwk.kid!, "user-42", "file.read shell.exec");
    const result = await bridge.verifyToken(token);
    expect(result.identity.actor_id).toBe("tf:actor:human:example.com/user-42");
    expect(result.identity.authority_roots[0]!.id).toBe("https://issuer.example.com/");
    expect(result.capabilities.map((c) => c.name).sort()).toEqual(["file.read", "shell.exec"]);
  });

  test("RS256 with a custom scopeToAction map", async () => {
    const { privateKey, jwk } = await makeKeySet("RS256");
    const bridge = new OAuthBridge({
      bridgeId: "tf-oauth",
      trustDomain: "example.com",
      jwks: { keys: [jwk] } as any,
      allowedAlgorithms: ["RS256"],
      issuer: "https://issuer.example.com/",
      audience: "trustforge",
      scopeToAction: (s) => `mapped.${s}`,
    });
    const token = await mintToken(privateKey, "RS256", jwk.kid!, "alice", "read write");
    const result = await bridge.verifyToken(token);
    expect(result.capabilities.map((c) => c.name).sort()).toEqual(["mapped.read", "mapped.write"]);
  });

  test("EdDSA token verifies", async () => {
    const { privateKey, jwk } = await makeKeySet("EdDSA");
    const bridge = new OAuthBridge({
      bridgeId: "tf-oauth",
      trustDomain: "example.com",
      jwks: { keys: [jwk] } as any,
      allowedAlgorithms: ["EdDSA"],
      issuer: "https://issuer.example.com/",
      audience: "trustforge",
    });
    const token = await mintToken(privateKey, "EdDSA", jwk.kid!, "bob", "");
    const result = await bridge.verifyToken(token);
    expect(result.identity.actor_id).toBe("tf:actor:human:example.com/bob");
  });

  test("rejects wrong issuer", async () => {
    const { privateKey, jwk } = await makeKeySet("ES256");
    const bridge = new OAuthBridge({
      bridgeId: "tf-oauth",
      trustDomain: "example.com",
      jwks: { keys: [jwk] } as any,
      allowedAlgorithms: ["ES256"],
      issuer: "https://issuer.example.com/",
      audience: "trustforge",
    });
    const evilToken = await new SignJWT({ scope: "" })
      .setProtectedHeader({ alg: "ES256", kid: jwk.kid! })
      .setIssuer("https://attacker.example/")
      .setAudience("trustforge")
      .setSubject("user")
      .setExpirationTime("5m")
      .sign(privateKey);
    await expect(bridge.verifyToken(evilToken)).rejects.toThrow(BridgeFailure);
  });

  test("rejects wrong audience", async () => {
    const { privateKey, jwk } = await makeKeySet("ES256");
    const bridge = new OAuthBridge({
      bridgeId: "tf-oauth",
      trustDomain: "example.com",
      jwks: { keys: [jwk] } as any,
      allowedAlgorithms: ["ES256"],
      issuer: "https://issuer.example.com/",
      audience: "trustforge",
    });
    const wrong = await new SignJWT({ scope: "" })
      .setProtectedHeader({ alg: "ES256", kid: jwk.kid! })
      .setIssuer("https://issuer.example.com/")
      .setAudience("someone-else")
      .setSubject("user")
      .setExpirationTime("5m")
      .sign(privateKey);
    await expect(bridge.verifyToken(wrong)).rejects.toThrow(BridgeFailure);
  });

  test("rejects algorithm not in allow-list (alg-confusion guard)", async () => {
    const { privateKey, jwk } = await makeKeySet("ES256");
    const bridge = new OAuthBridge({
      bridgeId: "tf-oauth",
      trustDomain: "example.com",
      jwks: { keys: [jwk] } as any,
      allowedAlgorithms: ["RS256"], // ES256 minted token will be rejected
      issuer: "https://issuer.example.com/",
      audience: "trustforge",
    });
    const token = await mintToken(privateKey, "ES256", jwk.kid!, "user", "");
    await expect(bridge.verifyToken(token)).rejects.toThrow(BridgeFailure);
  });

  test("rejects expired tokens", async () => {
    const { privateKey, jwk } = await makeKeySet("ES256");
    const bridge = new OAuthBridge({
      bridgeId: "tf-oauth",
      trustDomain: "example.com",
      jwks: { keys: [jwk] } as any,
      allowedAlgorithms: ["ES256"],
      issuer: "https://issuer.example.com/",
      audience: "trustforge",
      clockToleranceSeconds: 0,
    });
    const expired = await new SignJWT({ scope: "" })
      .setProtectedHeader({ alg: "ES256", kid: jwk.kid! })
      .setIssuer("https://issuer.example.com/")
      .setAudience("trustforge")
      .setSubject("user")
      .setIssuedAt(Math.floor(Date.now() / 1000) - 3600)
      .setExpirationTime(Math.floor(Date.now() / 1000) - 1800)
      .sign(privateKey);
    await expect(bridge.verifyToken(expired)).rejects.toThrow(BridgeFailure);
  });
});
