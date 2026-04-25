import { describe, expect, test } from "bun:test";
import { Crypto } from "@peculiar/webcrypto";
import * as x509 from "@peculiar/x509";

import { BridgeFailure, TlsBridge, parsePemBundle, extractEkuOids } from "../src/index";

const webcrypto = new Crypto();
x509.cryptoProvider.set(webcrypto as unknown as globalThis.Crypto);

interface CertMaterial {
  cert: x509.X509Certificate;
  pem: string;
  key: CryptoKeyPair;
}

async function makeRoot(name = "CN=TrustForge Root CA"): Promise<CertMaterial> {
  const key = (await webcrypto.subtle.generateKey(
    { name: "ECDSA", namedCurve: "P-256" },
    true,
    ["sign", "verify"],
  )) as CryptoKeyPair;
  const cert = await x509.X509CertificateGenerator.createSelfSigned({
    serialNumber: "01",
    name,
    notBefore: new Date(Date.now() - 1000 * 60),
    notAfter: new Date(Date.now() + 1000 * 60 * 60),
    signingAlgorithm: { name: "ECDSA", hash: "SHA-256" },
    keys: key,
    extensions: [
      new x509.BasicConstraintsExtension(true, undefined, true),
      new x509.KeyUsagesExtension(
        x509.KeyUsageFlags.keyCertSign | x509.KeyUsageFlags.cRLSign,
        true,
      ),
    ],
  });
  return { cert, pem: cert.toString("pem"), key };
}

interface IssueOptions {
  subject: string;
  isCa?: boolean;
  ekus?: x509.ExtendedKeyUsage[];
  sanUris?: string[];
  notBefore?: Date;
  notAfter?: Date;
}

async function issue(
  parent: CertMaterial,
  opts: IssueOptions,
): Promise<CertMaterial> {
  const key = (await webcrypto.subtle.generateKey(
    { name: "ECDSA", namedCurve: "P-256" },
    true,
    ["sign", "verify"],
  )) as CryptoKeyPair;
  const extensions: x509.Extension[] = [];
  if (opts.isCa) {
    extensions.push(new x509.BasicConstraintsExtension(true, 0, true));
    extensions.push(
      new x509.KeyUsagesExtension(
        x509.KeyUsageFlags.keyCertSign | x509.KeyUsageFlags.cRLSign,
        true,
      ),
    );
  } else {
    extensions.push(new x509.BasicConstraintsExtension(false, undefined, true));
    extensions.push(
      new x509.KeyUsagesExtension(
        x509.KeyUsageFlags.digitalSignature | x509.KeyUsageFlags.keyEncipherment,
        true,
      ),
    );
  }
  if (opts.ekus && opts.ekus.length > 0) {
    extensions.push(new x509.ExtendedKeyUsageExtension(opts.ekus, false));
  }
  if (opts.sanUris && opts.sanUris.length > 0) {
    extensions.push(
      new x509.SubjectAlternativeNameExtension(
        opts.sanUris.map((u) => ({ type: "url" as const, value: u })),
      ),
    );
  }
  const cert = await x509.X509CertificateGenerator.create({
    serialNumber: Math.floor(Math.random() * 1e9).toString(16),
    issuer: parent.cert.subject,
    subject: opts.subject,
    notBefore: opts.notBefore ?? new Date(Date.now() - 1000 * 60),
    notAfter: opts.notAfter ?? new Date(Date.now() + 1000 * 60 * 60),
    signingAlgorithm: { name: "ECDSA", hash: "SHA-256" },
    publicKey: key.publicKey,
    signingKey: parent.key.privateKey,
    extensions,
  });
  return { cert, pem: cert.toString("pem"), key };
}

describe("TLS / mTLS bridge", () => {
  test("verifies a valid leaf-intermediate-root chain", async () => {
    const root = await makeRoot();
    const inter = await issue(root, { subject: "CN=Intermediate", isCa: true });
    const leaf = await issue(inter, {
      subject: "CN=tf-service-leaf",
      ekus: [x509.ExtendedKeyUsage.clientAuth, x509.ExtendedKeyUsage.serverAuth],
      sanUris: ["spiffe://example.com/services/code-helper"],
    });

    const bridge = new TlsBridge({
      bridgeId: "tf-tls-bridge",
      trustDomain: "example.com",
      rootCertificatesPem: [root.pem],
    });
    const result = bridge.verifyChain([leaf.pem, inter.pem]);
    expect(result.identity.actor_type).toBe("service");
    expect(result.identity.actor_id).toBe(
      "tf:actor:service:example.com/spiffe%3A//example.com/services/code-helper",
    );
    const actions = result.capabilities.map((c) => c.name);
    expect(actions).toContain("tls.client-auth");
    expect(actions).toContain("tls.server-auth");
    expect(result.chain.length).toBe(3);
  });

  test("rejects chain with broken intermediate signature", async () => {
    const root = await makeRoot();
    const otherRoot = await makeRoot("CN=Imposter Root");
    const fakeInter = await issue(otherRoot, { subject: "CN=Inter", isCa: true });
    const leaf = await issue(fakeInter, {
      subject: "CN=leaf",
      ekus: [x509.ExtendedKeyUsage.clientAuth],
    });
    const bridge = new TlsBridge({
      bridgeId: "tf-tls-bridge",
      trustDomain: "example.com",
      rootCertificatesPem: [root.pem],
    });
    expect(() => bridge.verifyChain([leaf.pem, fakeInter.pem])).toThrow(BridgeFailure);
  });

  test("rejects expired leaf", async () => {
    const root = await makeRoot();
    const leaf = await issue(root, {
      subject: "CN=expired",
      ekus: [x509.ExtendedKeyUsage.clientAuth],
      notBefore: new Date(Date.now() - 1000 * 60 * 60 * 2),
      notAfter: new Date(Date.now() - 1000 * 60),
    });
    const bridge = new TlsBridge({
      bridgeId: "tf-tls-bridge",
      trustDomain: "example.com",
      rootCertificatesPem: [root.pem],
    });
    expect(() => bridge.verifyChain([leaf.pem])).toThrow(BridgeFailure);
  });

  test("rejects when no chain reaches a configured root", async () => {
    const root = await makeRoot();
    const otherRoot = await makeRoot("CN=Other Root");
    const leaf = await issue(otherRoot, {
      subject: "CN=leaf",
      ekus: [x509.ExtendedKeyUsage.clientAuth],
    });
    const bridge = new TlsBridge({
      bridgeId: "tf-tls-bridge",
      trustDomain: "example.com",
      rootCertificatesPem: [root.pem],
    });
    expect(() => bridge.verifyChain([leaf.pem])).toThrow(BridgeFailure);
  });

  test("enforces required SAN URI", async () => {
    const root = await makeRoot();
    const leaf = await issue(root, {
      subject: "CN=leaf",
      ekus: [x509.ExtendedKeyUsage.clientAuth],
      sanUris: ["spiffe://example.com/different"],
    });
    const bridge = new TlsBridge({
      bridgeId: "tf-tls-bridge",
      trustDomain: "example.com",
      rootCertificatesPem: [root.pem],
      requiredSanUri: "spiffe://example.com/expected",
    });
    expect(() => bridge.verifyChain([leaf.pem])).toThrow(BridgeFailure);
  });

  test("parsePemBundle splits multi-cert bundles", async () => {
    const root = await makeRoot();
    const inter = await issue(root, { subject: "CN=Inter", isCa: true });
    const bundle = `${root.pem}\n${inter.pem}`;
    const parsed = parsePemBundle(bundle);
    expect(parsed.length).toBe(2);
  });

  test("extractEkuOids reads OIDs out of a real cert", async () => {
    const root = await makeRoot();
    const leaf = await issue(root, {
      subject: "CN=leaf",
      ekus: [x509.ExtendedKeyUsage.codeSigning],
    });
    const oids = extractEkuOids(new Uint8Array(parsePemBundle(leaf.pem)[0]!.raw));
    expect(oids).toContain("1.3.6.1.5.5.7.3.3");
  });
});
