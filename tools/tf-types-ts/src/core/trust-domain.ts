export class TrustDomainParseError extends Error {}

export interface ParsedTrustDomain {
  readonly kind: "dns" | "local";
  readonly value: string;
  readonly raw: string;
}

/**
 * Parse a trust-domain identifier. DNS-like strings (e.g. "example.com") are
 * kind: "dns". Strings prefixed with "local/" are kind: "local". Anything
 * else is a parse error. Case-insensitive comparison applies to DNS domains
 * (RFC 1035); local domains compare case-sensitively.
 */
export function parseTrustDomain(s: string): ParsedTrustDomain {
  if (typeof s !== "string" || s.length === 0) {
    throw new TrustDomainParseError(`expected non-empty string, got ${JSON.stringify(s)}`);
  }
  if (s.startsWith("local/")) {
    const value = s.slice("local/".length);
    if (!value) throw new TrustDomainParseError("empty local trust-domain");
    return { kind: "local", value, raw: s };
  }
  if (!/^[A-Za-z0-9](?:[A-Za-z0-9.-]*[A-Za-z0-9])?$/.test(s)) {
    throw new TrustDomainParseError(`malformed DNS trust-domain: ${JSON.stringify(s)}`);
  }
  return { kind: "dns", value: s.toLowerCase(), raw: s };
}

export function trustDomainEquals(a: string, b: string): boolean {
  try {
    const pa = parseTrustDomain(a);
    const pb = parseTrustDomain(b);
    if (pa.kind !== pb.kind) return false;
    return pa.value === pb.value;
  } catch {
    return false;
  }
}
