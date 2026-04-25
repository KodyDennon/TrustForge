/**
 * Capability / authority / token expiration helpers.
 *
 * Capabilities, delegation links, identity documents, capability tokens,
 * and approval responses all carry validity windows. The daemon and the
 * RpcServer must reject any object whose window has expired before
 * acting on it. These helpers keep the comparison logic in one place so
 * TS and Rust agree byte-for-byte (RFC 3339 lexicographic comparison).
 */

export interface Window {
  valid_from?: string;
  valid_until?: string;
  /** Some objects use `expires_at` instead of `valid_until`. */
  expires_at?: string;
  /** Some carry `not_before` / `not_after`. */
  not_before?: string;
  not_after?: string;
}

export type ExpirationVerdict =
  | { ok: true }
  | { ok: false; reason: "not-yet-valid" | "expired"; threshold: string };

/** Returns whether the window is currently valid at the supplied
 *  ISO-8601 RFC 3339 timestamp `now`. Uses lexicographic comparison;
 *  callers MUST pass timestamps in `Z`-suffixed UTC form for parity
 *  with Rust. */
export function checkWindow(window: Window, now: string): ExpirationVerdict {
  const start = window.valid_from ?? window.not_before;
  const end = window.valid_until ?? window.expires_at ?? window.not_after;
  if (start && now < start) {
    return { ok: false, reason: "not-yet-valid", threshold: start };
  }
  if (end && now > end) {
    return { ok: false, reason: "expired", threshold: end };
  }
  return { ok: true };
}

/** Returns true iff `checkWindow(window, now).ok === true`. */
export function isWithinWindow(window: Window, now: string): boolean {
  return checkWindow(window, now).ok;
}

/** Returns true iff the window has hard-expired (the `end` boundary is
 *  in the past). "Not yet valid" returns false here so callers can
 *  distinguish premature use from stale use. */
export function isExpired(window: Window, now: string): boolean {
  const v = checkWindow(window, now);
  return !v.ok && v.reason === "expired";
}
