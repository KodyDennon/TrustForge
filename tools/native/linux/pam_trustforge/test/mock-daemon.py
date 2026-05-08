#!/usr/bin/env python3
"""
mock-daemon.py — minimal stand-in for the TrustForge decide daemon.

Listens on a Unix socket (default /run/trustforge/decide.sock) and answers
POST /v1/decide with a configurable allow/deny decision. Sufficient for
testing pam_trustforge.so without the real daemon.

Usage:
    python3 mock-daemon.py [--socket PATH] [--decision allow|deny] [--once]
                           [--reason TEXT]

Logs each request it receives to stderr.

This is a test fixture, not a reference implementation. It does not
verify host_token, actor, or anything else — it just echoes the
configured decision.
"""

from __future__ import annotations

import argparse
import json
import os
import os.path
import socket
import stat
import sys
import threading


def parse_request(buf: bytes) -> tuple[str, str, dict]:
    """Pull method, path, and JSON body out of a tiny HTTP/1.1 request."""
    head, _, body = buf.partition(b"\r\n\r\n")
    request_line, _, headers = head.partition(b"\r\n")
    parts = request_line.split(b" ")
    if len(parts) < 3:
        raise ValueError("malformed request line")
    method = parts[0].decode("ascii", "replace")
    path = parts[1].decode("ascii", "replace")
    parsed: dict = {}
    if body:
        try:
            parsed = json.loads(body.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise ValueError(f"bad json body: {exc}") from exc
    _ = headers  # ignored; we don't validate headers
    return method, path, parsed


def build_response(status: int, body_obj: dict) -> bytes:
    body = json.dumps(body_obj).encode("utf-8")
    reason = {200: "OK", 400: "Bad Request", 404: "Not Found",
              405: "Method Not Allowed", 500: "Internal Server Error"}.get(status, "OK")
    headers = (
        f"HTTP/1.1 {status} {reason}\r\n"
        f"Content-Type: application/json\r\n"
        f"Content-Length: {len(body)}\r\n"
        f"Connection: close\r\n"
        f"\r\n"
    ).encode("ascii")
    return headers + body


def handle_client(conn: socket.socket, decision: str, reason: str) -> None:
    try:
        conn.settimeout(2.0)
        chunks: list[bytes] = []
        while True:
            chunk = conn.recv(4096)
            if not chunk:
                break
            chunks.append(chunk)
            if b"\r\n\r\n" in b"".join(chunks):
                # We have the head; check Content-Length to know if there is more
                full = b"".join(chunks)
                head, _, body = full.partition(b"\r\n\r\n")
                cl = 0
                for line in head.split(b"\r\n")[1:]:
                    if line.lower().startswith(b"content-length:"):
                        try:
                            cl = int(line.split(b":", 1)[1].strip())
                        except ValueError:
                            cl = 0
                        break
                if len(body) >= cl:
                    break
        buf = b"".join(chunks)
        try:
            method, path, body_obj = parse_request(buf)
        except ValueError as exc:
            print(f"[mock-daemon] bad request: {exc}", file=sys.stderr)
            conn.sendall(build_response(400, {"error": str(exc)}))
            return

        print(f"[mock-daemon] {method} {path} body={body_obj}", file=sys.stderr)

        if path != "/v1/decide":
            conn.sendall(build_response(404, {"error": "not found"}))
            return
        if method != "POST":
            conn.sendall(build_response(405, {"error": "method not allowed"}))
            return

        resp = {"decision": decision, "reason": reason}
        conn.sendall(build_response(200, resp))
    except OSError as exc:
        print(f"[mock-daemon] socket error: {exc}", file=sys.stderr)
    finally:
        try:
            conn.shutdown(socket.SHUT_RDWR)
        except OSError:
            pass
        conn.close()


def default_socket_path() -> str:
    return os.environ.get("TRUSTFORGE_SOCKET", "/run/trustforge/decide.sock")


def main() -> int:
    p = argparse.ArgumentParser(description="Mock TrustForge decide daemon.")
    p.add_argument("--socket", default=default_socket_path(),
                   help="path to the AF_UNIX socket (default: /run/trustforge/decide.sock or TRUSTFORGE_SOCKET)")
    p.add_argument("--decision", choices=("allow", "deny"), default="allow",
                   help="decision to return for every request")
    p.add_argument("--reason", default="mock-daemon",
                   help="reason string echoed in the response")
    p.add_argument("--once", action="store_true",
                   help="exit after handling a single request")
    args = p.parse_args()

    sock_path = os.path.abspath(args.socket)
    os.makedirs(os.path.dirname(sock_path), exist_ok=True)
    if os.path.exists(sock_path):
        try:
            st = os.stat(sock_path)
            if stat.S_ISSOCK(st.st_mode):
                os.unlink(sock_path)
        except FileNotFoundError:
            pass

    srv = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    srv.bind(sock_path)
    os.chmod(sock_path, 0o600)
    srv.listen(8)
    print(f"[mock-daemon] listening on {sock_path} decision={args.decision}",
          file=sys.stderr)

    try:
        while True:
            conn, _ = srv.accept()
            if args.once:
                handle_client(conn, args.decision, args.reason)
                break
            t = threading.Thread(
                target=handle_client,
                args=(conn, args.decision, args.reason),
                daemon=True,
            )
            t.start()
    except KeyboardInterrupt:
        print("[mock-daemon] interrupted", file=sys.stderr)
    finally:
        srv.close()
        try:
            os.unlink(sock_path)
        except FileNotFoundError:
            pass
    return 0


if __name__ == "__main__":
    sys.exit(main())
