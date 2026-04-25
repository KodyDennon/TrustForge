#!/usr/bin/env python3
"""
mock-daemon.py — minimal stand-in for the TrustForge decide daemon, used
only to exercise libnss_trustforge.so.2 end-to-end on a developer box.

Listens on $HOME/.trustforge/decide.sock and answers three endpoints:

  POST /v1/import-credential   {"credential": "<name>", "hint": "..."}
  POST /v1/lookup-uid          {"uid": <int>}
  POST /v1/list-actors         {"hint": "..."}

It is NOT a real implementation of any TrustForge spec. It does not
authenticate. It is not safe for production use. Phase 0 only.
"""

from __future__ import annotations

import json
import os
import pathlib
import socket
import sys
import threading


# ---- Same FNV-1a 64 / range mapping as the C module --------------------- #
TF_UID_MIN = 100_000
TF_UID_MAX = 0x3FFFFFFF


def fnv1a64(s: str) -> int:
    h = 0xcbf29ce484222325
    for ch in s.encode("utf-8"):
        h ^= ch
        h = (h * 0x100000001b3) & 0xFFFFFFFFFFFFFFFF
    return h


def tf_uid_for_actor(actor_id: str) -> int:
    span = TF_UID_MAX - TF_UID_MIN
    return TF_UID_MIN + (fnv1a64(actor_id) % span)


# ---- Fake actor table --------------------------------------------------- #
ACTORS = {
    # username                 actor_id
    "alice":   "tf:actor:human:example.com/alice",
    "bob":     "tf:actor:human:example.com/bob",
    "agent01": "tf:actor:agent:example.com/code-helper",
}

UID_INDEX = {tf_uid_for_actor(aid): (name, aid) for name, aid in ACTORS.items()}


# ---- Tiny HTTP/1.0 over AF_UNIX ----------------------------------------- #
def parse_request(data: bytes) -> tuple[str, str, bytes]:
    """Return (method, path, body)."""
    head, _, body = data.partition(b"\r\n\r\n")
    lines = head.split(b"\r\n")
    if not lines:
        return "", "", b""
    parts = lines[0].split(b" ")
    if len(parts) < 2:
        return "", "", b""
    method = parts[0].decode("ascii", "replace")
    path = parts[1].decode("ascii", "replace")
    return method, path, body


def http_response(status: int, payload: dict | None) -> bytes:
    body = b"" if payload is None else json.dumps(payload).encode("utf-8")
    reason = {200: "OK", 404: "Not Found", 400: "Bad Request"}.get(status, "OK")
    head = (
        f"HTTP/1.0 {status} {reason}\r\n"
        f"Content-Type: application/json\r\n"
        f"Content-Length: {len(body)}\r\n"
        f"Connection: close\r\n"
        f"\r\n"
    ).encode("ascii")
    return head + body


def handle_import_credential(body: dict) -> tuple[int, dict | None]:
    name = body.get("credential", "")
    if name not in ACTORS:
        return 404, None
    actor_id = ACTORS[name]
    return 200, {
        "actor_id": actor_id,
        "name": name,
        "home": f"/var/lib/trustforge/actors/{name}",
        "shell": "/usr/sbin/nologin",
    }


def handle_lookup_uid(body: dict) -> tuple[int, dict | None]:
    try:
        uid = int(body.get("uid", -1))
    except (TypeError, ValueError):
        return 400, None
    found = UID_INDEX.get(uid)
    if not found:
        return 404, None
    name, actor_id = found
    return 200, {
        "actor_id": actor_id,
        "name": name,
        "home": f"/var/lib/trustforge/actors/{name}",
        "shell": "/usr/sbin/nologin",
    }


def handle_list_actors(_body: dict) -> tuple[int, dict | None]:
    # The C module parses a JSON array — we reply with the array directly.
    return 200, list(ACTORS.keys())


ROUTES = {
    "/v1/import-credential": handle_import_credential,
    "/v1/lookup-uid":        handle_lookup_uid,
    "/v1/list-actors":       handle_list_actors,
}


def serve_one(conn: socket.socket) -> None:
    try:
        chunks = []
        # Read until peer closes or we have a full request — the NSS module
        # only sends Connection: close requests, so EOF is a fine boundary.
        conn.settimeout(2.0)
        while True:
            buf = conn.recv(4096)
            if not buf:
                break
            chunks.append(buf)
            if b"\r\n\r\n" in b"".join(chunks):
                # Got headers; the NSS client sends the body in the same
                # round trip, so one more recv is enough.
                more = b""
                try:
                    more = conn.recv(4096)
                except socket.timeout:
                    pass
                if more:
                    chunks.append(more)
                break
        data = b"".join(chunks)
        method, path, body = parse_request(data)
        if method != "POST":
            conn.sendall(http_response(400, {"error": "method"}))
            return
        try:
            body_json = json.loads(body or b"{}")
        except json.JSONDecodeError:
            conn.sendall(http_response(400, {"error": "bad json"}))
            return
        handler = ROUTES.get(path)
        if not handler:
            conn.sendall(http_response(404, {"error": "no route"}))
            return
        status, payload = handler(body_json)
        # `list-actors` returns a list, not a dict — encode directly.
        if isinstance(payload, list):
            body_bytes = json.dumps(payload).encode("utf-8")
            head = (
                f"HTTP/1.0 {status} OK\r\n"
                f"Content-Type: application/json\r\n"
                f"Content-Length: {len(body_bytes)}\r\n"
                f"Connection: close\r\n\r\n"
            ).encode("ascii")
            conn.sendall(head + body_bytes)
        else:
            conn.sendall(http_response(status, payload))
    except Exception as e:  # noqa: BLE001
        try:
            conn.sendall(http_response(500, {"error": str(e)}))
        except OSError:
            pass
    finally:
        try:
            conn.close()
        except OSError:
            pass


def main() -> int:
    home = pathlib.Path(os.environ.get("HOME", "/tmp"))
    sock_dir = home / ".trustforge"
    sock_dir.mkdir(parents=True, exist_ok=True)
    sock_path = sock_dir / "decide.sock"
    if sock_path.exists():
        sock_path.unlink()

    srv = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    srv.bind(str(sock_path))
    os.chmod(sock_path, 0o600)
    srv.listen(8)

    print(f"mock-daemon listening on {sock_path}", file=sys.stderr)
    print(f"known actors: {', '.join(ACTORS)}", file=sys.stderr)

    try:
        while True:
            conn, _ = srv.accept()
            t = threading.Thread(target=serve_one, args=(conn,), daemon=True)
            t.start()
    except KeyboardInterrupt:
        print("shutting down", file=sys.stderr)
    finally:
        srv.close()
        try:
            sock_path.unlink()
        except FileNotFoundError:
            pass
    return 0


if __name__ == "__main__":
    sys.exit(main())
