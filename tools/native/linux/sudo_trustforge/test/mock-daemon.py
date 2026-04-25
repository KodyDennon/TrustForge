#!/usr/bin/env python3
"""
mock-daemon.py -- minimal stand-in for the TrustForge daemon's
/v1/decide endpoint. Listens on a UNIX socket and returns a fixed
decision for every request.

Usage:
    mock-daemon.py <socket-path> <allow|deny>

The daemon accepts one HTTP/1.0 request per connection (the wire
contract used by sudo_trustforge.so) and replies with a JSON body of
the form `{"decision":"allow"}` or `{"decision":"deny"}`. The full
request is echoed to stderr so test drivers can assert on shape.

This is for testing only. It performs no auth, no signing, no replay
protection -- the real daemon is the canonical decision point.
"""
import os
import sys
import json
import socket
import signal


def usage():
    print(__doc__, file=sys.stderr)
    sys.exit(2)


def serve(sock_path: str, decision: str) -> None:
    if decision not in ("allow", "deny"):
        usage()

    # Clean up any stale socket from a previous run.
    try:
        os.unlink(sock_path)
    except FileNotFoundError:
        pass

    s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    s.bind(sock_path)
    os.chmod(sock_path, 0o600)
    s.listen(8)

    print(f"mock-daemon: listening on {sock_path}, decision={decision}",
          file=sys.stderr, flush=True)

    # Graceful shutdown on SIGINT / SIGTERM.
    def _shutdown(signum, frame):
        try:
            os.unlink(sock_path)
        except OSError:
            pass
        sys.exit(0)
    signal.signal(signal.SIGINT, _shutdown)
    signal.signal(signal.SIGTERM, _shutdown)

    body = json.dumps({
        "decision": decision,
        "reason":   f"mock-daemon fixed-{decision}",
        "trace_id": "mock-0000-0000-0000",
    }).encode("utf-8")

    response = (
        b"HTTP/1.0 200 OK\r\n"
        b"Content-Type: application/json\r\n"
        b"Content-Length: " + str(len(body)).encode() + b"\r\n"
        b"Connection: close\r\n"
        b"\r\n"
        + body
    )

    while True:
        conn, _ = s.accept()
        with conn:
            data = b""
            # Read until we have headers + body or the peer closes.
            while b"\r\n\r\n" not in data:
                chunk = conn.recv(4096)
                if not chunk:
                    break
                data += chunk
                if len(data) > 1 << 20:
                    break  # 1 MiB cap; defensive
            # Best-effort drain of any remaining body bytes. We use a
            # short timeout because the client (sudo_trustforge.so /
            # polkit-trustforge-helper) keeps the connection open while
            # waiting for our response -- a blocking recv() here would
            # deadlock.
            conn.settimeout(0.05)
            try:
                conn.recv(65536)
            except (OSError, socket.timeout):
                pass
            conn.settimeout(None)
            sys.stderr.write("---request---\n")
            sys.stderr.write(data.decode("utf-8", errors="replace"))
            sys.stderr.write("\n-------------\n")
            sys.stderr.flush()
            try:
                conn.sendall(response)
            except BrokenPipeError:
                pass


if __name__ == "__main__":
    if len(sys.argv) != 3:
        usage()
    serve(sys.argv[1], sys.argv[2])
