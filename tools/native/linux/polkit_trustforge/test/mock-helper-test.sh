#!/usr/bin/env bash
# mock-helper-test.sh -- exercise polkit-trustforge-helper against a
# Python UNIX-socket mock daemon. We don't need polkitd for this; the
# helper is a plain client binary, so we just invoke it with the same
# argv polkit.spawn() would pass and check stdout / exit code.

set -euo pipefail

here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
helper="$here/../polkit-trustforge-helper"
mock_sock="${TMPDIR:-/tmp}/tf-polkit-test.sock"

# Reuse the sudo plugin's mock daemon if it's present in-tree; we keep
# this test independent by providing a tiny inline copy if not.
mock_py="$here/../../sudo_trustforge/test/mock-daemon.py"
if [[ ! -f "$mock_py" ]]; then
    mock_py="$here/mock-daemon.py"
    cat > "$mock_py" <<'PY'
#!/usr/bin/env python3
import os, sys, json, socket, signal
sock_path, decision = sys.argv[1], sys.argv[2]
try: os.unlink(sock_path)
except FileNotFoundError: pass
s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
s.bind(sock_path); os.chmod(sock_path, 0o600); s.listen(8)
print(f"mock: {sock_path} -> {decision}", file=sys.stderr, flush=True)
def shutdown(*_):
    try: os.unlink(sock_path)
    except OSError: pass
    sys.exit(0)
signal.signal(signal.SIGINT, shutdown); signal.signal(signal.SIGTERM, shutdown)
body = json.dumps({"decision": decision}).encode()
resp = (b"HTTP/1.0 200 OK\r\nContent-Type: application/json\r\n"
        b"Content-Length: " + str(len(body)).encode() + b"\r\n"
        b"Connection: close\r\n\r\n" + body)
while True:
    c, _ = s.accept()
    with c:
        d = b""
        while b"\r\n\r\n" not in d:
            chunk = c.recv(4096)
            if not chunk: break
            d += chunk
            if len(d) > 1<<20: break
        c.settimeout(0.05)
        try: c.recv(65536)
        except (OSError, socket.timeout): pass
        c.settimeout(None)
        sys.stderr.write(d.decode("utf-8", "replace") + "\n")
        sys.stderr.flush()
        try: c.sendall(resp)
        except BrokenPipeError: pass
PY
    chmod +x "$mock_py"
fi

cleanup() {
    [[ -n "${mock_pid:-}" ]] && kill "$mock_pid" 2>/dev/null || true
    rm -f "$mock_sock"
}
trap cleanup EXIT

if [[ ! -x "$helper" ]]; then
    echo "ERROR: $helper not built; run \`make\` first." >&2
    exit 1
fi

start_mock() {
    local decision="$1"
    python3 "$mock_py" "$mock_sock" "$decision" &
    mock_pid=$!
    for _ in $(seq 1 50); do
        [[ -S "$mock_sock" ]] && break
        sleep 0.05
    done
}
stop_mock() {
    [[ -n "${mock_pid:-}" ]] && kill "$mock_pid" 2>/dev/null || true
    wait "${mock_pid:-}" 2>/dev/null || true
    rm -f "$mock_sock"
    mock_pid=""
}

# ---- case 1: allow ----------------------------------------------------
echo "[test] allow path"
start_mock allow
out="$(TRUSTFORGE_SOCKET="$mock_sock" HOME=/tmp \
        "$helper" org.freedesktop.policykit.exec testuser)"
rc=$?
stop_mock
if [[ "$out" != "yes" ]] || [[ $rc -ne 0 ]]; then
    echo "FAIL: allow -> stdout='$out' rc=$rc (expected 'yes' rc=0)" >&2
    exit 1
fi
echo "  ok"

# ---- case 2: deny -----------------------------------------------------
echo "[test] deny path"
start_mock deny
out="$(TRUSTFORGE_SOCKET="$mock_sock" HOME=/tmp \
        "$helper" org.freedesktop.policykit.exec testuser || true)"
rc=$?
stop_mock
if [[ "$out" != "no" ]]; then
    echo "FAIL: deny -> stdout='$out' rc=$rc (expected 'no')" >&2
    exit 1
fi
echo "  ok"

# ---- case 3: daemon unreachable --------------------------------------
echo "[test] fail-closed when daemon unreachable"
out="$(TRUSTFORGE_SOCKET=/nonexistent/socket HOME=/tmp \
        "$helper" org.freedesktop.policykit.exec testuser || true)"
if [[ "$out" != "no" ]]; then
    echo "FAIL: unreachable -> stdout='$out' (expected 'no')" >&2
    exit 1
fi
echo "  ok"

# ---- case 4: missing args --------------------------------------------
echo "[test] missing args -> 'no'"
out="$("$helper" || true)"
if [[ "$out" != "no" ]]; then
    echo "FAIL: missing args -> stdout='$out' (expected 'no')" >&2
    exit 1
fi
echo "  ok"

echo "PASS"
