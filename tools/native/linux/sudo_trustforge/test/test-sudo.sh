#!/usr/bin/env bash
# test-sudo.sh -- integration test for sudo_trustforge.so
#
# Strategy: we do *not* require a real /etc/sudo.conf for the test, because
# that needs root and would interfere with the host's sudo. Instead we
# build a tiny C loader that dlopens the plugin, invokes policy_open and
# policy_check just like sudo would, and asserts on the return code.
#
# We then run the loader twice against a Python mock daemon -- once with
# the mock returning allow, once returning deny -- and verify behaviour.

set -euo pipefail

here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
plugin="$here/../sudo_trustforge.so"
loader="$here/loader"
mock_sock="${TMPDIR:-/tmp}/tf-sudo-test.sock"

cleanup() {
    [[ -n "${mock_pid:-}" ]] && kill "$mock_pid" 2>/dev/null || true
    rm -f "$mock_sock" "$loader"
}
trap cleanup EXIT

if [[ ! -f "$plugin" ]]; then
    echo "ERROR: $plugin not built; run \`make\` first." >&2
    exit 1
fi

# ---- build the loader -------------------------------------------------
cat > "$loader.c" <<'LOADER'
/*
 * Minimal sudo-plugin host. Dlopens the policy plugin, calls its
 * standard entry points the way sudo does, and reports the result.
 */
#include <dlfcn.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sudo_plugin.h>

static int conv_stub(int n, const struct sudo_conv_message m[],
                     struct sudo_conv_reply r[],
                     struct sudo_conv_callback *cb) {
    (void)n; (void)m; (void)r; (void)cb;
    return 0;
}
static int printf_stub(int level, const char *fmt, ...) {
    (void)level;
    va_list ap; va_start(ap, fmt);
    vfprintf(stderr, fmt, ap);
    va_end(ap);
    return 0;
}

int main(int argc, char **argv) {
    if (argc < 3) {
        fprintf(stderr, "usage: %s <plugin.so> <cmd> [args...]\n", argv[0]);
        return 2;
    }
    void *h = dlopen(argv[1], RTLD_NOW | RTLD_LOCAL);
    if (!h) { fprintf(stderr, "dlopen: %s\n", dlerror()); return 2; }
    struct policy_plugin *p = dlsym(h, "sudoers_policy");
    if (!p) { fprintf(stderr, "dlsym: %s\n", dlerror()); return 2; }

    char *settings[]  = { NULL };
    char *user_info[] = { NULL };
    char *user_env[]  = { NULL };
    char *plugin_opts[] = { NULL };

    int ok = p->open(SUDO_API_VERSION, conv_stub, printf_stub,
                     settings, user_info, user_env, plugin_opts);
    if (ok != 1) { fprintf(stderr, "policy_open failed: %d\n", ok); return 2; }

    int cargc = argc - 2;
    char **cargv = &argv[2];

    char **info = NULL, **out_argv = NULL, **out_env = NULL;
    int rc = p->check_policy(cargc, cargv, NULL, &info, &out_argv, &out_env);
    fprintf(stderr, "check_policy => %d\n", rc);

    if (p->close) p->close(0, 0);
    dlclose(h);
    return rc == 1 ? 0 : 1;
}
LOADER

cc -O0 -g -Wall -o "$loader" "$loader.c" -ldl
rm -f "$loader.c"

# ---- helper: start mock with a given decision -------------------------
start_mock() {
    local decision="$1"
    python3 "$here/mock-daemon.py" "$mock_sock" "$decision" &
    mock_pid=$!
    # Wait for socket to appear.
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
TRUSTFORGE_SOCKET="$mock_sock" SUDO_USER=testuser HOME=/tmp \
    "$loader" "$plugin" /bin/ls -la /tmp
rc=$?
stop_mock
if [[ $rc -ne 0 ]]; then
    echo "FAIL: allow path returned $rc, expected 0" >&2
    exit 1
fi
echo "  ok"

# ---- case 2: deny -----------------------------------------------------
echo "[test] deny path"
start_mock deny
TRUSTFORGE_SOCKET="$mock_sock" SUDO_USER=testuser HOME=/tmp \
    "$loader" "$plugin" /bin/rm -rf / || rc=$?
stop_mock
if [[ ${rc:-0} -ne 1 ]]; then
    echo "FAIL: deny path returned ${rc:-0}, expected 1" >&2
    exit 1
fi
echo "  ok"

# ---- case 3: daemon unreachable --------------------------------------
echo "[test] fail-closed when daemon unreachable"
TRUSTFORGE_SOCKET="/nonexistent/socket" SUDO_USER=testuser HOME=/tmp \
    "$loader" "$plugin" /bin/ls || rc=$?
if [[ ${rc:-0} -ne 1 ]]; then
    echo "FAIL: unreachable daemon returned ${rc:-0}, expected 1 (deny)" >&2
    exit 1
fi
echo "  ok"

echo "PASS"
