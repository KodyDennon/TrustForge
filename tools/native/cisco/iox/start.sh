#!/bin/sh
# Entrypoint for the TrustForge IOX package.
#
# Cisco Guest Shell hands us a near-empty environment, so we have to
# bootstrap directories, write a config from $TF_* env vars, and exec
# tf-daemon as PID 1.

set -eu

TF_PROFILE="${TF_PROFILE:-tf-enterprise-baseline}"
TF_LISTEN="${TF_LISTEN:-0.0.0.0:8642}"
TF_PROXY_LISTEN="${TF_PROXY_LISTEN:-0.0.0.0:8643}"
TF_STATE_DIR="${TF_STATE_DIR:-/data}"

mkdir -p "${TF_STATE_DIR}/log" "${TF_STATE_DIR}/run" "${TF_STATE_DIR}/etc"

CFG="${TF_STATE_DIR}/etc/config.yaml"
if [ ! -f "${CFG}" ]; then
  cat > "${CFG}" <<EOF
profile: ${TF_PROFILE}

listen:
  bind: ${TF_LISTEN}
  proxy_bind: ${TF_PROXY_LISTEN}
  control_socket: ${TF_STATE_DIR}/run/decide.sock

storage:
  state_dir: ${TF_STATE_DIR}
  log_dir: ${TF_STATE_DIR}/log

crypto:
  hybrid: false
  classical_suite: ed25519-x25519-chacha20poly1305

bridges:
  - kind: tacacs-plus
    enabled: true
  - kind: webauthn
    enabled: true
EOF
fi

# Cisco IOX restarts the container on exit; a clean exit is sufficient
# to recover from a bad config without forcing a privileged reload.
exec /usr/local/bin/tf-daemon --config "${CFG}"
