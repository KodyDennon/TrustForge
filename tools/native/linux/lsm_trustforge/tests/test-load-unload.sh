#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
#
# Sanity test: build, load, observe, and unload the TrustForge LSM module.
#
# Usage:  sudo bash tests/test-load-unload.sh [KDIR]
#
# This script does NOT exercise the userspace bridge or the daemon; it
# only proves that the module can be inserted and removed cleanly on
# the running kernel.

set -euo pipefail

KDIR="${1:-/lib/modules/$(uname -r)/build}"
HERE="$(cd "$(dirname "$0")/.." && pwd)"
MOD="trustforge_lsm"
KO="$HERE/${MOD}.ko"

log() { printf '[test-load-unload] %s\n' "$*"; }

if [[ "$(id -u)" -ne 0 ]]; then
  echo "must run as root (insmod/rmmod require CAP_SYS_MODULE)" >&2
  exit 2
fi

if [[ ! -d "$KDIR" ]]; then
  echo "kernel build dir not found: $KDIR" >&2
  echo "install kernel headers (linux-headers-\$(uname -r) on Debian/Ubuntu)" >&2
  exit 2
fi

log "building module against $KDIR"
make -C "$HERE" KDIR="$KDIR" module

log "inserting $MOD"
insmod "$KO" timeout_ms=100 fail_open=1

log "verifying lsmod sees it"
lsmod | grep -q "^$MOD" || { echo "module not visible in lsmod" >&2; exit 1; }

log "checking dmesg for init banner"
dmesg | tail -n 50 | grep -q "trustforge: LSM init" || \
  log "warning: init banner not found in last 50 lines of dmesg"

log "removing module"
rmmod "$MOD"

log "verifying lsmod no longer lists it"
if lsmod | grep -q "^$MOD"; then
  echo "module still loaded after rmmod" >&2
  exit 1
fi

log "OK"
