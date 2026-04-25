#!/usr/bin/env python3
"""Install and register the TrustForge IOX package on a Cisco device.

Uses NX-API (or RESTCONF on IOS-XE) to upload the package, install
it, activate it, and register the management endpoint with the host
device's policy engine.

This script is meant to be run from an admin workstation, not from
inside Guest Shell. It targets a single device via its NX-API URL.

Phase 0 / pre-release: the package tarball referenced does not exist
yet. The script is exercised against a recorded NX-API mock during
upstream conformance tests.
"""

from __future__ import annotations

import argparse
import json
import os
import sys
from typing import Any
from urllib import request, error

PACKAGE_NAME = "trustforge"
DEFAULT_PROFILE = "c1.small"


def nxapi_call(url: str, user: str, password: str, payload: dict[str, Any]) -> dict[str, Any]:
    """POST a single NX-API command payload and return parsed JSON."""
    body = json.dumps(payload).encode("utf-8")
    req = request.Request(
        url,
        data=body,
        method="POST",
        headers={
            "Content-Type": "application/json-rpc",
            "Accept": "application/json",
        },
    )
    auth = f"{user}:{password}".encode("utf-8")
    import base64

    req.add_header("Authorization", "Basic " + base64.b64encode(auth).decode("ascii"))
    try:
        with request.urlopen(req, timeout=30) as resp:
            return json.loads(resp.read().decode("utf-8"))
    except error.HTTPError as exc:
        sys.stderr.write(f"NX-API error {exc.code}: {exc.read().decode('utf-8', 'replace')}\n")
        raise


def cli_command(cmd: str, msg_id: int = 1) -> dict[str, Any]:
    """Build an NX-API JSON-RPC payload for a single CLI command."""
    return {
        "jsonrpc": "2.0",
        "method": "cli",
        "params": {"cmd": cmd, "version": 1},
        "id": msg_id,
    }


def install(host: str, user: str, password: str, package_path: str, profile: str) -> int:
    base = f"https://{host}/ins"

    if not os.path.isfile(package_path):
        sys.stderr.write(f"package not found: {package_path}\n")
        return 2

    pkg_basename = os.path.basename(package_path)

    steps = [
        # Copy the package into bootflash. In a real flow this would
        # be an SCP push; the CLI form keeps the script self-contained.
        f"copy scp://{user}@{host}/{package_path} bootflash:{pkg_basename} vrf management",
        f"app-hosting install appid {PACKAGE_NAME} package bootflash:{pkg_basename}",
        f"app-hosting activate appid {PACKAGE_NAME}",
        f"app-hosting start appid {PACKAGE_NAME}",
    ]

    for i, cmd in enumerate(steps, start=1):
        print(f"[{i}/{len(steps)}] {cmd}", flush=True)
        resp = nxapi_call(base, user, password, cli_command(cmd, msg_id=i))
        if "error" in resp:
            sys.stderr.write(json.dumps(resp["error"], indent=2) + "\n")
            return 1

    # Register tf-daemon with the host policy engine. This emits a
    # TACACS+ <-> TrustForge bridge entry so AAA flows through TF.
    register_cmd = (
        f"aaa group server tacacs+ trustforge\n"
        f" server-private 127.0.0.1 single-connection key 0 trustforge-bridge\n"
        f" exit\n"
        f"aaa authentication login default group trustforge local"
    )
    print(f"[{len(steps)+1}/{len(steps)+1}] register TACACS+ bridge", flush=True)
    resp = nxapi_call(base, user, password, cli_command(register_cmd, msg_id=99))
    if "error" in resp:
        sys.stderr.write(json.dumps(resp["error"], indent=2) + "\n")
        return 1

    print(f"trustforge {profile} installed and active on {host}")
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--host", required=True, help="Device management IP / hostname")
    parser.add_argument("--user", required=True, help="NX-API username")
    parser.add_argument(
        "--password",
        default=os.environ.get("CISCO_PASSWORD", ""),
        help="NX-API password (or set CISCO_PASSWORD env)",
    )
    parser.add_argument("--package", required=True, help="Path to tf-daemon IOX .tar")
    parser.add_argument("--profile", default=DEFAULT_PROFILE)
    args = parser.parse_args()

    if not args.password:
        sys.stderr.write("password required (--password or CISCO_PASSWORD)\n")
        return 2

    return install(args.host, args.user, args.password, args.package, args.profile)


if __name__ == "__main__":
    sys.exit(main())
