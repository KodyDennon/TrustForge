# Native Support Matrix

TrustForge is **experimental**. This matrix is the quick truth source for
native, network, and packaging surfaces. Status terms:

- **working reference**: exercised by repo tests or local smoke flows.
- **mock-tested**: tested against a local fake daemon/helper, not a real host integration.
- **hardware-untested**: package/config exists but has not been verified on target hardware.
- **docs-only**: design or install notes exist, but no verified runtime path.
- **planned**: roadmap item only.

| Surface | Status | Default daemon path | Tested environment | Known gaps |
|---|---|---|---|---|
| Linux `tf-daemon` source + systemd | working reference | `/run/trustforge/decide.sock` | Bun tests, local systemd files reviewed | Not production-reviewed; binary/packages not cut. |
| Linux PAM | mock-tested | `/run/trustforge/decide.sock` | C helper + mock daemon scripts | Needs distro install testing and PAM stack review. |
| Linux NSS | mock-tested | `/run/trustforge/decide.sock` | Mock daemon script | Needs glibc/NSS host testing and collision-policy review. |
| Linux sudo plugin | mock-tested | `/run/trustforge/decide.sock` | Mock daemon script | Needs sudo policy plugin install testing. |
| Linux polkit helper | mock-tested | `/run/trustforge/decide.sock` | Mock helper script | Needs real polkitd rule testing. |
| Linux LSM/eBPF | mock-tested | `/run/trustforge/decide.sock` | Loader/tests in repo | Kernel/version coverage incomplete. |
| AppArmor/SELinux policy | docs-only | `/run/trustforge/decide.sock` | Policy files reviewed | Needs distro enforcement testing and audit2allow pass. |
| macOS launchd/PAM/AuthPlugin | mock-tested | `/var/run/trustforge/decide.sock` | Source-level examples | Needs signed/notarized package and real login-window testing. |
| Windows service/Credential Provider/Auth Package | docs-only | Windows service endpoint TBD | Source skeletons | No production installer or end-to-end auth path. |
| FreeBSD/OpenBSD/illumos | docs-only | platform-specific | Source skeletons | No host verification. |
| Kubernetes admission webhook | mock-tested | TCP service / cluster config | Go unit tests | Container image and chart release path still v0.2. |
| Envoy/Istio/Linkerd | mock-tested | TCP/mesh sidecar config | Unit tests where present | No published container images; cluster smoke pending. |
| Tailscale, Pi-hole, UniFi, Consul | hardware-untested | local socket or API sidecar | Unit/source checks only | Needs target-device smoke and rollback docs. |
| OpenWRT, RouterOS, Cisco IOS-XE, VyOS, pfSense/OPNsense | hardware-untested | platform-specific local socket | Package/config source only | Release tarballs/packages are not published yet. |

## v0.2 Contract

TCP `/v1/*` endpoints require bearer auth from the configured admin token.
The Unix-domain socket is the local decision surface: `/v1/decide` and
`/v1/decide-batch` may rely on filesystem ownership, group membership,
service-manager policy, and peer credentials. Admin routes, credential
import, proof signing, proof verification, and privileged mutation
routes stay bearer-gated unless a future spec marks them local-safe.

Linux production defaults use `/run/trustforge/decide.sock`. Per-user
sockets such as `~/.trustforge/decide.sock` are test fixtures or
explicit overrides, not the default production path.
