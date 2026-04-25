# Sample Salt pillar for the trustforge formula.
#
# Drop into /srv/pillar/trustforge.sls (or assign via top.sls) and
# adjust per-host. None of these values are secrets; bridge issuer
# pubkeys live in encrypted pillar (`gpg` or `vault`) instead.

trustforge:
  version: 0.1.0
  arch: aarch64-unknown-linux-musl
  source_hash: sha256=0000000000000000000000000000000000000000000000000000000000000000

  # See docs/profiles/ in the upstream repo. Home gear should stay on
  # tf-home-compatible until an admin opts into stricter profiles.
  profile: tf-home-compatible

  listen: 127.0.0.1:8642
  proxy_port: 8643

  # Interfaces whose new outbound flows must clear tf-proxy.
  gated_interfaces:
    - eth1
    - eth2

  bridges:
    - kind: webauthn
      enabled: true
    - kind: oauth-gnap
      enabled: true
      options:
        issuer_match: https://login.microsoftonline.com
    - kind: tls
      enabled: false
