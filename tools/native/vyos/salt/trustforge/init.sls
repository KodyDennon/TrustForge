# Salt state: install and configure tf-daemon on a VyOS router.
#
# Apply with:
#   sudo salt-call --local state.apply trustforge
#
# Phase 0 / pre-release: the binary tarballs referenced below do not
# exist yet; they are produced by upstream CI when v0.1.0 is tagged.
# Until then this state is for review and salt-system testing only.

{% set tf = salt['pillar.get']('trustforge', {}) %}
{% set version = tf.get('version', '0.1.0') %}
{% set arch = tf.get('arch', 'x86_64-unknown-linux-musl') %}
{% set profile = tf.get('profile', 'tf-home-compatible') %}
{% set listen = tf.get('listen', '127.0.0.1:8642') %}

trustforge_user:
  user.present:
    - name: trustforge
    - system: True
    - shell: /usr/sbin/nologin
    - home: /var/lib/trustforge
    - createhome: True

trustforge_dirs:
  file.directory:
    - names:
      - /etc/trustforge
      - /var/lib/trustforge
      - /var/log/trustforge
      - /var/run/trustforge
    - user: trustforge
    - group: trustforge
    - mode: 0750
    - require:
      - user: trustforge_user

trustforge_binary:
  archive.extracted:
    - name: /usr/local/bin/
    - source: https://github.com/trustforge/trustforge/releases/download/v{{ version }}/tf-daemon-{{ arch }}.tar.gz
    - source_hash: {{ tf.get('source_hash', 'sha256=0000000000000000000000000000000000000000000000000000000000000000') }}
    - archive_format: tar
    - enforce_toplevel: False
    - if_missing: /usr/local/bin/tf-daemon
    - keep_source: False

trustforge_binary_perms:
  file.managed:
    - name: /usr/local/bin/tf-daemon
    - user: root
    - group: root
    - mode: 0755
    - replace: False
    - require:
      - archive: trustforge_binary

trustforge_config:
  file.managed:
    - name: /etc/trustforge/config.yaml
    - source: salt://trustforge/files/config.yaml.j2
    - template: jinja
    - user: trustforge
    - group: trustforge
    - mode: 0640
    - context:
        profile: {{ profile }}
        listen: {{ listen }}
        bridges: {{ tf.get('bridges', []) }}
    - require:
      - file: trustforge_dirs

trustforge_firewall:
  file.managed:
    - name: /config/scripts/trustforge-firewall.sh
    - source: salt://trustforge/files/firewall.j2
    - template: jinja
    - user: root
    - group: vyattacfg
    - mode: 0755
    - context:
        listen: {{ listen }}
        proxy_port: {{ tf.get('proxy_port', 8643) }}
        gated_interfaces: {{ tf.get('gated_interfaces', ['eth1']) }}

trustforge_service:
  file.managed:
    - name: /etc/systemd/system/trustforge.service
    - mode: 0644
    - contents: |
        [Unit]
        Description=TrustForge daemon (tf-daemon)
        Documentation=https://github.com/trustforge/trustforge
        After=network-online.target
        Wants=network-online.target

        [Service]
        Type=notify
        User=trustforge
        Group=trustforge
        ExecStart=/usr/local/bin/tf-daemon --config /etc/trustforge/config.yaml
        Restart=on-failure
        RestartSec=5s
        AmbientCapabilities=CAP_NET_BIND_SERVICE
        NoNewPrivileges=true
        ProtectSystem=strict
        ProtectHome=true
        ReadWritePaths=/var/log/trustforge /var/run/trustforge /var/lib/trustforge

        [Install]
        WantedBy=multi-user.target

  service.running:
    - name: trustforge
    - enable: True
    - watch:
      - file: trustforge_config
      - file: trustforge_service
      - file: trustforge_binary_perms
