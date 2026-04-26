# pledge-trustforge — TrustForge OpenBSD supervisor

OpenBSD does **not** expose an LSM-style kernel framework. The closest
idiomatic equivalent is the `pledge(2)` / `unveil(2)` pair, which let
a process voluntarily restrict itself to a subset of syscalls and
filesystem paths. `tf-pledge-supervisor` is a TrustForge-aware
supervisor that:

1. Reads a YAML policy describing the child to run, the pledge
   promises it should request, and the unveil paths it needs.
2. Asks the local TrustForge daemon (`/v1/decide`) whether the child
   is allowed to start with the requested capabilities and whether
   each unveil entry is permitted (the daemon may downgrade `rwc` to
   `r`, or shrink the promise set).
3. fork+exec()s the child via a re-exec helper that calls `unveil(2)`
   then `pledge(2)` and finally `execve(2)` of the real binary.
4. Watches the child for exit / signal and reports a structured
   outcome back to the daemon.

This is the closest analog of an LSM port available on OpenBSD: the
supervisor mediates pledge/unveil decisions cooperatively. It is not
a kernel hook — a hostile child that does not go through this
supervisor is unaffected.

> Status: **experimental**. Not production-ready.

## Layout

| Path                                                    | Purpose                                       |
|---------------------------------------------------------|-----------------------------------------------|
| `cmd/tf-pledge-supervisor/main.go`                      | Entry point; argument parsing                 |
| `cmd/tf-pledge-supervisor/policy.go`                    | YAML policy loader + validator                |
| `cmd/tf-pledge-supervisor/sync.go`                      | TrustForge `/v1/decide` client                |
| `cmd/tf-pledge-supervisor/supervise.go`                 | Decision loop + spawner interface             |
| `cmd/tf-pledge-supervisor/syscalls_openbsd.go`          | `pledge`/`unveil` re-exec spawner (OpenBSD)   |
| `cmd/tf-pledge-supervisor/syscalls_other.go`            | No-op spawner stub for dev hosts              |
| `cmd/tf-pledge-supervisor/supervise_test.go`            | Unit tests (host-portable)                    |
| `examples/pledge-policy.yaml`                           | Example: static httpd                         |
| `etc/rc.d/tf-pledge-supervisor`                         | OpenBSD rc.d service script                   |

## Building

```sh
cd cmd/tf-pledge-supervisor
go vet ./...
go test ./...
go build -o tf-pledge-supervisor .
```

The binary compiles on any host. Real `pledge(2)` / `unveil(2)`
syscalls are only invoked when built on OpenBSD; on macOS / Linux the
spawner is a no-op stub so unit tests can run on developer machines.

## Running

```sh
sudo install -m 0755 tf-pledge-supervisor /usr/local/sbin/
sudo install -d /etc/trustforge
sudo install -m 0644 examples/pledge-policy.yaml \
    /etc/trustforge/pledge-policy.yaml
sudo install -m 0755 etc/rc.d/tf-pledge-supervisor /etc/rc.d/

# Verify what the supervisor would do:
sudo tf-pledge-supervisor \
    --policy=/etc/trustforge/pledge-policy.yaml \
    --daemon=http://127.0.0.1:8787/v1/decide \
    --dry-run -v

# Run as a service:
sudo rcctl enable tf_pledge_supervisor
sudo rcctl start  tf_pledge_supervisor
```

## Policy file

See `examples/pledge-policy.yaml` for an annotated example. Required
top-level keys:

| Key             | Type             | Meaning                                                  |
|-----------------|------------------|----------------------------------------------------------|
| `name`          | string           | Stable identifier; used in daemon decisions and logs     |
| `exec`          | sequence<string> | argv (first element absolute path)                       |
| `promises`      | sequence<string> | pledge(2) promises to request                            |
| `exec_promises` | sequence<string> | retained across exec(2); subset of `promises`            |
| `unveil`        | sequence<map>    | `{path, perm}` entries; perm is a subset of `rwxc`       |
| `env`           | sequence<string> | `KEY=VALUE` pairs; if omitted, supervisor env is inherited|
| `cwd`           | string           | Optional working directory for the child                 |

The supervisor's YAML reader is a small subset of the spec —
sufficient for the structures above; production deployments can
generate the same shape from JSON.

## Decision protocol

The supervisor calls `/v1/decide` three times per child run:

| `kind`            | When                          | Daemon may                                     |
|-------------------|-------------------------------|------------------------------------------------|
| `pledge_start`    | Before fork                   | Deny outright; or shrink `Promises` / `ExecProm` |
| `pledge_unveil`   | Once per `UnveilEntry`        | Deny entry; or downgrade `Perm` (e.g. `rwc`→`r`)|
| `pledge_outcome`  | After child exits             | Best-effort log; no enforcement                  |

Failure modes (`--fail-open=true|false`) control what happens when the
daemon is unreachable. The default is **fail-closed** — stricter than
the LSM port, because OpenBSD's pledge promises are explicit
capabilities the user has chosen and the safest fallback is to deny.

## Limitations

- A hostile process that does not invoke this supervisor cannot be
  restricted — pledge/unveil are voluntary. Mandatory enforcement is
  not available on OpenBSD without a custom kernel patch.
- The current spawner uses a re-exec helper because Go's runtime
  starts threads that can be incompatible with the most restrictive
  promise sets. The single-threaded re-exec child is what actually
  calls `pledge(2)` and then `execve(2)`s the target.
- `pledge_outcome` is fire-and-forget; the supervisor does not block
  on the daemon's reply. Drop-in TrustForge policies should not rely
  on its synchronous arrival.

## See also

- [`pledge(2)`](https://man.openbsd.org/pledge.2) and
  [`unveil(2)`](https://man.openbsd.org/unveil.2) on OpenBSD.
- `tools/native/linux/lsm_trustforge/` — the Linux LSM port; mediates
  the same TrustForge decision events but in-kernel.
- `tools/native/freebsd/mac_trustforge/` — the FreeBSD MAC framework
  port.
- `docs/specs/TF-0009-enforcement-and-quarantine.md` — enforcement
  model the daemon implements.
