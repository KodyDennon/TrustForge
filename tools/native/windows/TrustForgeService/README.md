# TrustForgeService

A Windows Service Control Manager (SCM) wrapper around the `tf-daemon`
binary. Provides standard service semantics (auto-start, stop, pause,
continue, recovery actions) and a 10-second graceful-shutdown window.

**Status:** Draft — Phase 0. Experimental, not production-ready.

## What it does

- Registers as a SCM service via `StartServiceCtrlDispatcher`.
- On `SERVICE_START`, spawns `C:\Program Files\TrustForge\tf-daemon.exe`
  as a child process. Stdout/stderr are redirected to
  `C:\ProgramData\TrustForge\logs\tf-daemon.log` (append).
- On `SERVICE_CONTROL_STOP` / `SHUTDOWN` / `PAUSE` / `CONTINUE`, sends a
  one-byte control code to the daemon over the named pipe
  `\\.\pipe\trustforge\control` (`s`/`p`/`c`).
- On stop, waits up to **10 seconds** for the daemon to exit cleanly.
  If the deadline elapses, calls `TerminateProcess` and reports
  `SERVICE_STOPPED` with `ERROR_SERVICE_REQUEST_TIMEOUT`.
- If the daemon exits on its own, the service reports `SERVICE_STOPPED`
  with the daemon's exit code so the SCM recovery actions can react.

## Build

Windows-only. Visual Studio 2022 + Windows SDK.

```cmd
cmake -S . -B build -G "Visual Studio 17 2022" -A x64
cmake --build build --config Release
```

Output: `build\Release\TrustForgeService.exe`.

## Install

You **must** be Administrator (elevated Command Prompt). The SCM
operations below require `SeCreateServicePrivilege` /
`SC_MANAGER_CREATE_SERVICE`.

1. Copy the binaries to a stable system path:

   ```cmd
   mkdir "C:\Program Files\TrustForge"
   copy /Y build\Release\TrustForgeService.exe "C:\Program Files\TrustForge\"
   :: Also copy the actual tf-daemon.exe alongside it.
   copy /Y path\to\tf-daemon.exe              "C:\Program Files\TrustForge\"
   ```

2. From an **elevated** Command Prompt:

   ```cmd
   install.cmd
   ```

   Equivalent manual command (what `install.cmd` runs):

   ```cmd
   sc create TrustForge ^
     binPath= "\"C:\Program Files\TrustForge\TrustForgeService.exe\"" ^
     start= auto ^
     type= own ^
     displayname= "TrustForge Authorization Daemon"
   sc description TrustForge "Brokers TrustForge authorization decisions for the local system."
   sc failure     TrustForge reset= 86400 actions= restart/5000/restart/5000/restart/30000
   sc start       TrustForge
   ```

3. Verify:

   ```cmd
   sc query TrustForge
   ```

   You should see `STATE : 4 RUNNING`.

## Uninstall

```cmd
uninstall.cmd
```

Equivalent:

```cmd
sc stop   TrustForge
sc delete TrustForge
```

## Service account permissions

By default `sc create` registers the service to run as `LocalSystem`.
That is appropriate for a daemon that brokers logon/policy decisions
because:

- It needs to bind the named pipe `\\.\pipe\trustforge\decide` with a
  security descriptor that lets `winlogon` and `lsass` connect.
- It needs to read policy files under `C:\ProgramData\TrustForge\`.

If you prefer to drop privileges, you can switch to `LocalService` or a
managed service account *after* you have ACL'd the pipe and the
ProgramData directory appropriately:

```cmd
sc config TrustForge obj= "NT AUTHORITY\LocalService"
```

Note that running under `LocalService` will make some integrations
(e.g. the credential provider and the LSA package) unable to connect
unless the named-pipe ACL explicitly allows the calling SID.

## Logs

- **Service-level events** (start / stop / fault) are written by the SCM
  to the **Application** event log under source `Service Control Manager`
  and `TrustForge`. Open Event Viewer (`eventvwr.msc`) → Windows Logs →
  Application; filter by source `TrustForge`.
- **Daemon stdout/stderr** is redirected to:
  ```
  C:\ProgramData\TrustForge\logs\tf-daemon.log
  ```
  Rotate this file out of band (e.g. with `logman` or a scheduled task);
  the wrapper appends but does not rotate.
- **Structured proof events** (the daemon's audit trail) are written by
  the daemon itself, see `tf-proof` documentation. Path is configurable.

## Troubleshooting

- `sc start TrustForge` returns `1053 (ERROR_SERVICE_REQUEST_TIMEOUT)`:
  - The daemon failed to come up within the SCM's start-pending window.
    Inspect `C:\ProgramData\TrustForge\logs\tf-daemon.log` for the
    crash / config error.
- `sc start TrustForge` returns `1077 (ERROR_SERVICE_NEVER_STARTED)`:
  - Service never reported `SERVICE_RUNNING`. Often the daemon binary is
    missing or its dependencies aren't on PATH.
- The service runs but the credential provider / LSA package can't
  connect to `\\.\pipe\trustforge\decide`:
  - The pipe ACL is wrong. The daemon must create the pipe with a
    security descriptor that grants `FILE_GENERIC_READ |
    FILE_GENERIC_WRITE` to `winlogon` (`S-1-5-18`) and `lsass`. Check
    with `accesschk.exe -p \\.\pipe\trustforge\decide` (Sysinternals).
- Stop hangs for ~10 seconds:
  - That is the graceful-shutdown deadline. If the daemon doesn't accept
    `'s'` on the control pipe, the wrapper falls back to
    `TerminateProcess`. Fix the daemon's control-pipe handler.

## Files

- `CMakeLists.txt` — MSVC build, links `advapi32`, `ole32`.
- `service-main.cpp` — `wmain` -> `StartServiceCtrlDispatcher` -> child
  daemon supervision via `\\.\pipe\trustforge\control`.
- `install.cmd` / `uninstall.cmd` — `sc create` / `sc delete` plus
  description and recovery actions.
