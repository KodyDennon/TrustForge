# TrustForgeCredentialProvider

A Windows Credential Provider (COM in-process server) that consults the local
TrustForge daemon for an authorization decision before serializing a credential
to LogonUI. Composes alongside the built-in password provider rather than
replacing it.

**Status:** Draft — Phase 0. Experimental, not production-ready. The
TrustForge daemon exists as a working reference, but this provider remains
useful only for integration testing against the included mock daemon.

## What it does

When the user picks the "TrustForge" tile on the lock screen, sign-in screen,
or in CredUI, the provider:

1. Renders a tile with a username field, a password field, a submit button,
   and a small status line.
2. On submit, opens the named pipe `\\.\pipe\trustforge\decide`.
3. Sends `POST /v1/decide` with this body:

   ```json
   {
     "actor": null,
     "host_token": "<username>",
     "host_token_kind": "interactive-logon",
     "action": "login",
     "target": "winlogon"
   }
   ```

4. If the daemon returns `"decision": "allow"`, the provider packs the
   username + password into a `KERB_INTERACTIVE_UNLOCK_LOGON` and emits
   `CPGSR_RETURN_CREDENTIAL_FINISHED` so LSA continues the logon flow.
5. **Anything else — pipe missing, timeout, non-allow decision, parse error
   — fails closed.** The provider returns `CPGSR_NO_CREDENTIAL_NOT_FINISHED`
   and the daemon's `reason` string surfaces as the tile's status text.

The provider never sends the password to the daemon. The decision is taken
on identity + policy + session state; the password is forwarded to LSA only
once the decision is `allow`.

## Build

This must be built on Windows with Visual Studio 2022 (or 2019) plus the
Windows SDK. **It will not build on macOS or Linux.** The headers
(`credentialprovider.h`, `wincred.h`, `ntsecapi.h`) are Windows-only.

From a Developer Command Prompt:

```cmd
cmake -S . -B build -G "Visual Studio 17 2022" -A x64
cmake --build build --config Release
```

The output is `build\Release\TrustForgeCredentialProvider.dll`. Both `Win32`
and `x64` configurations are supported; install the architecture matching
your `winlogon.exe`.

## Install

1. Copy the DLL to a stable system location, e.g.:

   ```cmd
   xcopy /Y build\Release\TrustForgeCredentialProvider.dll "C:\Program Files\TrustForge\"
   ```

2. From an **elevated** Command Prompt, register the COM class:

   ```cmd
   regsvr32 "C:\Program Files\TrustForge\TrustForgeCredentialProvider.dll"
   ```

   Or, if you prefer the explicit registry route, edit `register.reg` so the
   `InprocServer32` default value points at the install path you used and
   apply it:

   ```cmd
   regedit /s register.reg
   ```

3. Lock the workstation (Win+L) — the TrustForge tile should appear next to
   the standard password tile.

### Installing from WSL or MSYS

`regsvr32` is a Windows binary; it must be invoked with a Windows path,
not a `/mnt/c/...` path. From an elevated WSL shell:

```sh
cmd.exe /c regsvr32 "C:\\Program Files\\TrustForge\\TrustForgeCredentialProvider.dll"
```

Most credential-provider development workflows use a SYSTEM-level shell
(via [PsExec](https://learn.microsoft.com/sysinternals/downloads/psexec)
`psexec -s -i cmd.exe`) so the test session matches the privilege level
that LogonUI runs at. Do this only on dev machines.

## Uninstall

```cmd
regsvr32 /u "C:\Program Files\TrustForge\TrustForgeCredentialProvider.dll"
del "C:\Program Files\TrustForge\TrustForgeCredentialProvider.dll"
```

## Security caveats

- **This DLL is loaded into `winlogon.exe` and `LogonUI.exe` — both run
  as SYSTEM, both are extremely sensitive.** Bugs here can prevent users
  from logging in. Keep the surface area minimal: the provider should only
  collect input fields and call the daemon. Do not put policy logic in the
  DLL.
- The provider links the **static CRT** (`/MT`) to avoid pulling a
  side-by-side VC++ runtime into winlogon.
- The provider zeroes the password buffer in `SetDeselected` and in the
  destructor (`SecureZeroMemory`), but the password necessarily lives
  in the process while the user is typing.
- The named-pipe call has a hard 5-second wait timeout via
  `WaitNamedPipeW`. There is no retry — if the daemon is down, logon via
  the TrustForge tile fails immediately. The standard password tile is
  unaffected.
- We do **not** send the password to the daemon. The daemon decides on
  identity + policy + session context; the password is handed to LSA only
  on `allow`.
- No custom cryptography. All handshake / session work is delegated to the
  daemon, which composes reviewed primitives.
- This is Draft / Phase 0. Do not deploy to production.

## Troubleshooting

- The tile does not appear:
  - Confirm the CLSID values in `register.reg` match the GUID in
    `dllmain.cpp` (`{8B0F8F3D-9E4C-4F2A-B7E1-2C6A5D9F1E03}`).
  - Check that `InprocServer32` points at a path that **exists** for the
    SYSTEM account. `winlogon.exe` cannot read user profiles.
  - Open Event Viewer → Windows Logs → Application, filter on source
    `Microsoft-Windows-Winlogon`. Failed credential-provider loads are
    logged with the failing CLSID.
- Logon always denies:
  - Confirm the daemon is running and listening on
    `\\.\pipe\trustforge\decide`. `Get-ChildItem \\.\pipe\` from PowerShell
    lists active pipes.
  - Tail the daemon log; the daemon emits a structured proof event for
    every decision.
- Logon hangs:
  - Most likely the daemon is reachable but not responding. The provider
    has only a 5-second wait on `WaitNamedPipeW` plus the duration of the
    `ReadFile` loop; if you see longer hangs, the daemon is reading but
    not closing the pipe. Inspect with
    `handle.exe -p winlogon.exe \\.\pipe\trustforge\decide`.

## Files

- `CMakeLists.txt` — MSVC build, links credui / secur32 / advapi32 /
  ole32 / shlwapi.
- `dllmain.cpp` — `DllMain`, COM exports (`DllGetClassObject`,
  `DllCanUnloadNow`, `DllRegisterServer`, `DllUnregisterServer`).
- `TrustForgeCredentialProvider.h` / `.cpp` — `ICredentialProvider`,
  `ICredentialProviderCredential`, the named-pipe HTTP call, hand-rolled
  JSON helpers.
- `register.reg` — registry entries equivalent to `DllRegisterServer`.
