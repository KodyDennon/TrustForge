# TrustForgeLsa — Windows LSA Authentication Package

A consultative LSA Authentication Package that brokers Windows logon
attempts through the local TrustForge daemon before letting MSV1_0 or
Kerberos finish the credential check.

**Status:** Draft — Phase 0. Experimental, NOT production-ready.

> ## STOP. READ THIS FIRST.
>
> An LSA authentication package is loaded into `lsass.exe` at boot. If the
> DLL is missing, malformed, returns an invalid status from
> `LsaApInitializePackage`, or raises an exception at any point during a
> logon, **`lsass.exe` will fail to start and the machine will become
> unbootable from the regular login screen.**
>
> Recovery requires either:
> - Booting into Safe Mode and removing the package from
>   `HKLM\System\CurrentControlSet\Control\Lsa\Authentication Packages`, or
> - WinRE / installation-media offline registry edit, or
> - Restoring a snapshot.
>
> **Test only on a VM with a fresh snapshot. Always preserve an
> Administrator account whose logon does not depend on this package
> (e.g. a local Administrator using the standard MSV1_0 path).**

## What it does

For every interactive, network, batch, service, unlock, RDP, or cached
logon attempt, the package:

1. Receives `LsaApLogonUserEx2` from `lsass.exe`.
2. Extracts the domain + username from the `KERB_INTERACTIVE_LOGON` submit
   buffer (passwords are **not** forwarded to the daemon).
3. Opens `\\.\pipe\trustforge\decide` and issues `POST /v1/decide` with:

   ```json
   {
     "actor": null,
     "host_token": "DOMAIN\\user",
     "host_token_kind": "lsa-logon",
     "action": "login" | "login.network" | "login.rdp" | ...,
     "target": "lsass"
   }
   ```

4. If the daemon returns `"decision": "allow"`, the package returns
   `STATUS_NOT_IMPLEMENTED`, which makes LSA fall through to the next
   package (typically MSV1_0/Kerberos) for the actual credential check.
5. Anything else — pipe missing, timeout, parse error, `decision != "allow"`
   — returns `STATUS_LOGON_FAILURE` with substatus
   `STATUS_ACCOUNT_RESTRICTION`. **Fail closed.**

The package is *consultative* on purpose. It never issues a token of its
own and never replaces the credential check. Removing the package from
the LSA list reverts behaviour to vanilla Windows.

## Build

This must be built on Windows with Visual Studio 2022 + Windows SDK.
**Will not build on macOS / Linux.**

```cmd
cmake -S . -B build -G "Visual Studio 17 2022" -A x64
cmake --build build --config Release
```

Static-CRT, `/GS`, `/DYNAMICBASE`, `/NXCOMPAT` are enabled — the binary
must not depend on a side-by-side VC++ runtime because `lsass.exe` runs
before all but the most basic services.

## Install

1. **Snapshot the VM.** Now. Not after, now.
2. Copy `TrustForgeLsa.dll` into `C:\Windows\System32\`. LSA loads
   packages from `System32` by short name only:

   ```cmd
   copy /Y build\Release\TrustForgeLsa.dll C:\Windows\System32\
   ```

3. **Inspect** the existing list before merging:

   ```cmd
   reg query "HKLM\System\CurrentControlSet\Control\Lsa" /v "Authentication Packages"
   ```

   The default value is the `REG_MULTI_SZ` `msv1_0`. If you see other
   entries (Credential Guard, third-party MFA, etc.), **edit
   `register.reg` to append `TrustForgeLsa` to your existing list** —
   do not let the file as shipped clobber your packages.

4. From an **elevated** Command Prompt:

   ```cmd
   regedit /s register.reg
   ```

5. **Reboot.** The package list is read by `lsass.exe` only at boot.

## Uninstall

1. Remove `TrustForgeLsa` from
   `HKLM\System\CurrentControlSet\Control\Lsa\Authentication Packages`.
2. Reboot.
3. Delete `C:\Windows\System32\TrustForgeLsa.dll` (a freshly-booted
   `lsass.exe` will no longer hold a handle on it).

## Recovery if you bricked the box

1. Boot to Safe Mode (in Safe Mode `lsass.exe` loads only a minimal
   package set; TrustForgeLsa may load there too — if so, fall back to
   step 2).
2. Boot WinRE → Command Prompt → load the `SYSTEM` hive offline:

   ```cmd
   reg load HKLM\OFFSYS C:\Windows\System32\config\SYSTEM
   reg query   "HKLM\OFFSYS\ControlSet001\Control\Lsa" /v "Authentication Packages"
   reg add     "HKLM\OFFSYS\ControlSet001\Control\Lsa" /v "Authentication Packages" /t REG_MULTI_SZ /d "msv1_0" /f
   reg unload  HKLM\OFFSYS
   ```

3. Reboot.

## Security caveats

- **`lsass.exe` is the most security-sensitive process on Windows.** A
  bug here is critical. Treat every change as a security review.
- The package links the static CRT and avoids dynamic allocation in the
  fast path. The named-pipe call has a 3-second wait timeout; if the
  daemon is slow, logons fail.
- The package does **not** receive or forward passwords. It decides on
  identity + policy only; the password path stays in MSV1_0/Kerberos.
- No custom cryptography. TrustForge composes reviewed primitives.
- Phase 0 / Draft — do not deploy to production.

## Troubleshooting

- Logons always fail:
  - From a working admin shell, check that
    `\\.\pipe\trustforge\decide` exists. If not, the daemon is down — by
    design, every logon then denies. Stop the package from the registry
    and reboot to recover.
- Verify the package is loaded: from elevated cmd:

  ```cmd
  reg query "HKLM\System\CurrentControlSet\Control\Lsa" /v "Authentication Packages"
  ```

- Event Viewer → Windows Logs → System / Security: `Microsoft-Windows-LSA`
  logs package load failures with package name and NTSTATUS.

## Files

- `CMakeLists.txt` — MSVC build (`/MT`, `/GS`, links `secur32`,
  `advapi32`, `ntdll`).
- `TrustForgeLsa.cpp` — the four LSA entry points
  (`LsaApInitializePackage`, `LsaApLogonUserEx2`, `LsaApLogonTerminated`,
  `LsaApCallPackage`) plus a legacy `LsaApLogonUser` shim and the
  named-pipe HTTP/JSON glue.
- `register.reg` — appends `TrustForgeLsa` to `HKLM\System\CurrentControlSet\Control\Lsa\Authentication Packages` (REG_MULTI_SZ). **Reboot required.**
