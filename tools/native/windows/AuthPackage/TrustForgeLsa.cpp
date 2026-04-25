// TrustForgeLsa.cpp
//
// Windows LSA Authentication Package — TrustForgeLsa.dll.
//
// Status: Draft — Phase 0. Experimental, NOT production-ready.
//
// !!! WARNING — A FAULT HERE BRICKS THE BOX !!!
// LSA authentication packages are loaded by lsass.exe at boot. A package
// that fails LsaApInitializePackage, raises an exception, or returns
// invalid status from LsaApLogonUserEx2 can prevent any user from logging
// on. ALWAYS test in a VM with a snapshot. ALWAYS keep an Administrator
// account whose logon path does NOT depend on this package (i.e. a local
// Administrator that authenticates via the standard MSV1_0 path).
//
// This package is consultative: on LsaApLogonUserEx2 it forwards the logon
// attempt to the TrustForge daemon over `\\.\pipe\trustforge\decide` and
// returns STATUS_LOGON_FAILURE if the daemon denies. On allow, it returns
// STATUS_NOT_IMPLEMENTED — which causes LSA to fall through to the next
// package in the list (typically MSV1_0). This composability prevents the
// package from accidentally short-circuiting Kerberos / NTLM and lets the
// admin remove TrustForgeLsa from the package list cleanly.

#define WIN32_LEAN_AND_MEAN
#define SECURITY_WIN32
#include <windows.h>
#include <ntsecapi.h>
#include <ntsecpkg.h>
#include <ntstatus.h>
#include <wchar.h>
#include <stdio.h>

// LSA dispatch table provided by lsass.exe.
static PLSA_SECPKG_FUNCTION_TABLE g_pLsaFunctions = nullptr;
static ULONG g_PackageId = 0;

// Package name (ASCII, used by LSA in package lists).
static const char kPackageNameA[] = "TrustForgeLsa";

// ---------------------------------------------------------------------------
// Tiny pipe + JSON helpers (mirror of the credential-provider helpers but
// callable from lsass with no CRT-allocated wide-string handling).
// ---------------------------------------------------------------------------

static int TfJsonEscape(const char* in, char* out, size_t outLen)
{
    size_t o = 0;
    for (size_t i = 0; in && in[i]; ++i) {
        unsigned char c = (unsigned char)in[i];
        const char* esc = nullptr;
        char ebuf[8];
        switch (c) {
        case '"':  esc = "\\\""; break;
        case '\\': esc = "\\\\"; break;
        case '\n': esc = "\\n";  break;
        case '\r': esc = "\\r";  break;
        case '\t': esc = "\\t";  break;
        default:
            if (c < 0x20) {
                _snprintf_s(ebuf, sizeof(ebuf), _TRUNCATE, "\\u%04x", c);
                esc = ebuf;
            }
            break;
        }
        if (esc) {
            for (size_t k = 0; esc[k]; ++k) {
                if (o + 1 >= outLen) return -1;
                out[o++] = esc[k];
            }
        } else {
            if (o + 1 >= outLen) return -1;
            out[o++] = (char)c;
        }
    }
    if (o >= outLen) return -1;
    out[o] = '\0';
    return (int)o;
}

static BOOL TfFindJsonString(const char* json, const char* key, char* out, size_t outLen)
{
    if (!json || !key || !out || outLen == 0) return FALSE;
    char needle[64];
    _snprintf_s(needle, sizeof(needle), _TRUNCATE, "\"%s\"", key);
    const char* p = strstr(json, needle);
    if (!p) return FALSE;
    p += strlen(needle);
    while (*p == ' ' || *p == '\t' || *p == ':' || *p == '\r' || *p == '\n') ++p;
    if (*p != '"') return FALSE;
    ++p;
    size_t o = 0;
    while (*p && *p != '"' && o + 1 < outLen) {
        if (*p == '\\' && p[1]) { out[o++] = p[1]; p += 2; }
        else { out[o++] = *p++; }
    }
    if (*p != '"') return FALSE;
    out[o] = '\0';
    return TRUE;
}

// Convert a UNICODE_STRING (which is NOT necessarily null-terminated) into a
// UTF-8 buffer.
static BOOL TfUStrToUtf8(const UNICODE_STRING* us, char* out, size_t outLen)
{
    if (!us || !out || outLen == 0) return FALSE;
    if (us->Length == 0) { out[0] = '\0'; return TRUE; }
    int cch = us->Length / sizeof(WCHAR);
    int n = WideCharToMultiByte(CP_UTF8, 0, us->Buffer, cch, out, (int)outLen - 1, nullptr, nullptr);
    if (n <= 0) return FALSE;
    out[n] = '\0';
    return TRUE;
}

// Returns:
//   STATUS_SUCCESS         — daemon allowed
//   STATUS_LOGON_FAILURE   — daemon denied or unreachable (fail closed)
static NTSTATUS TfDaemonDecide(const UNICODE_STRING* domain,
                               const UNICODE_STRING* user,
                               const char* action)
{
    char domU8[256] = {};
    char userU8[256] = {};
    TfUStrToUtf8(domain, domU8, sizeof(domU8));
    TfUStrToUtf8(user,   userU8, sizeof(userU8));

    char domEsc[1024], userEsc[1024];
    if (TfJsonEscape(domU8,  domEsc,  sizeof(domEsc))  < 0) return STATUS_LOGON_FAILURE;
    if (TfJsonEscape(userU8, userEsc, sizeof(userEsc)) < 0) return STATUS_LOGON_FAILURE;

    char body[2048];
    int bodyLen = _snprintf_s(body, sizeof(body), _TRUNCATE,
        "{"
        "\"actor\":null,"
        "\"host_token\":\"%s\\\\%s\","
        "\"host_token_kind\":\"lsa-logon\","
        "\"action\":\"%s\","
        "\"target\":\"lsass\""
        "}",
        domEsc, userEsc, action);
    if (bodyLen < 0) return STATUS_LOGON_FAILURE;

    char req[4096];
    int reqLen = _snprintf_s(req, sizeof(req), _TRUNCATE,
        "POST /v1/decide HTTP/1.1\r\n"
        "Host: trustforge\r\n"
        "Content-Type: application/json\r\n"
        "Content-Length: %d\r\n"
        "Connection: close\r\n"
        "\r\n"
        "%s",
        bodyLen, body);
    if (reqLen < 0) return STATUS_LOGON_FAILURE;

    LPCWSTR kPipe = L"\\\\.\\pipe\\trustforge\\decide";
    if (!WaitNamedPipeW(kPipe, 3000)) return STATUS_LOGON_FAILURE;

    HANDLE hPipe = CreateFileW(kPipe,
                               GENERIC_READ | GENERIC_WRITE,
                               0, nullptr, OPEN_EXISTING, 0, nullptr);
    if (hPipe == INVALID_HANDLE_VALUE) return STATUS_LOGON_FAILURE;

    DWORD mode = PIPE_READMODE_BYTE;
    SetNamedPipeHandleState(hPipe, &mode, nullptr, nullptr);

    DWORD written = 0;
    BOOL ok = WriteFile(hPipe, req, (DWORD)reqLen, &written, nullptr);
    if (!ok || written != (DWORD)reqLen) {
        CloseHandle(hPipe);
        return STATUS_LOGON_FAILURE;
    }

    char resp[8192] = {};
    DWORD totalRead = 0;
    while (totalRead < sizeof(resp) - 1) {
        DWORD n = 0;
        if (!ReadFile(hPipe, resp + totalRead,
                      (DWORD)(sizeof(resp) - 1 - totalRead), &n, nullptr)) {
            DWORD err = GetLastError();
            if (err == ERROR_BROKEN_PIPE || err == ERROR_HANDLE_EOF) break;
            CloseHandle(hPipe);
            return STATUS_LOGON_FAILURE;
        }
        if (n == 0) break;
        totalRead += n;
    }
    CloseHandle(hPipe);
    resp[totalRead] = '\0';

    const char* body0 = strstr(resp, "\r\n\r\n");
    if (!body0) return STATUS_LOGON_FAILURE;
    body0 += 4;

    char decision[32] = {};
    if (!TfFindJsonString(body0, "decision", decision, sizeof(decision))) {
        return STATUS_LOGON_FAILURE;
    }
    if (strcmp(decision, "allow") == 0) return STATUS_SUCCESS;
    return STATUS_LOGON_FAILURE;
}

// ---------------------------------------------------------------------------
// LSA authentication-package entry points
// ---------------------------------------------------------------------------

extern "C" NTSTATUS NTAPI LsaApInitializePackage(
    ULONG AuthenticationPackageId,
    PLSA_DISPATCH_TABLE LsaDispatchTable,
    PLSA_STRING /*Database*/,
    PLSA_STRING /*Confidentiality*/,
    PLSA_STRING* AuthenticationPackageName)
{
    g_PackageId = AuthenticationPackageId;
    (void)LsaDispatchTable;

    // Allocate the name LSA hands back as the package's identifier.
    USHORT nameLen = (USHORT)strlen(kPackageNameA);
    PLSA_STRING name = (PLSA_STRING)LocalAlloc(LPTR, sizeof(LSA_STRING));
    if (!name) return STATUS_NO_MEMORY;
    name->Length = nameLen;
    name->MaximumLength = nameLen + 1;
    name->Buffer = (PCHAR)LocalAlloc(LPTR, name->MaximumLength);
    if (!name->Buffer) { LocalFree(name); return STATUS_NO_MEMORY; }
    memcpy(name->Buffer, kPackageNameA, nameLen + 1);
    *AuthenticationPackageName = name;
    return STATUS_SUCCESS;
}

// LsaApLogonUserEx2 is the modern entry point. We consult the daemon and:
//   * deny     -> STATUS_LOGON_FAILURE (LSA stops the chain).
//   * allow    -> STATUS_NOT_IMPLEMENTED so LSA falls through to MSV1_0/Kerberos.
//
// We do NOT issue a token of our own; this package is consultative.
extern "C" NTSTATUS NTAPI LsaApLogonUserEx2(
    PLSA_CLIENT_REQUEST /*ClientRequest*/,
    SECURITY_LOGON_TYPE LogonType,
    PVOID ProtocolSubmitBuffer,
    PVOID /*ClientBufferBase*/,
    ULONG SubmitBufferLength,
    PVOID* /*ProfileBuffer*/,
    PULONG /*ProfileBufferLength*/,
    PLUID /*LogonId*/,
    PNTSTATUS SubStatus,
    PLSA_TOKEN_INFORMATION_TYPE /*TokenInformationType*/,
    PVOID* /*TokenInformation*/,
    PUNICODE_STRING* /*AccountName*/,
    PUNICODE_STRING* /*AuthenticatingAuthority*/,
    PUNICODE_STRING* /*MachineName*/,
    PSECPKG_PRIMARY_CRED /*PrimaryCredentials*/,
    PSECPKG_SUPPLEMENTAL_CRED_ARRAY* /*SupplementalCredentials*/)
{
    if (SubStatus) *SubStatus = STATUS_SUCCESS;

    // Defensive: validate the submit buffer big enough to be a logon struct.
    if (!ProtocolSubmitBuffer || SubmitBufferLength < sizeof(KERB_INTERACTIVE_LOGON)) {
        return STATUS_NOT_IMPLEMENTED;  // pass through; not our submit shape.
    }

    KERB_INTERACTIVE_LOGON* kil = (KERB_INTERACTIVE_LOGON*)ProtocolSubmitBuffer;
    const char* action = "login";
    switch (LogonType) {
    case Interactive:        action = "login";                break;
    case Network:            action = "login.network";        break;
    case Batch:              action = "login.batch";          break;
    case Service:            action = "login.service";        break;
    case Unlock:             action = "login.unlock";         break;
    case RemoteInteractive:  action = "login.rdp";            break;
    case CachedInteractive:  action = "login.cached";         break;
    default: break;
    }

    NTSTATUS s = TfDaemonDecide(&kil->LogonDomainName, &kil->UserName, action);
    if (s == STATUS_SUCCESS) {
        // Daemon allowed — let MSV1_0/Kerberos do the actual cred check.
        return STATUS_NOT_IMPLEMENTED;
    }
    if (SubStatus) *SubStatus = STATUS_ACCOUNT_RESTRICTION;
    return STATUS_LOGON_FAILURE;
}

extern "C" VOID NTAPI LsaApLogonTerminated(PLUID /*LogonId*/)
{
    // Nothing to clean up — we do not maintain per-logon state.
}

// LsaApCallPackage is invoked when a caller LsaCallAuthenticationPackage's
// us. We reserve message types 1..255 for diagnostic / health-probe calls.
extern "C" NTSTATUS NTAPI LsaApCallPackage(
    PLSA_CLIENT_REQUEST /*ClientRequest*/,
    PVOID ProtocolSubmitBuffer,
    PVOID /*ClientBufferBase*/,
    ULONG SubmitBufferLength,
    PVOID* ProtocolReturnBuffer,
    PULONG ReturnBufferLength,
    PNTSTATUS ProtocolStatus)
{
    if (ProtocolReturnBuffer) *ProtocolReturnBuffer = nullptr;
    if (ReturnBufferLength)   *ReturnBufferLength = 0;
    if (ProtocolStatus)       *ProtocolStatus = STATUS_NOT_IMPLEMENTED;

    if (!ProtocolSubmitBuffer || SubmitBufferLength < sizeof(ULONG)) {
        return STATUS_INVALID_PARAMETER;
    }

    // Message 1 = "ping": returns the package name. Useful for "is the
    // package loaded?" probes.
    ULONG msg = *(ULONG*)ProtocolSubmitBuffer;
    if (msg == 1) {
        size_t cb = sizeof(kPackageNameA);
        PVOID buf = LocalAlloc(LPTR, cb);
        if (!buf) return STATUS_NO_MEMORY;
        memcpy(buf, kPackageNameA, cb);
        if (ProtocolReturnBuffer) *ProtocolReturnBuffer = buf;
        if (ReturnBufferLength)   *ReturnBufferLength = (ULONG)cb;
        if (ProtocolStatus)       *ProtocolStatus = STATUS_SUCCESS;
        return STATUS_SUCCESS;
    }

    return STATUS_NOT_IMPLEMENTED;
}

// Optional: legacy LsaApLogonUser entry. Some hosts still call it; we
// forward through the same path.
extern "C" NTSTATUS NTAPI LsaApLogonUser(
    PLSA_CLIENT_REQUEST ClientRequest,
    SECURITY_LOGON_TYPE LogonType,
    PVOID ProtocolSubmitBuffer,
    PVOID ClientBufferBase,
    ULONG SubmitBufferLength,
    PVOID* ProfileBuffer,
    PULONG ProfileBufferLength,
    PLUID LogonId,
    PNTSTATUS SubStatus,
    PLSA_TOKEN_INFORMATION_TYPE TokenInformationType,
    PVOID* TokenInformation,
    PUNICODE_STRING* AccountName,
    PUNICODE_STRING* AuthenticatingAuthority)
{
    return LsaApLogonUserEx2(ClientRequest, LogonType,
                             ProtocolSubmitBuffer, ClientBufferBase,
                             SubmitBufferLength,
                             ProfileBuffer, ProfileBufferLength,
                             LogonId, SubStatus,
                             TokenInformationType, TokenInformation,
                             AccountName, AuthenticatingAuthority,
                             nullptr, nullptr, nullptr);
}

// ---- DllMain ---------------------------------------------------------------

BOOL APIENTRY DllMain(HINSTANCE hInstance, DWORD dwReason, LPVOID /*lpReserved*/)
{
    switch (dwReason) {
    case DLL_PROCESS_ATTACH:
        DisableThreadLibraryCalls(hInstance);
        break;
    }
    return TRUE;
}
