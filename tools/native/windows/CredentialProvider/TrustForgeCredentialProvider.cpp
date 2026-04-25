// TrustForgeCredentialProvider.cpp
//
// Implementation of CTrustForgeProvider, CTrustForgeCredential, and the
// minimal HTTP-over-named-pipe glue used by GetSerialization.
//
// Status: Draft — Phase 0. Experimental, not production-ready.
//
// Design notes:
//   * The provider exposes a single tile with username + password fields.
//   * On submit (GetSerialization) we issue POST /v1/decide to the daemon
//     listening on `\\.\pipe\trustforge\decide`. If the response decision
//     is "allow", we serialize the credential to LSA via
//     CredPackAuthenticationBuffer; otherwise we surface the deny reason
//     in the tile's status field.
//   * Failure mode is FAIL CLOSED. Any pipe error, timeout, or parse error
//     is treated as deny — winlogon never sees a credential.
//   * No external JSON library: hand-rolled escape-on-write and a tiny
//     scanner for the response. JSON injection from the daemon is bounded
//     because we only read string fields by key.

#include "TrustForgeCredentialProvider.h"
#include <new>
#include <strsafe.h>
#include <stdio.h>

// ---- field descriptors ------------------------------------------------------

const CREDENTIAL_PROVIDER_FIELD_DESCRIPTOR g_TfFieldDescriptors[TF_NUM_FIELDS] = {
    { TF_FIELD_TILEIMAGE, CPFT_TILE_IMAGE,    L"Image",       CPFG_CREDENTIAL_PROVIDER_LOGO  },
    { TF_FIELD_LABEL,     CPFT_LARGE_TEXT,    L"TrustForge",  CPFG_CREDENTIAL_PROVIDER_LABEL },
    { TF_FIELD_USERNAME,  CPFT_EDIT_TEXT,     L"Username",    CPFG_LOGON_USERNAME            },
    { TF_FIELD_PASSWORD,  CPFT_PASSWORD_TEXT, L"Password",    CPFG_LOGON_PASSWORD            },
    { TF_FIELD_SUBMIT,    CPFT_SUBMIT_BUTTON, L"Submit",      CPFG_CREDENTIAL_PROVIDER_LABEL },
    { TF_FIELD_STATUS,    CPFT_SMALL_TEXT,    L"Status",      CPFG_CREDENTIAL_PROVIDER_LABEL },
};

// ---- small string helpers ---------------------------------------------------

static HRESULT TfDupString(LPCWSTR src, LPWSTR* dst)
{
    if (!dst) return E_POINTER;
    *dst = nullptr;
    if (!src) src = L"";
    size_t cch = wcslen(src) + 1;
    *dst = static_cast<LPWSTR>(CoTaskMemAlloc(cch * sizeof(wchar_t)));
    if (!*dst) return E_OUTOFMEMORY;
    return StringCchCopyW(*dst, cch, src);
}

static HRESULT TfWideToUtf8(LPCWSTR ws, char* buf, size_t bufLen)
{
    int n = WideCharToMultiByte(CP_UTF8, 0, ws, -1, buf, (int)bufLen, nullptr, nullptr);
    return (n > 0) ? S_OK : HRESULT_FROM_WIN32(GetLastError());
}

static HRESULT TfUtf8ToWide(const char* s, LPWSTR* out)
{
    int n = MultiByteToWideChar(CP_UTF8, 0, s, -1, nullptr, 0);
    if (n <= 0) return HRESULT_FROM_WIN32(GetLastError());
    LPWSTR buf = static_cast<LPWSTR>(CoTaskMemAlloc(n * sizeof(wchar_t)));
    if (!buf) return E_OUTOFMEMORY;
    MultiByteToWideChar(CP_UTF8, 0, s, -1, buf, n);
    *out = buf;
    return S_OK;
}

// JSON-escape a UTF-8 string into `out`. Returns chars written or -1.
static int TfJsonEscape(const char* in, char* out, size_t outLen)
{
    size_t o = 0;
    for (size_t i = 0; in[i]; ++i) {
        unsigned char c = (unsigned char)in[i];
        const char* esc = nullptr;
        char ebuf[8];
        switch (c) {
        case '"':  esc = "\\\""; break;
        case '\\': esc = "\\\\"; break;
        case '\b': esc = "\\b";  break;
        case '\f': esc = "\\f";  break;
        case '\n': esc = "\\n";  break;
        case '\r': esc = "\\r";  break;
        case '\t': esc = "\\t";  break;
        default:
            if (c < 0x20) {
                StringCchPrintfA(ebuf, 8, "\\u%04x", c);
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

// Tiny scanner: find `"key"` and return a CoTaskMem-allocated UTF-8 copy of
// the string value that follows. Returns S_FALSE if key not found.
static HRESULT TfFindJsonString(const char* json, const char* key, char** out)
{
    *out = nullptr;
    char needle[64];
    if (FAILED(StringCchPrintfA(needle, 64, "\"%s\"", key))) return E_INVALIDARG;

    const char* p = strstr(json, needle);
    if (!p) return S_FALSE;
    p += strlen(needle);
    while (*p == ' ' || *p == '\t' || *p == ':' || *p == '\r' || *p == '\n') ++p;
    if (*p != '"') return S_FALSE;
    ++p;
    const char* start = p;
    // Scan to the closing quote, honoring backslash escapes minimally.
    while (*p && *p != '"') {
        if (*p == '\\' && p[1]) p += 2;
        else ++p;
    }
    if (*p != '"') return S_FALSE;
    size_t len = (size_t)(p - start);
    char* buf = static_cast<char*>(CoTaskMemAlloc(len + 1));
    if (!buf) return E_OUTOFMEMORY;
    memcpy(buf, start, len);
    buf[len] = '\0';
    *out = buf;
    return S_OK;
}

// ---- daemon call ------------------------------------------------------------

HRESULT TfCallDecide(LPCWSTR pwzUsername,
                     LPCWSTR pwzPassword,
                     BOOL* pbAllow,
                     LPWSTR* ppwzReason)
{
    if (!pbAllow) return E_POINTER;
    *pbAllow = FALSE;
    if (ppwzReason) *ppwzReason = nullptr;

    // 1. Encode username to UTF-8 (we never send the raw password to the
    //    daemon — we send a host_token marker; the password is later passed
    //    directly to LSA via CredPackAuthenticationBuffer).
    char userU8[256] = {};
    if (FAILED(TfWideToUtf8(pwzUsername ? pwzUsername : L"", userU8, sizeof(userU8)))) {
        return E_FAIL;
    }
    char userEsc[1024];
    if (TfJsonEscape(userU8, userEsc, sizeof(userEsc)) < 0) return E_FAIL;

    // host_token_kind = "interactive-logon" indicates this is winlogon-flavored.
    // The daemon may consult policy + session state without seeing the password.
    char body[2048];
    int bodyLen = _snprintf_s(body, sizeof(body), _TRUNCATE,
        "{"
        "\"actor\":null,"
        "\"host_token\":\"%s\","
        "\"host_token_kind\":\"interactive-logon\","
        "\"action\":\"login\","
        "\"target\":\"winlogon\""
        "}",
        userEsc);
    if (bodyLen < 0) return E_FAIL;

    // 2. Build a minimal HTTP/1.1 request frame.
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
    if (reqLen < 0) return E_FAIL;

    // 3. Open the named pipe with a 5s overall budget. WaitNamedPipe handles
    //    the case where the daemon is busy serving another caller.
    LPCWSTR kPipe = L"\\\\.\\pipe\\trustforge\\decide";
    if (!WaitNamedPipeW(kPipe, 5000)) {
        // Fail closed — daemon unavailable.
        if (ppwzReason) TfDupString(L"TrustForge daemon unreachable.", ppwzReason);
        return HRESULT_FROM_WIN32(GetLastError());
    }

    HANDLE hPipe = CreateFileW(kPipe,
                               GENERIC_READ | GENERIC_WRITE,
                               0, nullptr, OPEN_EXISTING, 0, nullptr);
    if (hPipe == INVALID_HANDLE_VALUE) {
        if (ppwzReason) TfDupString(L"TrustForge daemon unreachable.", ppwzReason);
        return HRESULT_FROM_WIN32(GetLastError());
    }

    DWORD mode = PIPE_READMODE_BYTE;
    SetNamedPipeHandleState(hPipe, &mode, nullptr, nullptr);

    DWORD written = 0;
    BOOL ok = WriteFile(hPipe, req, (DWORD)reqLen, &written, nullptr);
    if (!ok || written != (DWORD)reqLen) {
        CloseHandle(hPipe);
        if (ppwzReason) TfDupString(L"TrustForge daemon write failed.", ppwzReason);
        return E_FAIL;
    }

    // 4. Read response. We read until EOF or until we have a recognizable
    //    body. Buffer is bounded — if the response is larger we deny.
    char resp[8192] = {};
    DWORD totalRead = 0;
    while (totalRead < sizeof(resp) - 1) {
        DWORD n = 0;
        if (!ReadFile(hPipe, resp + totalRead,
                      (DWORD)(sizeof(resp) - 1 - totalRead), &n, nullptr)) {
            DWORD err = GetLastError();
            if (err == ERROR_BROKEN_PIPE || err == ERROR_HANDLE_EOF) break;
            CloseHandle(hPipe);
            if (ppwzReason) TfDupString(L"TrustForge daemon read failed.", ppwzReason);
            return HRESULT_FROM_WIN32(err);
        }
        if (n == 0) break;
        totalRead += n;
    }
    CloseHandle(hPipe);
    resp[totalRead] = '\0';

    // 5. Find the JSON body — first blank line separates headers from body.
    const char* body0 = strstr(resp, "\r\n\r\n");
    if (!body0) {
        if (ppwzReason) TfDupString(L"TrustForge daemon returned malformed HTTP.", ppwzReason);
        return E_FAIL;
    }
    body0 += 4;

    // 6. Parse decision string. Anything that is not exactly "allow" is deny.
    char* decision = nullptr;
    HRESULT hr = TfFindJsonString(body0, "decision", &decision);
    if (FAILED(hr) || hr == S_FALSE || !decision) {
        if (ppwzReason) TfDupString(L"TrustForge: missing decision.", ppwzReason);
        if (decision) CoTaskMemFree(decision);
        return E_FAIL;
    }
    if (strcmp(decision, "allow") == 0) {
        *pbAllow = TRUE;
    } else {
        *pbAllow = FALSE;
        char* reason = nullptr;
        if (SUCCEEDED(TfFindJsonString(body0, "reason", &reason)) && reason) {
            if (ppwzReason) TfUtf8ToWide(reason, ppwzReason);
            CoTaskMemFree(reason);
        } else if (ppwzReason) {
            TfDupString(L"TrustForge denied logon.", ppwzReason);
        }
    }
    CoTaskMemFree(decision);
    return S_OK;
}

// =============================================================================
// CTrustForgeCredential
// =============================================================================

CTrustForgeCredential::CTrustForgeCredential()
    : m_cRef(1),
      m_cpus(CPUS_INVALID),
      m_pCredProvCredentialEvents(nullptr)
{
    InterlockedIncrement(&g_cDllRef);
    for (int i = 0; i < TF_NUM_FIELDS; ++i) m_rgFieldStrings[i] = nullptr;
    TfDupString(L"TrustForge",                 &m_rgFieldStrings[TF_FIELD_LABEL]);
    TfDupString(L"",                           &m_rgFieldStrings[TF_FIELD_USERNAME]);
    TfDupString(L"",                           &m_rgFieldStrings[TF_FIELD_PASSWORD]);
    TfDupString(L"Sign in",                    &m_rgFieldStrings[TF_FIELD_SUBMIT]);
    TfDupString(L"Authorized via TrustForge",  &m_rgFieldStrings[TF_FIELD_STATUS]);
    TfDupString(L"",                           &m_rgFieldStrings[TF_FIELD_TILEIMAGE]);
}

CTrustForgeCredential::~CTrustForgeCredential()
{
    for (int i = 0; i < TF_NUM_FIELDS; ++i) {
        if (m_rgFieldStrings[i]) {
            // Zero out the password field before freeing.
            if (i == TF_FIELD_PASSWORD) {
                SecureZeroMemory(m_rgFieldStrings[i],
                                 wcslen(m_rgFieldStrings[i]) * sizeof(wchar_t));
            }
            CoTaskMemFree(m_rgFieldStrings[i]);
        }
    }
    InterlockedDecrement(&g_cDllRef);
}

IFACEMETHODIMP CTrustForgeCredential::QueryInterface(REFIID riid, void** ppv)
{
    if (!ppv) return E_POINTER;
    if (IsEqualIID(riid, IID_IUnknown) ||
        IsEqualIID(riid, IID_ICredentialProviderCredential)) {
        *ppv = static_cast<ICredentialProviderCredential*>(this);
        AddRef();
        return S_OK;
    }
    *ppv = nullptr;
    return E_NOINTERFACE;
}

IFACEMETHODIMP_(ULONG) CTrustForgeCredential::AddRef()  { return InterlockedIncrement(&m_cRef); }
IFACEMETHODIMP_(ULONG) CTrustForgeCredential::Release() {
    LONG n = InterlockedDecrement(&m_cRef);
    if (n == 0) delete this;
    return n;
}

IFACEMETHODIMP CTrustForgeCredential::Advise(ICredentialProviderCredentialEvents* p)
{
    if (m_pCredProvCredentialEvents) m_pCredProvCredentialEvents->Release();
    m_pCredProvCredentialEvents = p;
    if (m_pCredProvCredentialEvents) m_pCredProvCredentialEvents->AddRef();
    return S_OK;
}
IFACEMETHODIMP CTrustForgeCredential::UnAdvise()
{
    if (m_pCredProvCredentialEvents) {
        m_pCredProvCredentialEvents->Release();
        m_pCredProvCredentialEvents = nullptr;
    }
    return S_OK;
}
IFACEMETHODIMP CTrustForgeCredential::SetSelected(BOOL* pbAutoLogon)
{
    if (pbAutoLogon) *pbAutoLogon = FALSE;
    return S_OK;
}
IFACEMETHODIMP CTrustForgeCredential::SetDeselected()
{
    if (m_rgFieldStrings[TF_FIELD_PASSWORD]) {
        SecureZeroMemory(m_rgFieldStrings[TF_FIELD_PASSWORD],
                         wcslen(m_rgFieldStrings[TF_FIELD_PASSWORD]) * sizeof(wchar_t));
        CoTaskMemFree(m_rgFieldStrings[TF_FIELD_PASSWORD]);
        TfDupString(L"", &m_rgFieldStrings[TF_FIELD_PASSWORD]);
    }
    return S_OK;
}

IFACEMETHODIMP CTrustForgeCredential::GetFieldState(
    DWORD dwFieldID,
    CREDENTIAL_PROVIDER_FIELD_STATE* pcpfs,
    CREDENTIAL_PROVIDER_FIELD_INTERACTIVE_STATE* pcpfis)
{
    if (dwFieldID >= TF_NUM_FIELDS || !pcpfs || !pcpfis) return E_INVALIDARG;
    switch (dwFieldID) {
    case TF_FIELD_TILEIMAGE: *pcpfs = CPFS_DISPLAY_IN_BOTH;            *pcpfis = CPFIS_NONE; break;
    case TF_FIELD_LABEL:     *pcpfs = CPFS_DISPLAY_IN_BOTH;            *pcpfis = CPFIS_NONE; break;
    case TF_FIELD_USERNAME:  *pcpfs = CPFS_DISPLAY_IN_SELECTED_TILE;   *pcpfis = CPFIS_FOCUSED; break;
    case TF_FIELD_PASSWORD:  *pcpfs = CPFS_DISPLAY_IN_SELECTED_TILE;   *pcpfis = CPFIS_NONE; break;
    case TF_FIELD_SUBMIT:    *pcpfs = CPFS_DISPLAY_IN_SELECTED_TILE;   *pcpfis = CPFIS_NONE; break;
    case TF_FIELD_STATUS:    *pcpfs = CPFS_DISPLAY_IN_SELECTED_TILE;   *pcpfis = CPFIS_NONE; break;
    default: return E_INVALIDARG;
    }
    return S_OK;
}

IFACEMETHODIMP CTrustForgeCredential::GetStringValue(DWORD dwFieldID, LPWSTR* ppwsz)
{
    if (dwFieldID >= TF_NUM_FIELDS || !ppwsz) return E_INVALIDARG;
    return TfDupString(m_rgFieldStrings[dwFieldID] ? m_rgFieldStrings[dwFieldID] : L"", ppwsz);
}

IFACEMETHODIMP CTrustForgeCredential::GetBitmapValue(DWORD dwFieldID, HBITMAP* phbmp)
{
    if (dwFieldID != TF_FIELD_TILEIMAGE || !phbmp) return E_INVALIDARG;
    // We do not bundle a bitmap; LogonUI will fall back to its default.
    *phbmp = nullptr;
    return E_NOTIMPL;
}

IFACEMETHODIMP CTrustForgeCredential::GetCheckboxValue(DWORD, BOOL*, LPWSTR*) { return E_NOTIMPL; }
IFACEMETHODIMP CTrustForgeCredential::GetSubmitButtonValue(DWORD dwFieldID, DWORD* pdwAdjacentTo)
{
    if (dwFieldID != TF_FIELD_SUBMIT || !pdwAdjacentTo) return E_INVALIDARG;
    *pdwAdjacentTo = TF_FIELD_PASSWORD;
    return S_OK;
}
IFACEMETHODIMP CTrustForgeCredential::GetComboBoxValueCount(DWORD, DWORD*, DWORD*) { return E_NOTIMPL; }
IFACEMETHODIMP CTrustForgeCredential::GetComboBoxValueAt(DWORD, DWORD, LPWSTR*) { return E_NOTIMPL; }

IFACEMETHODIMP CTrustForgeCredential::SetStringValue(DWORD dwFieldID, LPCWSTR pwz)
{
    if (dwFieldID != TF_FIELD_USERNAME && dwFieldID != TF_FIELD_PASSWORD) return E_INVALIDARG;
    if (m_rgFieldStrings[dwFieldID]) {
        if (dwFieldID == TF_FIELD_PASSWORD) {
            SecureZeroMemory(m_rgFieldStrings[dwFieldID],
                             wcslen(m_rgFieldStrings[dwFieldID]) * sizeof(wchar_t));
        }
        CoTaskMemFree(m_rgFieldStrings[dwFieldID]);
        m_rgFieldStrings[dwFieldID] = nullptr;
    }
    return TfDupString(pwz, &m_rgFieldStrings[dwFieldID]);
}

IFACEMETHODIMP CTrustForgeCredential::SetCheckboxValue(DWORD, BOOL) { return E_NOTIMPL; }
IFACEMETHODIMP CTrustForgeCredential::SetComboBoxSelectedValue(DWORD, DWORD) { return E_NOTIMPL; }
IFACEMETHODIMP CTrustForgeCredential::CommandLinkClicked(DWORD) { return E_NOTIMPL; }

// The gate.
IFACEMETHODIMP CTrustForgeCredential::GetSerialization(
    CREDENTIAL_PROVIDER_GET_SERIALIZATION_RESPONSE* pcpgsr,
    CREDENTIAL_PROVIDER_CREDENTIAL_SERIALIZATION* pcpcs,
    LPWSTR* ppwszOptionalStatusText,
    CREDENTIAL_PROVIDER_STATUS_ICON* pcpsiOptionalStatusIcon)
{
    if (!pcpgsr || !pcpcs) return E_POINTER;
    *pcpgsr = CPGSR_NO_CREDENTIAL_NOT_FINISHED;
    if (pcpsiOptionalStatusIcon) *pcpsiOptionalStatusIcon = CPSI_ERROR;

    // 1. Ask TrustForge daemon — fail closed on any error.
    BOOL bAllow = FALSE;
    LPWSTR reason = nullptr;
    HRESULT hr = TfCallDecide(m_rgFieldStrings[TF_FIELD_USERNAME],
                              m_rgFieldStrings[TF_FIELD_PASSWORD],
                              &bAllow,
                              &reason);
    if (FAILED(hr) || !bAllow) {
        if (ppwszOptionalStatusText) {
            *ppwszOptionalStatusText = reason
                ? reason
                : nullptr;
            if (!*ppwszOptionalStatusText) {
                TfDupString(L"TrustForge denied logon.", ppwszOptionalStatusText);
            }
        } else if (reason) {
            CoTaskMemFree(reason);
        }
        *pcpgsr = CPGSR_NO_CREDENTIAL_NOT_FINISHED;
        return S_OK;
    }
    if (reason) CoTaskMemFree(reason);

    // 2. Daemon allowed. Pack credentials for LSA via CredPackAuthenticationBuffer.
    KERB_INTERACTIVE_UNLOCK_LOGON kiul = {};
    KERB_INTERACTIVE_LOGON& kil = kiul.Logon;
    kil.MessageType = (m_cpus == CPUS_UNLOCK_WORKSTATION)
        ? (KERB_LOGON_SUBMIT_TYPE)KerbWorkstationUnlockLogon
        : KerbInteractiveLogon;

    LPCWSTR userIn = m_rgFieldStrings[TF_FIELD_USERNAME] ? m_rgFieldStrings[TF_FIELD_USERNAME] : L"";
    LPCWSTR passIn = m_rgFieldStrings[TF_FIELD_PASSWORD] ? m_rgFieldStrings[TF_FIELD_PASSWORD] : L"";

    // Split DOMAIN\user if present.
    wchar_t domain[256] = L".";
    wchar_t user[256]   = {};
    const wchar_t* slash = wcschr(userIn, L'\\');
    if (slash) {
        size_t dl = (size_t)(slash - userIn);
        if (dl >= ARRAYSIZE(domain)) dl = ARRAYSIZE(domain) - 1;
        wcsncpy_s(domain, ARRAYSIZE(domain), userIn, dl);
        StringCchCopyW(user, ARRAYSIZE(user), slash + 1);
    } else {
        StringCchCopyW(user, ARRAYSIZE(user), userIn);
    }

    auto fillUS = [](UNICODE_STRING* us, LPCWSTR s) {
        size_t cch = s ? wcslen(s) : 0;
        us->Length = (USHORT)(cch * sizeof(wchar_t));
        us->MaximumLength = us->Length;
        us->Buffer = (PWSTR)s;
    };
    fillUS(&kil.LogonDomainName, domain);
    fillUS(&kil.UserName,        user);
    fillUS(&kil.Password,        passIn);

    DWORD cb = 0;
    KerbInteractiveUnlockLogonInit(&kil, &cb); // helper expected to compute size; if not present, fall back.
    // For portability, just allocate a generous buffer.
    cb = (DWORD)(sizeof(KERB_INTERACTIVE_UNLOCK_LOGON)
                 + (wcslen(domain) + wcslen(user) + wcslen(passIn) + 3) * sizeof(wchar_t));
    BYTE* buf = (BYTE*)CoTaskMemAlloc(cb);
    if (!buf) return E_OUTOFMEMORY;
    ZeroMemory(buf, cb);
    memcpy(buf, &kiul, sizeof(kiul));

    // Append strings after the struct, fix up pointers as offsets.
    BYTE* tail = buf + sizeof(kiul);
    auto append = [&](UNICODE_STRING* dst, LPCWSTR s) {
        size_t cb2 = (wcslen(s) + 1) * sizeof(wchar_t);
        memcpy(tail, s, cb2);
        ((KERB_INTERACTIVE_UNLOCK_LOGON*)buf)
            ->Logon
            .*(dst == &kil.LogonDomainName ? &KERB_INTERACTIVE_LOGON::LogonDomainName
                : dst == &kil.UserName     ? &KERB_INTERACTIVE_LOGON::UserName
                                           : &KERB_INTERACTIVE_LOGON::Password)
            .Buffer = (PWSTR)tail;
        tail += cb2;
    };
    append(&kil.LogonDomainName, domain);
    append(&kil.UserName,        user);
    append(&kil.Password,        passIn);

    pcpcs->ulAuthenticationPackage = 0; // LSA fills the actual package; we set MSV1_0 below.
    LSA_STRING msv1_0 = { (USHORT)strlen(MSV1_0_PACKAGE_NAME),
                          (USHORT)strlen(MSV1_0_PACKAGE_NAME) + 1,
                          (PCHAR)MSV1_0_PACKAGE_NAME };
    HANDLE hLsa = nullptr;
    if (LsaConnectUntrusted(&hLsa) == 0) {
        ULONG authPkg = 0;
        if (LsaLookupAuthenticationPackage(hLsa, &msv1_0, &authPkg) == 0) {
            pcpcs->ulAuthenticationPackage = authPkg;
        }
        LsaDeregisterLogonProcess(hLsa);
    }

    pcpcs->clsidCredentialProvider = CLSID_TrustForgeCredentialProvider;
    pcpcs->cbSerialization = cb;
    pcpcs->rgbSerialization = buf;

    *pcpgsr = CPGSR_RETURN_CREDENTIAL_FINISHED;
    if (pcpsiOptionalStatusIcon) *pcpsiOptionalStatusIcon = CPSI_SUCCESS;
    return S_OK;
}

IFACEMETHODIMP CTrustForgeCredential::ReportResult(NTSTATUS,
                                                   NTSTATUS,
                                                   LPWSTR* ppwszOptionalStatusText,
                                                   CREDENTIAL_PROVIDER_STATUS_ICON* pcpsiOptionalStatusIcon)
{
    if (ppwszOptionalStatusText) *ppwszOptionalStatusText = nullptr;
    if (pcpsiOptionalStatusIcon) *pcpsiOptionalStatusIcon = CPSI_NONE;
    return S_OK;
}

// =============================================================================
// CTrustForgeProvider
// =============================================================================

CTrustForgeProvider::CTrustForgeProvider()
    : m_cRef(1), m_pCredential(nullptr), m_cpus(CPUS_INVALID)
{
    InterlockedIncrement(&g_cDllRef);
}

CTrustForgeProvider::~CTrustForgeProvider()
{
    if (m_pCredential) m_pCredential->Release();
    InterlockedDecrement(&g_cDllRef);
}

IFACEMETHODIMP CTrustForgeProvider::QueryInterface(REFIID riid, void** ppv)
{
    if (!ppv) return E_POINTER;
    if (IsEqualIID(riid, IID_IUnknown) || IsEqualIID(riid, IID_ICredentialProvider)) {
        *ppv = static_cast<ICredentialProvider*>(this);
        AddRef();
        return S_OK;
    }
    *ppv = nullptr;
    return E_NOINTERFACE;
}

IFACEMETHODIMP_(ULONG) CTrustForgeProvider::AddRef()  { return InterlockedIncrement(&m_cRef); }
IFACEMETHODIMP_(ULONG) CTrustForgeProvider::Release() {
    LONG n = InterlockedDecrement(&m_cRef);
    if (n == 0) delete this;
    return n;
}

IFACEMETHODIMP CTrustForgeProvider::SetUsageScenario(CREDENTIAL_PROVIDER_USAGE_SCENARIO cpus, DWORD)
{
    m_cpus = cpus;
    switch (cpus) {
    case CPUS_LOGON:
    case CPUS_UNLOCK_WORKSTATION:
    case CPUS_CREDUI:
        if (!m_pCredential) m_pCredential = new (std::nothrow) CTrustForgeCredential();
        return m_pCredential ? S_OK : E_OUTOFMEMORY;
    default:
        return E_NOTIMPL;
    }
}

IFACEMETHODIMP CTrustForgeProvider::SetSerialization(const CREDENTIAL_PROVIDER_CREDENTIAL_SERIALIZATION*) { return E_NOTIMPL; }
IFACEMETHODIMP CTrustForgeProvider::Advise(ICredentialProviderEvents*, UINT_PTR) { return E_NOTIMPL; }
IFACEMETHODIMP CTrustForgeProvider::UnAdvise() { return E_NOTIMPL; }

IFACEMETHODIMP CTrustForgeProvider::GetFieldDescriptorCount(DWORD* pdwCount)
{
    if (!pdwCount) return E_POINTER;
    *pdwCount = TF_NUM_FIELDS;
    return S_OK;
}

IFACEMETHODIMP CTrustForgeProvider::GetFieldDescriptorAt(DWORD dwIndex,
                                                        CREDENTIAL_PROVIDER_FIELD_DESCRIPTOR** ppcpfd)
{
    if (dwIndex >= TF_NUM_FIELDS || !ppcpfd) return E_INVALIDARG;
    *ppcpfd = static_cast<CREDENTIAL_PROVIDER_FIELD_DESCRIPTOR*>(
        CoTaskMemAlloc(sizeof(CREDENTIAL_PROVIDER_FIELD_DESCRIPTOR)));
    if (!*ppcpfd) return E_OUTOFMEMORY;
    **ppcpfd = g_TfFieldDescriptors[dwIndex];
    if (g_TfFieldDescriptors[dwIndex].pszLabel) {
        TfDupString(g_TfFieldDescriptors[dwIndex].pszLabel, &(*ppcpfd)->pszLabel);
    }
    return S_OK;
}

IFACEMETHODIMP CTrustForgeProvider::GetCredentialCount(DWORD* pdwCount,
                                                      DWORD* pdwDefault,
                                                      BOOL* pbAutoLogonWithDefault)
{
    if (!pdwCount || !pdwDefault || !pbAutoLogonWithDefault) return E_POINTER;
    *pdwCount = m_pCredential ? 1 : 0;
    *pdwDefault = 0;
    *pbAutoLogonWithDefault = FALSE;
    return S_OK;
}

IFACEMETHODIMP CTrustForgeProvider::GetCredentialAt(DWORD dwIndex,
                                                   ICredentialProviderCredential** ppcpc)
{
    if (!ppcpc) return E_POINTER;
    if (dwIndex != 0 || !m_pCredential) return E_INVALIDARG;
    return m_pCredential->QueryInterface(IID_PPV_ARGS(ppcpc));
}

// =============================================================================
// CTrustForgeProviderFactory
// =============================================================================

CTrustForgeProviderFactory::CTrustForgeProviderFactory() : m_cRef(1) {
    InterlockedIncrement(&g_cDllRef);
}
CTrustForgeProviderFactory::~CTrustForgeProviderFactory() {
    InterlockedDecrement(&g_cDllRef);
}

IFACEMETHODIMP CTrustForgeProviderFactory::QueryInterface(REFIID riid, void** ppv)
{
    if (!ppv) return E_POINTER;
    if (IsEqualIID(riid, IID_IUnknown) || IsEqualIID(riid, IID_IClassFactory)) {
        *ppv = static_cast<IClassFactory*>(this);
        AddRef();
        return S_OK;
    }
    *ppv = nullptr;
    return E_NOINTERFACE;
}
IFACEMETHODIMP_(ULONG) CTrustForgeProviderFactory::AddRef()  { return InterlockedIncrement(&m_cRef); }
IFACEMETHODIMP_(ULONG) CTrustForgeProviderFactory::Release() {
    LONG n = InterlockedDecrement(&m_cRef);
    if (n == 0) delete this;
    return n;
}
IFACEMETHODIMP CTrustForgeProviderFactory::CreateInstance(IUnknown* pUnkOuter, REFIID riid, void** ppv)
{
    if (!ppv) return E_POINTER;
    *ppv = nullptr;
    if (pUnkOuter) return CLASS_E_NOAGGREGATION;
    auto* p = new (std::nothrow) CTrustForgeProvider();
    if (!p) return E_OUTOFMEMORY;
    HRESULT hr = p->QueryInterface(riid, ppv);
    p->Release();
    return hr;
}
IFACEMETHODIMP CTrustForgeProviderFactory::LockServer(BOOL fLock)
{
    if (fLock) InterlockedIncrement(&g_cDllRef);
    else       InterlockedDecrement(&g_cDllRef);
    return S_OK;
}
