// dllmain.cpp
//
// COM in-process server scaffolding for TrustForgeCredentialProvider.dll.
//
// Status: Draft — Phase 0. Experimental, not production-ready.
//
// Exports:
//   DllGetClassObject     — hands out the class factory for our CLSID.
//   DllCanUnloadNow       — refcount-based unload gate.
//   DllRegisterServer     — registers the credential provider in HKLM.
//   DllUnregisterServer   — removes the registration.
//
// The CLSID and registry layout is documented in register.reg and must stay
// in sync with TrustForgeCredentialProvider.h.

#include "TrustForgeCredentialProvider.h"
#include <new>
#include <strsafe.h>

// ---- module state -----------------------------------------------------------

LONG g_cDllRef = 0;
static HINSTANCE g_hInst = nullptr;

// {8B0F8F3D-9E4C-4F2A-B7E1-2C6A5D9F1E03}
extern "C" const CLSID CLSID_TrustForgeCredentialProvider =
{ 0x8B0F8F3D, 0x9E4C, 0x4F2A, { 0xB7, 0xE1, 0x2C, 0x6A, 0x5D, 0x9F, 0x1E, 0x03 } };

// String form of the CLSID — used by Dll{Register,Unregister}Server.
static const wchar_t kCLSIDString[] =
    L"{8B0F8F3D-9E4C-4F2A-B7E1-2C6A5D9F1E03}";

static const wchar_t kFriendlyName[] = L"TrustForge Credential Provider";

// ---- DllMain ----------------------------------------------------------------

BOOL APIENTRY DllMain(HINSTANCE hInstance, DWORD dwReason, LPVOID /*lpReserved*/)
{
    switch (dwReason) {
    case DLL_PROCESS_ATTACH:
        g_hInst = hInstance;
        // We do not need per-thread callbacks; tell the loader to skip them.
        DisableThreadLibraryCalls(hInstance);
        break;
    case DLL_PROCESS_DETACH:
        break;
    }
    return TRUE;
}

// ---- COM exports ------------------------------------------------------------

extern "C" __declspec(dllexport) HRESULT __stdcall
DllGetClassObject(REFCLSID rclsid, REFIID riid, void** ppv)
{
    if (!ppv) return E_POINTER;
    *ppv = nullptr;

    if (!IsEqualCLSID(rclsid, CLSID_TrustForgeCredentialProvider)) {
        return CLASS_E_CLASSNOTAVAILABLE;
    }

    auto* pFactory = new (std::nothrow) CTrustForgeProviderFactory();
    if (!pFactory) return E_OUTOFMEMORY;

    HRESULT hr = pFactory->QueryInterface(riid, ppv);
    pFactory->Release();
    return hr;
}

extern "C" __declspec(dllexport) HRESULT __stdcall
DllCanUnloadNow(void)
{
    return (g_cDllRef == 0) ? S_OK : S_FALSE;
}

// ---- Registration helpers ---------------------------------------------------

static HRESULT TfWriteRegString(HKEY hRoot, LPCWSTR subKey, LPCWSTR valueName, LPCWSTR value)
{
    HKEY hKey = nullptr;
    LONG err = RegCreateKeyExW(hRoot, subKey, 0, nullptr,
                               REG_OPTION_NON_VOLATILE, KEY_WRITE,
                               nullptr, &hKey, nullptr);
    if (err != ERROR_SUCCESS) return HRESULT_FROM_WIN32(err);

    DWORD cb = (DWORD)((wcslen(value) + 1) * sizeof(wchar_t));
    err = RegSetValueExW(hKey, valueName, 0, REG_SZ,
                         reinterpret_cast<const BYTE*>(value), cb);
    RegCloseKey(hKey);
    return (err == ERROR_SUCCESS) ? S_OK : HRESULT_FROM_WIN32(err);
}

static HRESULT TfDeleteRegTree(HKEY hRoot, LPCWSTR subKey)
{
    LONG err = RegDeleteTreeW(hRoot, subKey);
    if (err == ERROR_FILE_NOT_FOUND) return S_OK;
    return (err == ERROR_SUCCESS) ? S_OK : HRESULT_FROM_WIN32(err);
}

extern "C" __declspec(dllexport) HRESULT __stdcall
DllRegisterServer(void)
{
    wchar_t modulePath[MAX_PATH] = {};
    if (GetModuleFileNameW(g_hInst, modulePath, MAX_PATH) == 0) {
        return HRESULT_FROM_WIN32(GetLastError());
    }

    wchar_t clsidKey[256];
    wchar_t inprocKey[256];
    wchar_t cpKey[512];

    StringCchPrintfW(clsidKey, ARRAYSIZE(clsidKey),
                     L"SOFTWARE\\Classes\\CLSID\\%s", kCLSIDString);
    StringCchPrintfW(inprocKey, ARRAYSIZE(inprocKey),
                     L"SOFTWARE\\Classes\\CLSID\\%s\\InprocServer32", kCLSIDString);
    StringCchPrintfW(cpKey, ARRAYSIZE(cpKey),
                     L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\"
                     L"Authentication\\Credential Providers\\%s", kCLSIDString);

    HRESULT hr;
    hr = TfWriteRegString(HKEY_LOCAL_MACHINE, clsidKey, nullptr, kFriendlyName);
    if (FAILED(hr)) return hr;

    hr = TfWriteRegString(HKEY_LOCAL_MACHINE, inprocKey, nullptr, modulePath);
    if (FAILED(hr)) return hr;

    hr = TfWriteRegString(HKEY_LOCAL_MACHINE, inprocKey, L"ThreadingModel", L"Apartment");
    if (FAILED(hr)) return hr;

    hr = TfWriteRegString(HKEY_LOCAL_MACHINE, cpKey, nullptr, kFriendlyName);
    if (FAILED(hr)) return hr;

    return S_OK;
}

extern "C" __declspec(dllexport) HRESULT __stdcall
DllUnregisterServer(void)
{
    wchar_t clsidKey[256];
    wchar_t cpKey[512];
    StringCchPrintfW(clsidKey, ARRAYSIZE(clsidKey),
                     L"SOFTWARE\\Classes\\CLSID\\%s", kCLSIDString);
    StringCchPrintfW(cpKey, ARRAYSIZE(cpKey),
                     L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\"
                     L"Authentication\\Credential Providers\\%s", kCLSIDString);

    HRESULT hr1 = TfDeleteRegTree(HKEY_LOCAL_MACHINE, cpKey);
    HRESULT hr2 = TfDeleteRegTree(HKEY_LOCAL_MACHINE, clsidKey);

    if (FAILED(hr1)) return hr1;
    if (FAILED(hr2)) return hr2;
    return S_OK;
}
