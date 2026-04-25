// TrustForgeCredentialProvider.h
//
// Declarations for the TrustForge ICredentialProvider implementation.
//
// Status: Draft — Phase 0. Experimental, not production-ready. The reference
// TrustForge daemon is not yet shipped; until it is, this provider is only
// useful for integration testing against the included mock daemon.
//
// COM identity:
//   CLSID_TrustForgeCredentialProvider = {8B0F8F3D-9E4C-4F2A-B7E1-2C6A5D9F1E03}
//
// The CLSID is a stable random GUID generated for TrustForge. Do not change
// it without coordinating with register.reg and the deployment manifest.

#pragma once

#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <unknwn.h>
#include <credentialprovider.h>
#include <wincred.h>
#include <ntsecapi.h>
#include <wchar.h>

// {8B0F8F3D-9E4C-4F2A-B7E1-2C6A5D9F1E03}
// Stable random GUID for TrustForge's credential provider COM class.
// IMPORTANT: keep in sync with register.reg.
extern "C" const CLSID CLSID_TrustForgeCredentialProvider;

// Module-level reference count, owned by dllmain.cpp.
extern LONG g_cDllRef;

// Field IDs used by the credential tile. Order matters: it dictates layout
// in the LogonUI tile.
enum TF_FIELD_ID {
    TF_FIELD_TILEIMAGE   = 0,
    TF_FIELD_LABEL       = 1,
    TF_FIELD_USERNAME    = 2,
    TF_FIELD_PASSWORD    = 3,
    TF_FIELD_SUBMIT      = 4,
    TF_FIELD_STATUS      = 5,
    TF_NUM_FIELDS        = 6,
};

extern const CREDENTIAL_PROVIDER_FIELD_DESCRIPTOR g_TfFieldDescriptors[TF_NUM_FIELDS];

// -----------------------------------------------------------------------------
// CTrustForgeCredential — implements ICredentialProviderCredential. One per tile.
// -----------------------------------------------------------------------------
class CTrustForgeCredential : public ICredentialProviderCredential
{
public:
    CTrustForgeCredential();
    virtual ~CTrustForgeCredential();

    // IUnknown
    IFACEMETHODIMP QueryInterface(REFIID riid, void** ppv) override;
    IFACEMETHODIMP_(ULONG) AddRef() override;
    IFACEMETHODIMP_(ULONG) Release() override;

    // ICredentialProviderCredential
    IFACEMETHODIMP Advise(ICredentialProviderCredentialEvents* pcpce) override;
    IFACEMETHODIMP UnAdvise() override;
    IFACEMETHODIMP SetSelected(BOOL* pbAutoLogon) override;
    IFACEMETHODIMP SetDeselected() override;
    IFACEMETHODIMP GetFieldState(DWORD dwFieldID,
                                 CREDENTIAL_PROVIDER_FIELD_STATE* pcpfs,
                                 CREDENTIAL_PROVIDER_FIELD_INTERACTIVE_STATE* pcpfis) override;
    IFACEMETHODIMP GetStringValue(DWORD dwFieldID, LPWSTR* ppwsz) override;
    IFACEMETHODIMP GetBitmapValue(DWORD dwFieldID, HBITMAP* phbmp) override;
    IFACEMETHODIMP GetCheckboxValue(DWORD dwFieldID, BOOL* pbChecked, LPWSTR* ppwszLabel) override;
    IFACEMETHODIMP GetSubmitButtonValue(DWORD dwFieldID, DWORD* pdwAdjacentTo) override;
    IFACEMETHODIMP GetComboBoxValueCount(DWORD dwFieldID, DWORD* pcItems, DWORD* pdwSelectedItem) override;
    IFACEMETHODIMP GetComboBoxValueAt(DWORD dwFieldID, DWORD dwItem, LPWSTR* ppwszItem) override;
    IFACEMETHODIMP SetStringValue(DWORD dwFieldID, LPCWSTR pwz) override;
    IFACEMETHODIMP SetCheckboxValue(DWORD dwFieldID, BOOL bChecked) override;
    IFACEMETHODIMP SetComboBoxSelectedValue(DWORD dwFieldID, DWORD dwSelectedItem) override;
    IFACEMETHODIMP CommandLinkClicked(DWORD dwFieldID) override;

    // The gate. LogonUI calls this when the user clicks Submit. We invoke the
    // TrustForge daemon over `\\.\pipe\trustforge\decide` and only emit
    // CPGSR_RETURN_CREDENTIAL_FINISHED when the daemon decision is "allow".
    IFACEMETHODIMP GetSerialization(
        CREDENTIAL_PROVIDER_GET_SERIALIZATION_RESPONSE* pcpgsr,
        CREDENTIAL_PROVIDER_CREDENTIAL_SERIALIZATION* pcpcs,
        LPWSTR* ppwszOptionalStatusText,
        CREDENTIAL_PROVIDER_STATUS_ICON* pcpsiOptionalStatusIcon) override;

    IFACEMETHODIMP ReportResult(NTSTATUS ntsStatus,
                                NTSTATUS ntsSubstatus,
                                LPWSTR* ppwszOptionalStatusText,
                                CREDENTIAL_PROVIDER_STATUS_ICON* pcpsiOptionalStatusIcon) override;

private:
    LONG m_cRef;
    CREDENTIAL_PROVIDER_USAGE_SCENARIO m_cpus;
    ICredentialProviderCredentialEvents* m_pCredProvCredentialEvents;
    LPWSTR m_rgFieldStrings[TF_NUM_FIELDS];
};

// -----------------------------------------------------------------------------
// CTrustForgeProvider — implements ICredentialProvider. The class object.
// -----------------------------------------------------------------------------
class CTrustForgeProvider : public ICredentialProvider
{
public:
    CTrustForgeProvider();
    virtual ~CTrustForgeProvider();

    // IUnknown
    IFACEMETHODIMP QueryInterface(REFIID riid, void** ppv) override;
    IFACEMETHODIMP_(ULONG) AddRef() override;
    IFACEMETHODIMP_(ULONG) Release() override;

    // ICredentialProvider
    IFACEMETHODIMP SetUsageScenario(CREDENTIAL_PROVIDER_USAGE_SCENARIO cpus, DWORD dwFlags) override;
    IFACEMETHODIMP SetSerialization(const CREDENTIAL_PROVIDER_CREDENTIAL_SERIALIZATION* pcpcs) override;
    IFACEMETHODIMP Advise(ICredentialProviderEvents* pcpe, UINT_PTR upAdviseContext) override;
    IFACEMETHODIMP UnAdvise() override;
    IFACEMETHODIMP GetFieldDescriptorCount(DWORD* pdwCount) override;
    IFACEMETHODIMP GetFieldDescriptorAt(DWORD dwIndex,
                                        CREDENTIAL_PROVIDER_FIELD_DESCRIPTOR** ppcpfd) override;
    IFACEMETHODIMP GetCredentialCount(DWORD* pdwCount,
                                      DWORD* pdwDefault,
                                      BOOL* pbAutoLogonWithDefault) override;
    IFACEMETHODIMP GetCredentialAt(DWORD dwIndex,
                                   ICredentialProviderCredential** ppcpc) override;

private:
    LONG m_cRef;
    CTrustForgeCredential* m_pCredential;
    CREDENTIAL_PROVIDER_USAGE_SCENARIO m_cpus;
};

// -----------------------------------------------------------------------------
// Class factory.
// -----------------------------------------------------------------------------
class CTrustForgeProviderFactory : public IClassFactory
{
public:
    CTrustForgeProviderFactory();
    virtual ~CTrustForgeProviderFactory();

    IFACEMETHODIMP QueryInterface(REFIID riid, void** ppv) override;
    IFACEMETHODIMP_(ULONG) AddRef() override;
    IFACEMETHODIMP_(ULONG) Release() override;
    IFACEMETHODIMP CreateInstance(IUnknown* pUnkOuter, REFIID riid, void** ppv) override;
    IFACEMETHODIMP LockServer(BOOL fLock) override;

private:
    LONG m_cRef;
};

// -----------------------------------------------------------------------------
// Helpers — tiny pipe + JSON glue. Implemented in TrustForgeCredentialProvider.cpp.
// -----------------------------------------------------------------------------

// Calls the TrustForge daemon over `\\.\pipe\trustforge\decide` with a
// minimal HTTP/1.1 POST /v1/decide request and parses the JSON decision.
// On success, sets *pbAllow to TRUE for "allow", FALSE otherwise. On any
// transport / parse error, returns an HRESULT failure and leaves *pbAllow
// untouched — the caller MUST treat that as deny (fail closed).
HRESULT TfCallDecide(LPCWSTR pwzUsername,
                     LPCWSTR pwzPassword,
                     BOOL* pbAllow,
                     LPWSTR* ppwzReason);
