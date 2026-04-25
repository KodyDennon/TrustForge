// service-main.cpp
//
// TrustForgeService.exe — Windows Service Control Manager (SCM) wrapper for
// the underlying `tf-daemon` binary.
//
// Status: Draft — Phase 0. Experimental, not production-ready.
//
// What this does:
//   * Registers with the SCM via StartServiceCtrlDispatcher.
//   * On SERVICE_START, spawns tf-daemon.exe as a child process from
//     `C:\Program Files\TrustForge\tf-daemon.exe`. Stdout/stderr are
//     redirected to `C:\ProgramData\TrustForge\logs\tf-daemon.log`.
//   * Forwards SERVICE_CONTROL_STOP / PAUSE / CONTINUE to the daemon by
//     writing a one-byte control code to `\\.\pipe\trustforge\control`.
//   * Honors a 10-second graceful-shutdown window. If the daemon does not
//     exit cleanly within that window, the service terminates the child
//     and reports SERVICE_STOPPED with ERROR_SERVICE_REQUEST_TIMEOUT.

#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <winsvc.h>
#include <stdio.h>
#include <strsafe.h>

// ---- service identity ------------------------------------------------------

static const wchar_t kServiceName[]   = L"TrustForge";
static const wchar_t kDaemonExe[]     = L"C:\\Program Files\\TrustForge\\tf-daemon.exe";
static const wchar_t kLogPath[]       = L"C:\\ProgramData\\TrustForge\\logs\\tf-daemon.log";
static const wchar_t kControlPipe[]   = L"\\\\.\\pipe\\trustforge\\control";

static const DWORD kGracefulShutdownMs = 10000;

// ---- service state ---------------------------------------------------------

static SERVICE_STATUS_HANDLE g_StatusHandle = nullptr;
static SERVICE_STATUS        g_Status       = {};
static HANDLE                g_StopEvent    = nullptr;
static HANDLE                g_DaemonProc   = nullptr;
static HANDLE                g_DaemonThread = nullptr;
static HANDLE                g_LogHandle    = nullptr;

// ---- helpers ---------------------------------------------------------------

static void TfReportStatus(DWORD currentState, DWORD win32ExitCode, DWORD waitHintMs)
{
    static DWORD checkPoint = 1;
    g_Status.dwCurrentState  = currentState;
    g_Status.dwWin32ExitCode = win32ExitCode;
    g_Status.dwWaitHint      = waitHintMs;

    if (currentState == SERVICE_START_PENDING) {
        g_Status.dwControlsAccepted = 0;
    } else {
        g_Status.dwControlsAccepted =
            SERVICE_ACCEPT_STOP |
            SERVICE_ACCEPT_PAUSE_CONTINUE |
            SERVICE_ACCEPT_SHUTDOWN;
    }

    if (currentState == SERVICE_RUNNING || currentState == SERVICE_STOPPED) {
        g_Status.dwCheckPoint = 0;
    } else {
        g_Status.dwCheckPoint = checkPoint++;
    }

    if (g_StatusHandle) SetServiceStatus(g_StatusHandle, &g_Status);
}

// Best-effort: ensure C:\ProgramData\TrustForge\logs exists.
static void TfEnsureLogDir(void)
{
    CreateDirectoryW(L"C:\\ProgramData\\TrustForge", nullptr);
    CreateDirectoryW(L"C:\\ProgramData\\TrustForge\\logs", nullptr);
}

// Send a single control byte to the daemon's control pipe. Returns TRUE on
// success. The daemon is expected to handle the codes:
//   's' = stop, 'p' = pause, 'c' = continue.
static BOOL TfSendControl(char code)
{
    // Wait briefly for the pipe — if the daemon is starting up the pipe
    // may not be live yet.
    if (!WaitNamedPipeW(kControlPipe, 1000)) return FALSE;
    HANDLE h = CreateFileW(kControlPipe,
                           GENERIC_WRITE,
                           0, nullptr, OPEN_EXISTING, 0, nullptr);
    if (h == INVALID_HANDLE_VALUE) return FALSE;
    DWORD n = 0;
    BOOL ok = WriteFile(h, &code, 1, &n, nullptr);
    CloseHandle(h);
    return ok && n == 1;
}

// Spawn tf-daemon.exe with stdout/stderr redirected to the log file.
static BOOL TfSpawnDaemon(void)
{
    TfEnsureLogDir();

    SECURITY_ATTRIBUTES sa = { sizeof(sa), nullptr, TRUE };
    g_LogHandle = CreateFileW(kLogPath,
                              FILE_APPEND_DATA,
                              FILE_SHARE_READ | FILE_SHARE_WRITE,
                              &sa,
                              OPEN_ALWAYS,
                              FILE_ATTRIBUTE_NORMAL,
                              nullptr);
    if (g_LogHandle == INVALID_HANDLE_VALUE) g_LogHandle = nullptr;

    STARTUPINFOW si = { sizeof(si) };
    if (g_LogHandle) {
        si.dwFlags    = STARTF_USESTDHANDLES;
        si.hStdInput  = nullptr;
        si.hStdOutput = g_LogHandle;
        si.hStdError  = g_LogHandle;
    }

    PROCESS_INFORMATION pi = {};
    wchar_t cmdLine[MAX_PATH * 2];
    StringCchPrintfW(cmdLine, ARRAYSIZE(cmdLine), L"\"%s\" --service", kDaemonExe);

    BOOL ok = CreateProcessW(kDaemonExe,
                             cmdLine,
                             nullptr, nullptr,
                             /*bInheritHandles*/ TRUE,
                             CREATE_NO_WINDOW,
                             nullptr,
                             nullptr,
                             &si,
                             &pi);
    if (!ok) return FALSE;
    g_DaemonProc   = pi.hProcess;
    g_DaemonThread = pi.hThread;
    return TRUE;
}

// Graceful stop: send 's', wait up to 10s, then terminate.
static void TfStopDaemon(void)
{
    if (!g_DaemonProc) return;
    TfSendControl('s');

    DWORD r = WaitForSingleObject(g_DaemonProc, kGracefulShutdownMs);
    if (r != WAIT_OBJECT_0) {
        // Last resort.
        TerminateProcess(g_DaemonProc, ERROR_SERVICE_REQUEST_TIMEOUT);
        WaitForSingleObject(g_DaemonProc, 2000);
    }
    if (g_DaemonThread) { CloseHandle(g_DaemonThread); g_DaemonThread = nullptr; }
    CloseHandle(g_DaemonProc);
    g_DaemonProc = nullptr;
    if (g_LogHandle) { CloseHandle(g_LogHandle); g_LogHandle = nullptr; }
}

// ---- SCM callback ----------------------------------------------------------

static DWORD WINAPI ServiceCtrlHandlerEx(DWORD ctrl, DWORD /*evtType*/,
                                         LPVOID /*evtData*/, LPVOID /*ctx*/)
{
    switch (ctrl) {
    case SERVICE_CONTROL_STOP:
    case SERVICE_CONTROL_SHUTDOWN:
        TfReportStatus(SERVICE_STOP_PENDING, NO_ERROR, kGracefulShutdownMs + 2000);
        SetEvent(g_StopEvent);
        return NO_ERROR;

    case SERVICE_CONTROL_PAUSE:
        TfReportStatus(SERVICE_PAUSE_PENDING, NO_ERROR, 3000);
        if (TfSendControl('p')) {
            TfReportStatus(SERVICE_PAUSED, NO_ERROR, 0);
        } else {
            TfReportStatus(SERVICE_RUNNING, ERROR_SERVICE_NOT_ACTIVE, 0);
        }
        return NO_ERROR;

    case SERVICE_CONTROL_CONTINUE:
        TfReportStatus(SERVICE_CONTINUE_PENDING, NO_ERROR, 3000);
        if (TfSendControl('c')) {
            TfReportStatus(SERVICE_RUNNING, NO_ERROR, 0);
        } else {
            TfReportStatus(SERVICE_PAUSED, ERROR_SERVICE_NOT_ACTIVE, 0);
        }
        return NO_ERROR;

    case SERVICE_CONTROL_INTERROGATE:
        return NO_ERROR;

    default:
        return ERROR_CALL_NOT_IMPLEMENTED;
    }
}

// ---- service main ----------------------------------------------------------

static VOID WINAPI ServiceMain(DWORD /*argc*/, LPWSTR* /*argv*/)
{
    g_Status.dwServiceType = SERVICE_WIN32_OWN_PROCESS;
    g_Status.dwCurrentState = SERVICE_START_PENDING;

    g_StatusHandle = RegisterServiceCtrlHandlerExW(kServiceName,
                                                   ServiceCtrlHandlerEx,
                                                   nullptr);
    if (!g_StatusHandle) return;

    TfReportStatus(SERVICE_START_PENDING, NO_ERROR, 5000);

    g_StopEvent = CreateEventW(nullptr, TRUE, FALSE, nullptr);
    if (!g_StopEvent) {
        TfReportStatus(SERVICE_STOPPED, GetLastError(), 0);
        return;
    }

    if (!TfSpawnDaemon()) {
        DWORD err = GetLastError();
        TfReportStatus(SERVICE_STOPPED, err ? err : ERROR_SERVICE_SPECIFIC_ERROR, 0);
        CloseHandle(g_StopEvent);
        g_StopEvent = nullptr;
        return;
    }

    TfReportStatus(SERVICE_RUNNING, NO_ERROR, 0);

    // Wait until SCM asks us to stop OR the daemon exits unexpectedly.
    HANDLE handles[2] = { g_StopEvent, g_DaemonProc };
    DWORD w = WaitForMultipleObjects(2, handles, FALSE, INFINITE);

    TfReportStatus(SERVICE_STOP_PENDING, NO_ERROR, kGracefulShutdownMs + 2000);

    if (w == WAIT_OBJECT_0) {
        // SCM stop request — graceful.
        TfStopDaemon();
        TfReportStatus(SERVICE_STOPPED, NO_ERROR, 0);
    } else if (w == WAIT_OBJECT_0 + 1) {
        // Daemon died on its own. Reap and report a service-specific error.
        DWORD exitCode = ERROR_SERVICE_SPECIFIC_ERROR;
        GetExitCodeProcess(g_DaemonProc, &exitCode);
        if (g_DaemonThread) { CloseHandle(g_DaemonThread); g_DaemonThread = nullptr; }
        CloseHandle(g_DaemonProc);
        g_DaemonProc = nullptr;
        if (g_LogHandle) { CloseHandle(g_LogHandle); g_LogHandle = nullptr; }
        TfReportStatus(SERVICE_STOPPED,
                       exitCode ? exitCode : ERROR_SERVICE_SPECIFIC_ERROR, 0);
    } else {
        TfStopDaemon();
        TfReportStatus(SERVICE_STOPPED, GetLastError(), 0);
    }

    if (g_StopEvent) { CloseHandle(g_StopEvent); g_StopEvent = nullptr; }
}

// ---- entry point -----------------------------------------------------------

int wmain(int /*argc*/, wchar_t** /*argv*/)
{
    SERVICE_TABLE_ENTRYW table[] = {
        { (LPWSTR)kServiceName, ServiceMain },
        { nullptr, nullptr }
    };

    if (!StartServiceCtrlDispatcherW(table)) {
        // Common cause: the binary was launched directly from a console
        // instead of being started by the SCM. Surface the error code so
        // it shows up in `sc start` output / the Application event log.
        return (int)GetLastError();
    }
    return 0;
}
