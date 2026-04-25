# CMakeLists.txt for TrustForgeCredentialProvider
#
# Builds TrustForgeCredentialProvider.dll — a Windows Credential Provider
# (ICredentialProvider COM in-process server) that consults the TrustForge
# daemon over a named pipe before returning a serialized credential to LogonUI.
#
# Status: Draft — Phase 0. Experimental, not production-ready.
#
# This must be built on Windows with Visual Studio (MSVC) + the Windows SDK.
# It will not build on macOS or Linux. CMakeLists is provided so the project
# can be opened with Visual Studio "Open Folder" or generated via:
#
#   cmake -S . -B build -G "Visual Studio 17 2022" -A x64
#   cmake --build build --config Release
#
# Configurations: Win32 and x64. Both produce a single DLL whose path must
# match the InProcServer32 entry in register.reg.

cmake_minimum_required(VERSION 3.20)
project(TrustForgeCredentialProvider LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

if(NOT WIN32)
    message(FATAL_ERROR
        "TrustForgeCredentialProvider must be built on Windows. "
        "It is a COM in-process server that depends on the Windows SDK "
        "(credentialprovider.h, credui.h, etc.).")
endif()

# Build as a DLL.
add_library(TrustForgeCredentialProvider SHARED
    dllmain.cpp
    TrustForgeCredentialProvider.cpp
)

target_include_directories(TrustForgeCredentialProvider PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}
)

# Windows libraries:
#   credui    — CredPackAuthenticationBuffer / CredUI helpers
#   secur32   — LSA / SSPI helpers
#   advapi32  — registry, security descriptors
#   ole32     — COM
#   shlwapi   — string helpers used by the provider
target_link_libraries(TrustForgeCredentialProvider PRIVATE
    credui
    secur32
    advapi32
    ole32
    shlwapi
)

# Define UNICODE so all Win32 APIs use the wide-char variants. LogonUI
# always passes wide strings.
target_compile_definitions(TrustForgeCredentialProvider PRIVATE
    UNICODE
    _UNICODE
    WIN32_LEAN_AND_MEAN
    NOMINMAX
)

# DLL must export DllGetClassObject / DllCanUnloadNow / DllRegisterServer /
# DllUnregisterServer. Use a .def-equivalent via __declspec(dllexport) in
# dllmain.cpp; no .def file required.
set_target_properties(TrustForgeCredentialProvider PROPERTIES
    OUTPUT_NAME "TrustForgeCredentialProvider"
    PREFIX ""
    SUFFIX ".dll"
)

# Use static CRT to avoid VC++ runtime dependency in winlogon.exe.
if(MSVC)
    target_compile_options(TrustForgeCredentialProvider PRIVATE
        /W4
        /permissive-
        $<$<CONFIG:Release>:/MT>
        $<$<CONFIG:Debug>:/MTd>
    )
endif()
