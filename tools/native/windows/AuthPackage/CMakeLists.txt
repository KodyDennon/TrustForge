# CMakeLists.txt for TrustForgeLsa
#
# Builds TrustForgeLsa.dll — a Windows LSA Authentication Package that
# brokers logon decisions through the TrustForge daemon. Loaded by
# lsass.exe at boot.
#
# Status: Draft — Phase 0. Experimental, NOT production-ready.
#
# !!! WARNING !!!
# An LSA authentication package that crashes or returns invalid status from
# LsaApInitializePackage prevents lsass.exe from starting, which means the
# system cannot boot. Test in a VM with a known-good restore point. Always
# keep an Administrator account that does NOT depend on this package.
#
# This must be built on Windows with Visual Studio (MSVC) + Windows SDK.

cmake_minimum_required(VERSION 3.20)
project(TrustForgeLsa LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

if(NOT WIN32)
    message(FATAL_ERROR
        "TrustForgeLsa must be built on Windows. It depends on the LSA "
        "headers (ntsecapi.h, ntsecpkg.h) shipped only with the Windows SDK.")
endif()

add_library(TrustForgeLsa SHARED
    TrustForgeLsa.cpp
)

target_include_directories(TrustForgeLsa PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}
)

# secur32   — LSA support libraries
# advapi32  — registry, security descriptors
# ntdll     — RtlInitUnicodeString and friends
target_link_libraries(TrustForgeLsa PRIVATE
    secur32
    advapi32
    ntdll
)

target_compile_definitions(TrustForgeLsa PRIVATE
    UNICODE
    _UNICODE
    SECURITY_WIN32
    WIN32_LEAN_AND_MEAN
    NOMINMAX
)

set_target_properties(TrustForgeLsa PROPERTIES
    OUTPUT_NAME "TrustForgeLsa"
    PREFIX ""
    SUFFIX ".dll"
)

# Static CRT — lsass.exe must not depend on the side-by-side VC++ runtime.
if(MSVC)
    target_compile_options(TrustForgeLsa PRIVATE
        /W4
        /permissive-
        /GS                                # buffer security checks
        $<$<CONFIG:Release>:/MT>
        $<$<CONFIG:Debug>:/MTd>
    )
    target_link_options(TrustForgeLsa PRIVATE
        /DYNAMICBASE
        /NXCOMPAT
    )
endif()
