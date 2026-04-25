# CMakeLists.txt for TrustForgeService
#
# Builds TrustForgeService.exe — a Windows Service Control Manager wrapper
# around the tf-daemon binary. The service starts the daemon as a child
# process, forwards SCM control codes (stop/pause/continue) to it via the
# `\\.\pipe\trustforge\control` named pipe, and reports SERVICE_STOPPED
# back to the SCM with a 10-second graceful-shutdown window.
#
# Status: Draft — Phase 0. Experimental, not production-ready.
#
# Must be built on Windows with Visual Studio (MSVC) + Windows SDK.

cmake_minimum_required(VERSION 3.20)
project(TrustForgeService LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

if(NOT WIN32)
    message(FATAL_ERROR
        "TrustForgeService must be built on Windows. It depends on "
        "winsvc.h and the Service Control Manager APIs (advapi32).")
endif()

add_executable(TrustForgeService
    service-main.cpp
)

target_include_directories(TrustForgeService PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}
)

# advapi32  — RegisterServiceCtrlHandler / SetServiceStatus / SCM
# ole32     — CoInitialize, in case daemon dispatch needs it
target_link_libraries(TrustForgeService PRIVATE
    advapi32
    ole32
)

target_compile_definitions(TrustForgeService PRIVATE
    UNICODE
    _UNICODE
    WIN32_LEAN_AND_MEAN
    NOMINMAX
)

if(MSVC)
    target_compile_options(TrustForgeService PRIVATE
        /W4
        /permissive-
        $<$<CONFIG:Release>:/MT>
        $<$<CONFIG:Debug>:/MTd>
    )
endif()
