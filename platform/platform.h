/*
 * platform/platform.h
 * Role: Single source of platform truth for the entire codebase.
 *       Defines HK_PLATFORM_* macros and declares cross-platform abstractions.
 *       Every platform-conditional include or API must route through this header.
 * Target platforms: Windows, Linux, macOS
 * Interface: this IS the platform interface header; backends implement it.
 */

#pragma once

/* -------------------------------------------------------------------------
 * Platform detection — set exactly once, here, never elsewhere.
 * Backends in platform_win.cpp / platform_linux.cpp / platform_macos.cpp
 * are selected by CMake if(WIN32)/if(APPLE)/if(UNIX) and always compile
 * for their matching host, so they do not need these guards at file scope.
 * ------------------------------------------------------------------------- */
#if defined(_WIN32)
#  define HK_PLATFORM_WINDOWS 1
#elif defined(__APPLE__)
#  define HK_PLATFORM_MACOS   1
#elif defined(__linux__)
#  define HK_PLATFORM_LINUX   1
#else
#  error "Unsupported platform"
#endif

#include <cstdint>

namespace hk { namespace platform {

/* Process identifier type. On Windows this is DWORD; on POSIX it is pid_t.
   We expose it as a fixed-width alias so callers never include OS headers. */
using process_id_t    = uint32_t;

/* Opaque handle to a loaded module / shared library. */
using module_handle_t = void*;

/* Returns the OS page size in bytes. */
uint32_t page_size();

/* Returns the calling process's PID. */
process_id_t current_process_id();

/* Returns true if a debugger is currently attached to this process.
   Phase 1 implementation is deliberately weak (system API only).
   Anti-debug hardening lands in a later phase under /tdd. */
bool is_debugger_attached();

} } // namespace hk::platform
