/*
 * platform/platform_win.cpp
 * Role: Windows backend for the hk::platform abstraction layer.
 * Target platforms: Windows only. Selected by CMake if(WIN32).
 * Implements: platform/platform.h
 */

#include "platform.h"
#include <windows.h>
#include <sysinfoapi.h>

namespace hk { namespace platform {

uint32_t page_size() {
    SYSTEM_INFO si{};
    GetSystemInfo(&si);
    return static_cast<uint32_t>(si.dwPageSize);
}

process_id_t current_process_id() {
    return static_cast<process_id_t>(GetCurrentProcessId());
}

bool is_debugger_attached() {
    return IsDebuggerPresent() != FALSE;
}

} } // namespace hk::platform
