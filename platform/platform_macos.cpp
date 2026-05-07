/*
 * platform/platform_macos.cpp
 * Role: macOS backend for the hk::platform abstraction layer.
 * Target platforms: macOS only. Selected by CMake if(APPLE).
 * Implements: platform/platform.h
 */

#include "platform.h"
#include <unistd.h>
#include <sys/sysctl.h>
#include <sys/types.h>
#include <cstring>

namespace hk { namespace platform {

uint32_t page_size() {
    return static_cast<uint32_t>(getpagesize());
}

process_id_t current_process_id() {
    return static_cast<process_id_t>(getpid());
}

bool is_debugger_attached() {
    /* Check the P_TRACED flag via sysctl(KERN_PROC_PID). Phase 1 only;
       hardened detection lands in a later phase. */
    struct kinfo_proc info;
    memset(&info, 0, sizeof(info));

    int mib[4] = { CTL_KERN, KERN_PROC, KERN_PROC_PID, getpid() };
    size_t size = sizeof(info);

    if (sysctl(mib, 4, &info, &size, nullptr, 0) != 0) {
        return false;
    }
    return (info.kp_proc.p_flag & P_TRACED) != 0;
}

} } // namespace hk::platform
