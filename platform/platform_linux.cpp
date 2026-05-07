/*
 * platform/platform_linux.cpp
 * Role: Linux backend for the hk::platform abstraction layer.
 * Target platforms: Linux only. Selected by CMake if(UNIX AND NOT APPLE).
 * Implements: platform/platform.h
 */

#include "platform.h"
#include <unistd.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <cstdio>
#include <cstring>

namespace hk { namespace platform {

uint32_t page_size() {
    const long ps = sysconf(_SC_PAGESIZE);
    return static_cast<uint32_t>(ps > 0 ? ps : 4096);
}

process_id_t current_process_id() {
    return static_cast<process_id_t>(getpid());
}

bool is_debugger_attached() {
    /* Read TracerPid from /proc/self/status. A non-zero value means a
       debugger is attached. Phase 1 uses this simple heuristic only;
       hardened detection lands in a later phase. */
    FILE* f = fopen("/proc/self/status", "r");
    if (!f) return false;

    char line[256];
    bool result = false;
    while (fgets(line, sizeof(line), f)) {
        if (strncmp(line, "TracerPid:", 10) == 0) {
            long tracer_pid = 0;
            if (sscanf(line + 10, "%ld", &tracer_pid) == 1) {
                result = tracer_pid != 0;
            }
            break;
        }
    }
    fclose(f);
    return result;
}

} } // namespace hk::platform
