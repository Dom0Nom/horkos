/*
 * examples/pc_basic/main.cpp
 * Role: Minimal SDK integration example. Calls horkos_init, horkos_drm_validate,
 *       and horkos_ac_start, then prints whether the stack is running in ACTIVE
 *       (kernel driver present) or DEGRADED (userspace-only) mode. Must not
 *       crash with or without the driver loaded.
 * Target platforms: Windows (Phase 3); builds on Linux/macOS in degraded mode.
 * Interface: consumes sdk/include/horkos/sdk.h.
 */

#include <cstdio>

#include "horkos/sdk.h"

static const char* mode_name(hk_mode m)
{
    switch (m) {
    case HK_MODE_ACTIVE:   return "ACTIVE (kernel driver present)";
    case HK_MODE_DEGRADED: return "DEGRADED (userspace only)";
    default:               return "UNINITIALIZED";
    }
}

int main(void)
{
    const int init_rc = horkos_init();
    std::printf("horkos_init       -> %d\n", init_rc);
    std::printf("mode              -> %s\n", mode_name(horkos_mode()));

    std::printf("horkos_drm_validate -> %d\n", horkos_drm_validate());
    std::printf("horkos_ac_start     -> %d\n", horkos_ac_start());

    horkos_shutdown();
    std::printf("shutdown done.\n");

    /* The example reports status; it never fails the process on degraded mode. */
    return 0;
}
