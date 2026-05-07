/*
 * ac/src/ac.cpp
 * Role: Anti-cheat C API stub implementation. All functions return
 *       HK_AC_NOT_IMPLEMENTED. Real detection logic lands in a later
 *       phase under /tdd with bypass tests in Phase 5.
 * Target platforms: Windows, Linux, macOS.
 * Implements: ac/include/horkos/ac.h
 */

#include <horkos/ac.h>

struct ac_config_t {
    uint32_t reserved;
};

int ac_start(const ac_config_t* /*cfg*/) {
    return HK_AC_NOT_IMPLEMENTED;
}

int ac_stop(void) {
    return HK_AC_NOT_IMPLEMENTED;
}

uint32_t ac_get_last_flag(void) {
    return 0u;
}
