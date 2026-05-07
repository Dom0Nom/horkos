/*
 * ac/include/horkos/ac.h
 * Role: Public C API for Horkos anti-cheat client. Logic lands in a later
 *       phase under /tdd with bypass tests in Phase 5.
 * Target platforms: Windows, Linux, macOS (PC first; console-ready interface).
 * Interface: this IS the AC public C surface; ac/src/ac.cpp implements it.
 */

#pragma once

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Return codes for all ac_* functions. */
#define HK_AC_OK               0
#define HK_AC_NOT_IMPLEMENTED  1
#define HK_AC_ALREADY_RUNNING  2
#define HK_AC_DRIVER_MISSING   3
#define HK_AC_DEGRADED         4

/* Opaque AC configuration. Passed to ac_start. */
typedef struct ac_config_t ac_config_t;

/*
 * ac_start — start the anti-cheat client with the given configuration.
 * Returns HK_AC_OK on success; HK_AC_DEGRADED when running without the
 * kernel driver; HK_AC_NOT_IMPLEMENTED in Phase 1 stubs.
 */
int ac_start(const ac_config_t* cfg);

/*
 * ac_stop — stop the anti-cheat client and release resources.
 * Returns HK_AC_OK on success.
 */
int ac_stop(void);

/*
 * ac_get_last_flag — retrieve the most recent detection flag bitmask.
 * Used by bypass tests (Phase 5) to assert detection without a ban.
 */
uint32_t ac_get_last_flag(void);

#ifdef __cplusplus
} /* extern "C" */
#endif
