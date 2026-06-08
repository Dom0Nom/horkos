/*
 * sdk/include/horkos/sdk.h
 * Role: Public SDK C surface a game integrates. Stable across versions
 *       (guardrail #10 spirit). Wraps drm_validate / ac_start and reports
 *       whether the kernel driver is present (active vs degraded mode).
 * Target platforms: Windows (Phase 3); Linux/macOS land the same surface in
 *       Phase 4 with their own driver-presence probe.
 * Interface: this IS the SDK public surface; sdk/src/sdk.cpp implements it.
 */

#pragma once

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Return codes shared across the SDK entry points. */
#define HK_SDK_OK              0
#define HK_SDK_DEGRADED        1  /* Initialized, but kernel driver not loaded. */
#define HK_SDK_ERROR           2
#define HK_SDK_NOT_IMPLEMENTED 3

/* Operating mode reported by horkos_init / horkos_mode. */
typedef enum hk_mode {
    HK_MODE_UNINITIALIZED = 0,
    HK_MODE_ACTIVE        = 1,  /* Kernel driver present and reachable. */
    HK_MODE_DEGRADED      = 2,  /* Userspace only; no kernel visibility. */
} hk_mode;

/*
 * horkos_init — initialize the SDK. Probes for the kernel driver and sets the
 * operating mode. Safe to call once at game startup. Returns HK_SDK_OK in
 * active mode, HK_SDK_DEGRADED when the driver is absent (not an error — the
 * game still runs), HK_SDK_ERROR on hard failure.
 */
int horkos_init(void);

/*
 * horkos_mode — current operating mode. HK_MODE_UNINITIALIZED before init.
 */
hk_mode horkos_mode(void);

/*
 * horkos_drm_validate — run the DRM licence/integrity validation path.
 * Delegates to drm_validate. Returns HK_SDK_OK / HK_SDK_NOT_IMPLEMENTED.
 */
int horkos_drm_validate(void);

/*
 * horkos_ac_start — start the anti-cheat client. Delegates to ac_start.
 * In degraded mode the AC still runs its userspace checks.
 */
int horkos_ac_start(void);

/*
 * horkos_shutdown — stop the AC and release SDK resources.
 */
int horkos_shutdown(void);

#ifdef __cplusplus
} /* extern "C" */
#endif
