/*
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
 * horkos_set_tick_sink — register the host's telemetry transport. The SDK calls
 * `sink(json, len, user)` once per `horkos_submit_tick` with the serialized
 * TickPayload JSON; the host owns the actual send (HTTP POST to the AC server).
 * Passing NULL clears the sink (submitted ticks are then dropped). The SDK bakes
 * in no network stack — transport is the integrator's, behind this seam.
 */
typedef void (*hk_tick_sink_fn)(const char* json, uint64_t len, void* user);
void horkos_set_tick_sink(hk_tick_sink_fn sink, void* user);

/*
 * horkos_submit_tick — the per-frame entry point. The host game calls this once
 * per tick with the SERVER simulation tick it last consumed plus the assembled
 * aim features (see sdk/src/TelemetrySerialize.h `hk_tick_input`). The SDK
 * serializes a TickPayload whose `tick` field ECHOES `server_tick` and hands the
 * JSON to the registered sink. `tick_input` is
 * `const hk::sdk::telemetry::hk_tick_input*` (typed `void*` here to keep this C
 * surface free of the C++ POD). Returns HK_SDK_OK, HK_SDK_ERROR on a
 * null/oversized payload, or HK_SDK_DEGRADED when no sink is registered.
 */
int horkos_submit_tick(const void* tick_input);

/*
 * horkos_shutdown — stop the AC and release SDK resources.
 */
int horkos_shutdown(void);

#ifdef __cplusplus
} /* extern "C" */
#endif
