/*
 * sdk/src/sdk.cpp
 * Role: Platform-neutral implementation of the public SDK surface (sdk.h).
 *       Composes the DRM and AC libraries and reports active vs degraded mode
 *       based on the platform driver probe (sdk_backend.h). Contains no
 *       platform API directly — driver detection routes through a backend
 *       (guardrail #1).
 * Target platforms: all (PC first).
 * Interface: implements sdk/include/horkos/sdk.h.
 */

#include "horkos/sdk.h"

#include "horkos/ac.h"
#include "horkos/drm.h"

#include "sdk_backend.h"

namespace {

hk_mode g_mode = HK_MODE_UNINITIALIZED;

} // namespace

extern "C" int horkos_init(void)
{
    const bool driver_present = hk::sdk::probe_driver();
    g_mode = driver_present ? HK_MODE_ACTIVE : HK_MODE_DEGRADED;
    return driver_present ? HK_SDK_OK : HK_SDK_DEGRADED;
}

extern "C" hk_mode horkos_mode(void)
{
    return g_mode;
}

extern "C" int horkos_drm_validate(void)
{
    drm_context_t* ctx = drm_create_context();
    const int rc = drm_validate(ctx);
    drm_destroy_context(ctx);

    switch (rc) {
    case HK_DRM_OK:
        return HK_SDK_OK;
    case HK_DRM_NOT_IMPLEMENTED:
        return HK_SDK_NOT_IMPLEMENTED;
    default:
        return HK_SDK_ERROR;
    }
}

extern "C" int horkos_ac_start(void)
{
    const int rc = ac_start(nullptr);
    switch (rc) {
    case HK_AC_OK:
        return HK_SDK_OK;
    case HK_AC_DEGRADED:
        return HK_SDK_DEGRADED;
    case HK_AC_NOT_IMPLEMENTED:
        return HK_SDK_NOT_IMPLEMENTED;
    default:
        return HK_SDK_ERROR;
    }
}

extern "C" int horkos_shutdown(void)
{
    const int rc = ac_stop();
    g_mode = HK_MODE_UNINITIALIZED;
    return (rc == HK_AC_OK || rc == HK_AC_NOT_IMPLEMENTED) ? HK_SDK_OK
                                                           : HK_SDK_ERROR;
}
