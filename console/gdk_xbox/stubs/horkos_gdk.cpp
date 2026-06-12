/*
 * Role: Public-doc-shaped GDK integration stubs for Horkos attestation/identity
 *       on Xbox / Microsoft Game Development Kit. Signatures mirror the PUBLIC
 *       XGameRuntime / XUser surface documented on learn.microsoft.com; the real
 *       GDK headers are proprietary and absent (Locked Decision #7, guardrail
 *       #2). Every stub returns HK_GDK_NOT_AVAILABLE and names the documented
 *       function it maps to. Excluded from the default build (no CMake target
 *       references this file); it compiles only inside a real GDK environment.
 * Target platforms: Xbox (GDK). Not built on PC/Linux/macOS.
 */

#include <cstdint>

#define HK_GDK_OK             0
#define HK_GDK_NOT_AVAILABLE  1

/*
 * Maps to XGameRuntimeInitialize:
 *   https://learn.microsoft.com/gaming/gdk/_content/gc/reference/system/xgameruntimeinitialize/functions/xgameruntimeinitialize
 * Initializes the GDK runtime before any other Horkos GDK call.
 */
int hk_gdk_runtime_init(void) {
    return HK_GDK_NOT_AVAILABLE;
}

/*
 * Maps to XUserAddAsync / XUserGetId:
 *   https://learn.microsoft.com/gaming/gdk/_content/gc/reference/live/xuser/functions/xuseraddasync
 * Resolves the signed-in user's stable id for licence binding.
 */
int hk_gdk_get_user_id(uint64_t* out_user_id) {
    if (out_user_id) {
        *out_user_id = 0;
    }
    return HK_GDK_NOT_AVAILABLE;
}

/*
 * Maps to XStoreQueryLicense / XStoreQueryEntitlementsAsync:
 *   https://learn.microsoft.com/gaming/gdk/_content/gc/reference/commerce/xstore
 * Confirms the title licence/entitlement — the GDK analogue of the DRM licence
 * check, surfaced through the same Attestation.h interface on PC.
 */
int hk_gdk_query_license(int* out_is_licensed) {
    if (out_is_licensed) {
        *out_is_licensed = 0;
    }
    return HK_GDK_NOT_AVAILABLE;
}
