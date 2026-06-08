/*
 * drm/src/drm.cpp
 * Role: DRM C API stub implementation. All functions return NOT_IMPLEMENTED.
 *       Real licence validation and hardware binding land in a later phase
 *       under /tdd, with bypass tests in Phase 5.
 * Target platforms: Windows, Linux, macOS.
 * Implements: drm/include/horkos/drm.h
 */

#include <horkos/drm.h>
#include <cstdint>
#include <cstdlib>

/* Sentinel type used as the opaque drm_context_t in Phase 1 stubs. */
struct drm_context_t {
    uint32_t sentinel;
};

static constexpr uint32_t kDrmSentinel = 0xDEADC0DE;

drm_context_t* drm_create_context(void) {
    auto* ctx = static_cast<drm_context_t*>(std::malloc(sizeof(drm_context_t)));
    if (ctx) ctx->sentinel = kDrmSentinel;
    return ctx;
}

void drm_destroy_context(drm_context_t* ctx) {
    std::free(ctx);
}

int drm_validate(const drm_context_t* ctx) {
    if (!ctx || ctx->sentinel != kDrmSentinel) {
        return HK_DRM_INVALID_CTX;
    }
    return HK_DRM_NOT_IMPLEMENTED;
}
