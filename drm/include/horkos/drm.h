/*
 * drm/include/horkos/drm.h
 * Role: Public C API for Horkos DRM. Applies only to game init, licence,
 *       integrity, and attestation paths — never the hot loop (guardrail #9).
 *       Logic lands in a later phase under /tdd.
 * Target platforms: Windows, Linux, macOS (PC first; console-ready interface).
 * Interface: this IS the DRM public C surface; drm/src/drm.cpp implements it.
 */

#pragma once

#ifdef __cplusplus
extern "C" {
#endif

/* Return codes for all drm_* functions. */
#define HK_DRM_OK               0
#define HK_DRM_NOT_IMPLEMENTED  1
#define HK_DRM_INVALID_CTX      2
#define HK_DRM_LICENCE_INVALID  3
#define HK_DRM_HARDWARE_FAIL    4

/* Opaque DRM context. Allocated by drm_create_context, freed by
   drm_destroy_context. Never allocate on the stack. */
typedef struct drm_context_t drm_context_t;

/*
 * drm_validate — validate the current DRM licence against hardware binding.
 * ctx  must be a non-NULL context returned by drm_create_context.
 * Returns HK_DRM_OK on success; an HK_DRM_* error code otherwise.
 * Phase 1: always returns HK_DRM_NOT_IMPLEMENTED.
 */
int drm_validate(const drm_context_t* ctx);

/*
 * drm_create_context / drm_destroy_context — lifecycle management.
 * Phase 1: create returns a sentinel non-NULL pointer; destroy is a no-op.
 */
drm_context_t* drm_create_context(void);
void           drm_destroy_context(drm_context_t* ctx);

#ifdef __cplusplus
} /* extern "C" */
#endif
