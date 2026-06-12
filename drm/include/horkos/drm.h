/*
 * Role: Public C API for Horkos DRM. Applies only to game init, licence,
 *       integrity, and attestation paths — never the hot loop (guardrail #9).
 *       A licence is an Ed25519-signed claim binding a product + hardware id +
 *       expiry; drm_validate verifies the signature against a pinned server
 *       public key and enforces the hardware binding and expiry, fail-closed.
 * Target platforms: Windows, Linux, macOS (PC first; console-ready interface).
 * Interface: this IS the DRM public C surface; drm/src/drm.cpp implements it.
 */

#pragma once

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Return codes for all drm_* functions. */
#define HK_DRM_OK               0
#define HK_DRM_NOT_IMPLEMENTED  1
#define HK_DRM_INVALID_CTX      2
#define HK_DRM_LICENCE_INVALID  3
#define HK_DRM_HARDWARE_FAIL    4

/* Licence-claim wire format (the signed bytes). Fixed-size, no parsing needed
 * on the client. The server signs exactly these bytes; drm_validate verifies
 * the detached signature over them. A token is `claims || signature[64]`. */
#define HK_DRM_CLAIMS_MAGIC   0x484B4C43u /* 'HKLC' */
#define HK_DRM_CLAIMS_VERSION 1u
#define HK_DRM_HWID_MAX       64
#define HK_DRM_PRODUCT_MAX    32
#define HK_DRM_SIG_BYTES      64
#define HK_DRM_PUBKEY_BYTES   32

typedef struct hk_drm_claims {
    uint32_t magic;            /* == HK_DRM_CLAIMS_MAGIC. */
    uint32_t version;          /* == HK_DRM_CLAIMS_VERSION. */
    uint64_t expires_unix_s;   /* licence expiry, seconds since epoch. */
    char     hardware_id[HK_DRM_HWID_MAX];   /* NUL-padded bound hardware id. */
    char     product_id[HK_DRM_PRODUCT_MAX]; /* NUL-padded product id. */
} hk_drm_claims;

/* Opaque DRM context. Allocated by drm_create_context, freed by
   drm_destroy_context. Never allocate on the stack. */
typedef struct drm_context_t drm_context_t;

/*
 * drm_configure — install the validation material before drm_validate.
 *   pubkey      : the pinned 32-byte server Ed25519 public key.
 *   token       : claims || signature (sizeof(hk_drm_claims) + 64 bytes).
 *   token_len   : length of token; must equal sizeof(hk_drm_claims)+64.
 *   hardware_id : this machine's hardware id (NUL-terminated).
 * Returns HK_DRM_OK if stored, HK_DRM_INVALID_CTX / HK_DRM_LICENCE_INVALID on
 * bad arguments. An unconfigured context fails validation closed.
 */
int drm_configure(drm_context_t* ctx,
                  const uint8_t* pubkey,
                  const uint8_t* token, size_t token_len,
                  const char* hardware_id);

/*
 * drm_validate — verify the configured licence: Ed25519 signature over the
 * claims against the pinned key, claim magic/version, hardware binding to this
 * machine, and expiry. ctx must be a non-NULL configured context.
 * Returns HK_DRM_OK on a valid licence; HK_DRM_LICENCE_INVALID (bad signature/
 * format/expiry), HK_DRM_HARDWARE_FAIL (bound to other hardware), or
 * HK_DRM_INVALID_CTX. Fail-closed: an unconfigured context returns
 * HK_DRM_LICENCE_INVALID.
 */
int drm_validate(const drm_context_t* ctx);

/*
 * drm_create_context / drm_destroy_context — lifecycle management.
 */
drm_context_t* drm_create_context(void);
void           drm_destroy_context(drm_context_t* ctx);

#ifdef __cplusplus
} /* extern "C" */
#endif
