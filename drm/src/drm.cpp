/*
 * Role: DRM C API implementation — Ed25519 licence verification with hardware
 *       binding and expiry. A licence token is `hk_drm_claims || signature[64]`;
 *       drm_validate verifies the detached signature against the pinned server
 *       public key (libsodium crypto_sign_verify_detached), then enforces the
 *       claim magic/version, the hardware binding to this machine, and expiry.
 *       Every failure is fail-closed (an unconfigured context never validates).
 * Target platforms: Windows, Linux, macOS. Uses libsodium for Ed25519 (a real
 *       deployment static-links it cross-platform; consoles use their own
 *       crypto). Not the hot loop (guardrail #9).
 * Implements: drm/include/horkos/drm.h
 */

#include <horkos/drm.h>

#include <sodium.h>

#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <ctime>

namespace {

constexpr uint32_t kDrmSentinel = 0xDEADC0DE;
constexpr size_t kTokenLen = sizeof(hk_drm_claims) + HK_DRM_SIG_BYTES;

/* Ensure libsodium is initialised exactly once before any crypto call. */
bool ensure_sodium() {
    static const int rc = sodium_init();
    return rc >= 0; // 0 = ok, 1 = already initialised
}

} // namespace

struct drm_context_t {
    uint32_t sentinel;
    bool     configured;
    uint8_t  pubkey[HK_DRM_PUBKEY_BYTES];
    uint8_t  token[kTokenLen];
    char     hardware_id[HK_DRM_HWID_MAX]; // NUL-terminated local hardware id
};

extern "C" drm_context_t* drm_create_context(void) {
    auto* ctx = static_cast<drm_context_t*>(std::calloc(1, sizeof(drm_context_t)));
    if (ctx) {
        ctx->sentinel = kDrmSentinel;
        ctx->configured = false;
    }
    return ctx;
}

extern "C" void drm_destroy_context(drm_context_t* ctx) {
    if (ctx) {
        // Scrub material before free (hygiene for a licence path).
        sodium_memzero(ctx, sizeof(*ctx));
        std::free(ctx);
    }
}

extern "C" int drm_configure(drm_context_t* ctx,
                             const uint8_t* pubkey,
                             const uint8_t* token, size_t token_len,
                             const char* hardware_id) {
    if (!ctx || ctx->sentinel != kDrmSentinel) {
        return HK_DRM_INVALID_CTX;
    }
    if (!pubkey || !token || !hardware_id || token_len != kTokenLen) {
        return HK_DRM_LICENCE_INVALID;
    }
    std::memcpy(ctx->pubkey, pubkey, HK_DRM_PUBKEY_BYTES);
    std::memcpy(ctx->token, token, kTokenLen);
    // Bounded copy of the local hardware id; always NUL-terminated.
    std::strncpy(ctx->hardware_id, hardware_id, HK_DRM_HWID_MAX - 1);
    ctx->hardware_id[HK_DRM_HWID_MAX - 1] = '\0';
    ctx->configured = true;
    return HK_DRM_OK;
}

extern "C" int drm_validate(const drm_context_t* ctx) {
    if (!ctx || ctx->sentinel != kDrmSentinel) {
        return HK_DRM_INVALID_CTX;
    }
    // Fail-closed: an unconfigured context is never valid.
    if (!ctx->configured) {
        return HK_DRM_LICENCE_INVALID;
    }
    if (!ensure_sodium()) {
        return HK_DRM_LICENCE_INVALID;
    }

    const uint8_t* claims_bytes = ctx->token;
    const uint8_t* sig = ctx->token + sizeof(hk_drm_claims);

    // 1. Ed25519 signature over the claims bytes against the pinned key.
    if (crypto_sign_verify_detached(sig, claims_bytes, sizeof(hk_drm_claims),
                                    ctx->pubkey) != 0) {
        return HK_DRM_LICENCE_INVALID;
    }

    // 2. Decode the (now-trusted) fixed claims and check magic/version.
    hk_drm_claims claims;
    std::memcpy(&claims, claims_bytes, sizeof(claims));
    if (claims.magic != HK_DRM_CLAIMS_MAGIC || claims.version != HK_DRM_CLAIMS_VERSION) {
        return HK_DRM_LICENCE_INVALID;
    }

    // 3. Hardware binding: the claim's hardware_id must match this machine.
    //    Bounded compare; the claim field is NUL-padded to HK_DRM_HWID_MAX.
    char claim_hw[HK_DRM_HWID_MAX];
    std::memcpy(claim_hw, claims.hardware_id, HK_DRM_HWID_MAX);
    claim_hw[HK_DRM_HWID_MAX - 1] = '\0';
    if (std::strncmp(claim_hw, ctx->hardware_id, HK_DRM_HWID_MAX) != 0) {
        return HK_DRM_HARDWARE_FAIL;
    }

    // 4. Expiry.
    const uint64_t now = static_cast<uint64_t>(std::time(nullptr));
    if (now >= claims.expires_unix_s) {
        return HK_DRM_LICENCE_INVALID;
    }

    return HK_DRM_OK;
}
