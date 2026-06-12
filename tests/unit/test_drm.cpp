/*
 * Role: Host unit test for the DRM licence verifier (drm/src/drm.cpp). Signs
 *       licence claims with a libsodium-generated key, then drives
 *       drm_configure + drm_validate to prove: a valid licence passes; a wrong
 *       key, tampered claim, wrong-hardware binding, expired licence, malformed
 *       token, and unconfigured context all fail closed with the right code.
 * Target platforms: host (CI). Links hk_drm + libsodium.
 */

#include <horkos/drm.h>

#include <sodium.h>
#include <gtest/gtest.h>

#include <cstring>
#include <ctime>
#include <vector>

namespace {

struct Keypair {
    uint8_t pk[HK_DRM_PUBKEY_BYTES];
    uint8_t sk[crypto_sign_SECRETKEYBYTES];
};

Keypair make_key() {
    Keypair k{};
    crypto_sign_keypair(k.pk, k.sk);
    return k;
}

hk_drm_claims make_claims(const char* hw, const char* product, uint64_t expires) {
    hk_drm_claims c{};
    c.magic = HK_DRM_CLAIMS_MAGIC;
    c.version = HK_DRM_CLAIMS_VERSION;
    c.expires_unix_s = expires;
    std::strncpy(c.hardware_id, hw, HK_DRM_HWID_MAX - 1);
    std::strncpy(c.product_id, product, HK_DRM_PRODUCT_MAX - 1);
    return c;
}

// token = claims || detached-sig(claims, sk)
std::vector<uint8_t> sign_token(const hk_drm_claims& c, const uint8_t* sk) {
    std::vector<uint8_t> token(sizeof(hk_drm_claims) + HK_DRM_SIG_BYTES);
    std::memcpy(token.data(), &c, sizeof(c));
    crypto_sign_detached(token.data() + sizeof(c), nullptr,
                         token.data(), sizeof(c), sk);
    return token;
}

uint64_t future() { return static_cast<uint64_t>(std::time(nullptr)) + 86400; }

int validate(const uint8_t* pk, const std::vector<uint8_t>& token, const char* local_hw) {
    drm_context_t* ctx = drm_create_context();
    EXPECT_NE(ctx, nullptr);
    int cfg = drm_configure(ctx, pk, token.data(), token.size(), local_hw);
    EXPECT_EQ(cfg, HK_DRM_OK);
    int rc = drm_validate(ctx);
    drm_destroy_context(ctx);
    return rc;
}

} // namespace

TEST(Drm, ValidLicencePasses) {
    ASSERT_GE(sodium_init(), 0);
    Keypair k = make_key();
    auto token = sign_token(make_claims("HW-1", "horkos", future()), k.sk);
    EXPECT_EQ(validate(k.pk, token, "HW-1"), HK_DRM_OK);
}

TEST(Drm, WrongKeyFails) {
    Keypair signer = make_key();
    Keypair pinned = make_key();
    auto token = sign_token(make_claims("HW-1", "horkos", future()), signer.sk);
    EXPECT_EQ(validate(pinned.pk, token, "HW-1"), HK_DRM_LICENCE_INVALID);
}

TEST(Drm, TamperedClaimFails) {
    Keypair k = make_key();
    auto token = sign_token(make_claims("HW-1", "horkos", future()), k.sk);
    token[16] ^= 0xFF; // flip a claims byte (inside the signed region)
    EXPECT_EQ(validate(k.pk, token, "HW-1"), HK_DRM_LICENCE_INVALID);
}

TEST(Drm, WrongHardwareFails) {
    Keypair k = make_key();
    auto token = sign_token(make_claims("HW-1", "horkos", future()), k.sk);
    EXPECT_EQ(validate(k.pk, token, "HW-OTHER"), HK_DRM_HARDWARE_FAIL);
}

TEST(Drm, ExpiredLicenceFails) {
    Keypair k = make_key();
    uint64_t past = static_cast<uint64_t>(std::time(nullptr)) - 10;
    auto token = sign_token(make_claims("HW-1", "horkos", past), k.sk);
    EXPECT_EQ(validate(k.pk, token, "HW-1"), HK_DRM_LICENCE_INVALID);
}

TEST(Drm, BadMagicFails) {
    Keypair k = make_key();
    hk_drm_claims c = make_claims("HW-1", "horkos", future());
    c.magic = 0xBADBAD00u;
    auto token = sign_token(c, k.sk); // correctly signed, but bad magic
    EXPECT_EQ(validate(k.pk, token, "HW-1"), HK_DRM_LICENCE_INVALID);
}

TEST(Drm, WrongTokenLengthRejectedAtConfigure) {
    Keypair k = make_key();
    auto token = sign_token(make_claims("HW-1", "horkos", future()), k.sk);
    token.pop_back(); // truncate
    drm_context_t* ctx = drm_create_context();
    EXPECT_EQ(drm_configure(ctx, k.pk, token.data(), token.size(), "HW-1"),
              HK_DRM_LICENCE_INVALID);
    drm_destroy_context(ctx);
}

TEST(Drm, UnconfiguredContextFailsClosed) {
    drm_context_t* ctx = drm_create_context();
    EXPECT_EQ(drm_validate(ctx), HK_DRM_LICENCE_INVALID);
    drm_destroy_context(ctx);
}

TEST(Drm, NullContextIsInvalidCtx) {
    EXPECT_EQ(drm_validate(nullptr), HK_DRM_INVALID_CTX);
}
