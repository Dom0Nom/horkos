/*
 * tests/unit/test_attestation_create.cpp
 * Role: Verifies that Attestation::create() returns a non-null backend and
 *       that quote() returns AttestationStatus::NotImplemented on Phase 1 stubs.
 * Target platforms: all.
 */

#include <gtest/gtest.h>
#include <Attestation.h>

TEST(AttestationCreate, ReturnsNonNull) {
    auto attestation = hk::Attestation::create();
    ASSERT_NE(attestation, nullptr);
}

TEST(AttestationCreate, QuoteReturnsNotImplemented) {
    auto attestation = hk::Attestation::create();
    ASSERT_NE(attestation, nullptr);

    const uint8_t nonce[16] = {0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
                                0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10};
    hk::AttestationQuote quote{};
    const auto status = attestation->quote(nonce, sizeof(nonce), quote);
    EXPECT_EQ(status, hk::AttestationStatus::NotImplemented);
}
