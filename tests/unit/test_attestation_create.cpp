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

    hk::AttestationQuote quote{};
    const auto status = attestation->quote(quote);
    EXPECT_EQ(status, hk::AttestationStatus::NotImplemented);
}
