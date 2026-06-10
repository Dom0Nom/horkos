/*
 * attestation/backends/console/gdk/AttestationGdk.cpp
 * Role: Xbox / GDK attestation backend stub.
 *       Maps to: XGameRuntime attestation surface, specifically
 *       XUserGetTokenAndSignatureAsync (Xbox User Token and Signature API,
 *       documented at learn.microsoft.com/en-us/gaming/gdk).
 *       Implementation requires NDA / dev-account access and is intentionally
 *       absent from this repository.
 * Target platforms: Xbox (GDK) — NDA-gated.
 * Implements: attestation/Attestation.h
 */

#include "../../Attestation.h"

namespace hk {

namespace {

class AttestationGdk final : public Attestation {
public:
    AttestationStatus quote(const uint8_t* /*nonce*/, size_t /*nonce_len*/,
                            AttestationQuote& /*quote_out*/) override {
        return AttestationStatus::NotImplemented;
    }
};

} // namespace

std::unique_ptr<Attestation> Attestation::create() {
    return std::make_unique<AttestationGdk>();
}

} // namespace hk
