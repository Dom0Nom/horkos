/*
 * attestation/backends/console/nintendo/AttestationNintendo.cpp
 * Role: Nintendo Switch attestation backend stub.
 *       Maps to: nn::account / nn::nifm identity attestation surface
 *       (documented at developer.nintendo.com — requires NDA dev account).
 *       Implementation requires NDA / dev-account access and is intentionally
 *       absent from this repository.
 * Target platforms: Nintendo Switch (NintendoSDK) — NDA-gated.
 * Implements: attestation/Attestation.h
 */

#include "../../Attestation.h"

namespace hk {

namespace {

class AttestationNintendo final : public Attestation {
public:
    AttestationStatus quote(AttestationQuote& /*quote_out*/) override {
        return AttestationStatus::NotImplemented;
    }
};

} // namespace

std::unique_ptr<Attestation> Attestation::create() {
    return std::make_unique<AttestationNintendo>();
}

} // namespace hk
