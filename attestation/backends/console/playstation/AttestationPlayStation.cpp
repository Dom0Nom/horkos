/*
 * Role: PlayStation attestation backend stub.
 *       Maps to: sceNpTrophy / SCE attestation surface for platform identity
 *       (documented in PS5/PS4 SDK — requires NDA dev account).
 *       Implementation requires NDA / dev-account access and is intentionally
 *       absent from this repository.
 * Target platforms: PlayStation 4/5 — NDA-gated.
 * Implements: attestation/Attestation.h
 */

#include "../../Attestation.h"

namespace hk {

namespace {

class AttestationPlayStation final : public Attestation {
public:
    AttestationStatus quote(const uint8_t* /*nonce*/, size_t /*nonce_len*/,
                            AttestationQuote& /*quote_out*/) override {
        return AttestationStatus::NotImplemented;
    }
};

} // namespace

std::unique_ptr<Attestation> Attestation::create() {
    return std::make_unique<AttestationPlayStation>();
}

} // namespace hk
