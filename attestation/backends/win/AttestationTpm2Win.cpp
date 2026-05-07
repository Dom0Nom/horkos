/*
 * attestation/backends/win/AttestationTpm2Win.cpp
 * Role: Windows TPM 2.0 attestation backend stub.
 *       Phase 4+ backend: will use tpm2-tss (Trusted Platform Module 2.0
 *       TSS library) to produce a real TPM quote via TPM2_Quote command.
 * Target platforms: Windows only.
 * Implements: attestation/Attestation.h
 */

#include "../../Attestation.h"

namespace hk {

namespace {

class AttestationTpm2Win final : public Attestation {
public:
    AttestationStatus quote(AttestationQuote& /*quote_out*/) override {
        return AttestationStatus::NotImplemented;
    }
};

} // namespace

std::unique_ptr<Attestation> Attestation::create() {
    return std::make_unique<AttestationTpm2Win>();
}

} // namespace hk
