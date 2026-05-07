/*
 * attestation/backends/linux/AttestationTpm2Linux.cpp
 * Role: Linux TPM 2.0 attestation backend stub.
 *       Phase 4+ backend: will use tpm2-tss (libtss2-esys / libtss2-rc) to
 *       produce a real TPM quote via Esys_Quote.
 * Target platforms: Linux only.
 * Implements: attestation/Attestation.h
 */

#include "../../Attestation.h"

namespace hk {

namespace {

class AttestationTpm2Linux final : public Attestation {
public:
    AttestationStatus quote(AttestationQuote& /*quote_out*/) override {
        return AttestationStatus::NotImplemented;
    }
};

} // namespace

std::unique_ptr<Attestation> Attestation::create() {
    return std::make_unique<AttestationTpm2Linux>();
}

} // namespace hk
