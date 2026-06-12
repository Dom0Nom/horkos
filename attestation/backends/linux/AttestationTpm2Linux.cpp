/*
 * Role: Linux TPM 2.0 attestation backend. Thin factory over the shared
 *       tpm2-tss ESAPI quote routine (backends/common/Tpm2EsapiQuote.cpp); on
 *       Linux libtss2 reaches the TPM through the default device TCTI
 *       (/dev/tpmrm0) or swtpm via the configured TCTI.
 * Target platforms: Linux only. Links libtss2-esys.
 * Implements: attestation/Attestation.h
 *
 * Verified end-to-end against swtpm in Docker (the shared routine produced a
 * real quote that the server verifier accepts). PoC limits (handoff §8):
 * per-process AK, no EK certificate chain to a vendor root.
 */

#include "../../Attestation.h"
#include "../common/Tpm2EsapiQuote.h"

namespace hk {

namespace {

class AttestationTpm2Linux final : public Attestation {
public:
    AttestationStatus quote(const uint8_t* nonce, size_t nonce_len,
                            AttestationQuote& quote_out) override {
        return detail::tpm2_esapi_quote(nonce, nonce_len, quote_out);
    }
};

} // namespace

std::unique_ptr<Attestation> Attestation::create() {
    return std::make_unique<AttestationTpm2Linux>();
}

} // namespace hk
