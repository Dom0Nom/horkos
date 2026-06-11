/*
 * attestation/backends/win/AttestationTpm2Win.cpp
 * Role: Windows TPM 2.0 attestation backend. Thin factory over the shared
 *       tpm2-tss ESAPI quote routine (backends/common/Tpm2EsapiQuote.cpp) — the
 *       Esys_* sequence is identical to Linux; on Windows libtss2 reaches the
 *       platform TPM through the tcti-tbs TCTI (Windows TBS), selected by
 *       Esys_Initialize(NULL) inside the library.
 * Target platforms: Windows only. Links tpm2-tss-for-windows (tss2-esys).
 * Implements: attestation/Attestation.h
 *
 * UNVERIFIED: the shared ESAPI logic is verified on Linux against swtpm, but
 * this Windows wiring (tcti-tbs + the tpm2-tss-for-windows import libs) has
 * never been built on a Windows box — expect a link/TCTI pass there. PoC limits
 * match the Linux backend (per-process AK, no EK cert chain; handoff §8).
 */

#include "../../Attestation.h"
#include "../common/Tpm2EsapiQuote.h"

namespace hk {

namespace {

class AttestationTpm2Win final : public Attestation {
public:
    AttestationStatus quote(const uint8_t* nonce, size_t nonce_len,
                            AttestationQuote& quote_out) override {
        return detail::tpm2_esapi_quote(nonce, nonce_len, quote_out);
    }
};

} // namespace

std::unique_ptr<Attestation> Attestation::create() {
    return std::make_unique<AttestationTpm2Win>();
}

} // namespace hk
