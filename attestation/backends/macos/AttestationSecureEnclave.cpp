/*
 * attestation/backends/macos/AttestationSecureEnclave.cpp
 * Role: macOS Secure Enclave attestation backend stub.
 *       Phase 4+ backend: will use CryptoKit / Security framework
 *       SecKeyCreateRandomKey with kSecAttrTokenIDSecureEnclave to
 *       produce a hardware-backed attestation payload.
 * Target platforms: macOS only.
 * Implements: attestation/Attestation.h
 */

#include "../../Attestation.h"

namespace hk {

namespace {

class AttestationSecureEnclave final : public Attestation {
public:
    AttestationStatus quote(const uint8_t* /*nonce*/, size_t /*nonce_len*/,
                            AttestationQuote& /*quote_out*/) override {
        return AttestationStatus::NotImplemented;
    }
};

} // namespace

std::unique_ptr<Attestation> Attestation::create() {
    return std::make_unique<AttestationSecureEnclave>();
}

} // namespace hk
