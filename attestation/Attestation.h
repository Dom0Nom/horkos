/*
 * Role: Stable attestation interface. Backends change; this header does not
 *       (Locked Decision #6 and guardrail #10).
 * Target platforms: Windows, Linux, macOS, console stubs.
 * Interface: this IS the attestation interface; backends implement Attestation.
 */

#pragma once

#include <cstdint>
#include <cstring>
#include <memory>

namespace hk {

enum class AttestationStatus : uint32_t {
    Ok                 = 0,
    NotImplemented     = 1,
    HardwareUnavailable = 2,
    PolicyRejected     = 3,
};

/* A hardware-backed quote, in the three parts the server verifier needs (see
 * server/attestation-verify). `data[512]` (the old single opaque buffer) was
 * too small to hold the TPMS_ATTEST + TPMT_SIGNATURE + AK public together
 * (handoff §8); they are carried separately here so the verifier does not
 * re-parse a packed blob.
 *
 *   attest   : the raw TPMS_ATTEST bytes the TPM signed (TPM2_Quote output).
 *   signature: the AK signature over `attest` (DER ECDSA-P256 on the PoC path).
 *   ak_pub   : the AK public key the verifier pins (SEC1 for ECC).
 *
 * On macOS (Secure Enclave) `attest` carries the signed payload (nonce ||
 * context), `signature` the SE signature, `ak_pub` the SE public key. */
struct AttestationQuote {
    uint8_t  attest[640];
    uint32_t attest_len;
    uint8_t  signature[256];
    uint32_t signature_len;
    uint8_t  ak_pub[256];
    uint32_t ak_pub_len;

    AttestationQuote()
        : attest_len(0), signature_len(0), ak_pub_len(0) {
        memset(attest, 0, sizeof(attest));
        memset(signature, 0, sizeof(signature));
        memset(ak_pub, 0, sizeof(ak_pub));
    }
};

class Attestation {
public:
    virtual ~Attestation() = default;

    Attestation(const Attestation&) = delete;
    Attestation& operator=(const Attestation&) = delete;

    /* Request a hardware-backed quote bound to a server-issued nonce.
     *
     * nonce / nonce_len: a freshness challenge issued by the server for this
     * request; must be bound into the quote so replayed quotes are rejected by
     * the verifier. On TPM backends nonce is passed as qualifyingData to
     * TPM2_Quote; on Secure Enclave backends it is included in the signed
     * payload. Callers must supply a non-null nonce of at least 8 bytes.
     *
     * On stub backends this returns AttestationStatus::NotImplemented and
     * leaves quote_out untouched. */
    virtual AttestationStatus quote(const uint8_t* nonce, size_t nonce_len,
                                    AttestationQuote& quote_out) = 0;

    /* Factory: selects the backend for the current platform.
       Returns a stub on platforms without a real TPM/SE backend yet. */
    static std::unique_ptr<Attestation> create();

protected:
    Attestation() = default;
};

} // namespace hk
