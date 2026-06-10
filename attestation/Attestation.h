/*
 * attestation/Attestation.h
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

struct AttestationQuote {
    uint8_t  data[512];
    uint32_t length;

    AttestationQuote() : length(0) {
        memset(data, 0, sizeof(data));
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
