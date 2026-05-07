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

    /* Request a hardware-backed quote. On stub backends this returns
       AttestationStatus::NotImplemented and leaves quote untouched. */
    virtual AttestationStatus quote(AttestationQuote& quote_out) = 0;

    /* Factory: selects the backend for the current platform.
       Returns a stub on platforms without a real TPM/SE backend yet. */
    static std::unique_ptr<Attestation> create();

protected:
    Attestation() = default;
};

} // namespace hk
