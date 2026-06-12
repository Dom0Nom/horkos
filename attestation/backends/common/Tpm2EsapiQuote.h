/*
 * Role: Platform-neutral tpm2-tss ESAPI quote routine shared by the Linux and
 *       Windows TPM backends. The Esys_* API is identical on both; only the
 *       default TCTI differs (device /dev/tpmrm0 on Linux, tcti-tbs on Windows)
 *       and that is selected inside libtss2 by Esys_Initialize(NULL), not here.
 * Target platforms: Linux + Windows (any libtss2-esys host).
 * Interface: produces an AttestationQuote from a server nonce; the per-platform
 *       backend is a thin factory wrapping this.
 */

#pragma once

#include "../../Attestation.h"

#include <cstddef>
#include <cstdint>

namespace hk {
namespace detail {

/* Create an ECDSA-P256 restricted-signing AK as an endorsement-hierarchy
 * primary, run TPM2_Quote over a SHA-256 PCR selection with `nonce` as
 * qualifyingData, and marshal the TPMS_ATTEST + raw r||s ECDSA signature + SEC1
 * AK public into `out`. Returns Ok on success; HardwareUnavailable if no TPM /
 * the ESAPI sequence fails; PolicyRejected on a bad nonce or oversized output. */
AttestationStatus tpm2_esapi_quote(const uint8_t* nonce, size_t nonce_len,
                                   AttestationQuote& out);

} // namespace detail
} // namespace hk
