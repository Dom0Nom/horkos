/*
 * attestation/backends/linux/AttestationTpm2Linux.cpp
 * Role: Linux TPM 2.0 attestation backend (tpm2-tss / ESAPI). Produces a real
 *       hardware quote: creates an ECDSA-P256 restricted signing key (the AK)
 *       as an endorsement-hierarchy primary, runs TPM2_Quote over a SHA-256 PCR
 *       selection with the server nonce as qualifyingData, and marshals the
 *       TPMS_ATTEST + signature + AK public into AttestationQuote in the shape
 *       server/attestation-verify consumes (attest bytes, raw r||s ECDSA sig,
 *       SEC1 AK public).
 * Target platforms: Linux only. Links libtss2-esys. Runs against a real TPM
 *       (/dev/tpmrm0) or swtpm via the default/${TPM2TOOLS_TCTI} TCTI; no TPM
 *       present -> HardwareUnavailable.
 * Implements: attestation/Attestation.h
 *
 * PoC scope (handoff §8): the AK is a freshly-created primary per process, not
 * an enrolment-persisted EK->AK pair, and there is no EK certificate chain to a
 * vendor root — those are the documented limits. The ESAPI quote sequence,
 * nonce binding, and marshalling are real.
 */

#include "../../Attestation.h"

#include <tss2/tss2_esys.h>

#include <cstring>

namespace hk {

namespace {

/* P-256 field element size. */
constexpr size_t kP256 = 32;

/* RAII for the Esys context so every early return tears down the TPM session. */
struct EsysCtx {
    ESYS_CONTEXT* ctx = nullptr;
    ~EsysCtx() {
        if (ctx) Esys_Finalize(&ctx);
    }
};

/* Restricted ECDSA-P256 signing-key template for the AK (endorsement primary). */
TPM2B_PUBLIC ak_template() {
    TPM2B_PUBLIC t = {};
    t.publicArea.type = TPM2_ALG_ECC;
    t.publicArea.nameAlg = TPM2_ALG_SHA256;
    t.publicArea.objectAttributes =
        TPMA_OBJECT_FIXEDTPM | TPMA_OBJECT_FIXEDPARENT |
        TPMA_OBJECT_SENSITIVEDATAORIGIN | TPMA_OBJECT_USERWITHAUTH |
        TPMA_OBJECT_RESTRICTED | TPMA_OBJECT_SIGN_ENCRYPT;
    t.publicArea.parameters.eccDetail.symmetric.algorithm = TPM2_ALG_NULL;
    t.publicArea.parameters.eccDetail.scheme.scheme = TPM2_ALG_ECDSA;
    t.publicArea.parameters.eccDetail.scheme.details.ecdsa.hashAlg = TPM2_ALG_SHA256;
    t.publicArea.parameters.eccDetail.curveID = TPM2_ECC_NIST_P256;
    t.publicArea.parameters.eccDetail.kdf.scheme = TPM2_ALG_NULL;
    return t;
}

class AttestationTpm2Linux final : public Attestation {
public:
    AttestationStatus quote(const uint8_t* nonce, size_t nonce_len,
                            AttestationQuote& quote_out) override {
        if (!nonce || nonce_len < 8 || nonce_len > sizeof(TPM2B_DATA{}.buffer)) {
            return AttestationStatus::PolicyRejected;
        }

        EsysCtx e;
        if (Esys_Initialize(&e.ctx, nullptr, nullptr) != TSS2_RC_SUCCESS || !e.ctx) {
            return AttestationStatus::HardwareUnavailable;
        }

        // --- Create the AK as an endorsement-hierarchy primary --------------
        TPM2B_SENSITIVE_CREATE in_sensitive = {};
        TPM2B_PUBLIC in_public = ak_template();
        TPM2B_DATA outside_info = {};
        TPML_PCR_SELECTION creation_pcr = {};

        ESYS_TR ak = ESYS_TR_NONE;
        TPM2B_PUBLIC* out_public = nullptr;
        if (Esys_CreatePrimary(e.ctx, ESYS_TR_RH_ENDORSEMENT,
                               ESYS_TR_PASSWORD, ESYS_TR_NONE, ESYS_TR_NONE,
                               &in_sensitive, &in_public, &outside_info,
                               &creation_pcr, &ak, &out_public,
                               nullptr, nullptr, nullptr) != TSS2_RC_SUCCESS) {
            return AttestationStatus::HardwareUnavailable;
        }

        // --- Quote over a SHA-256 PCR selection, nonce as qualifyingData ----
        TPM2B_DATA qualifying = {};
        qualifying.size = static_cast<UINT16>(nonce_len);
        std::memcpy(qualifying.buffer, nonce, nonce_len);

        TPMT_SIG_SCHEME scheme = {};
        scheme.scheme = TPM2_ALG_ECDSA;
        scheme.details.ecdsa.hashAlg = TPM2_ALG_SHA256;

        TPML_PCR_SELECTION pcr_sel = {};
        pcr_sel.count = 1;
        pcr_sel.pcrSelections[0].hash = TPM2_ALG_SHA256;
        pcr_sel.pcrSelections[0].sizeofSelect = 3;
        pcr_sel.pcrSelections[0].pcrSelect[0] = 0xFF; // PCR 0-7
        pcr_sel.pcrSelections[0].pcrSelect[1] = 0x00;
        pcr_sel.pcrSelections[0].pcrSelect[2] = 0x00;

        TPM2B_ATTEST* quoted = nullptr;
        TPMT_SIGNATURE* signature = nullptr;
        TSS2_RC rc = Esys_Quote(e.ctx, ak,
                                ESYS_TR_PASSWORD, ESYS_TR_NONE, ESYS_TR_NONE,
                                &qualifying, &scheme, &pcr_sel,
                                &quoted, &signature);
        if (rc != TSS2_RC_SUCCESS || !quoted || !signature) {
            Esys_FlushContext(e.ctx, ak);
            Esys_Free(out_public);
            return AttestationStatus::HardwareUnavailable;
        }

        AttestationStatus status = marshal(*quoted, *signature, *out_public, quote_out);

        Esys_Free(quoted);
        Esys_Free(signature);
        Esys_Free(out_public);
        Esys_FlushContext(e.ctx, ak);
        return status;
    }

private:
    /* Copy the attest bytes, raw r||s ECDSA signature, and SEC1 AK public into
     * the output, bounded by the quote field sizes. */
    static AttestationStatus marshal(const TPM2B_ATTEST& quoted,
                                     const TPMT_SIGNATURE& sig,
                                     const TPM2B_PUBLIC& ak_pub,
                                     AttestationQuote& out) {
        if (quoted.size > sizeof(out.attest)) {
            return AttestationStatus::PolicyRejected;
        }
        std::memcpy(out.attest, quoted.attestationData, quoted.size);
        out.attest_len = quoted.size;

        if (sig.sigAlg != TPM2_ALG_ECDSA) {
            return AttestationStatus::PolicyRejected;
        }
        const TPM2B_ECC_PARAMETER& r = sig.signature.ecdsa.signatureR;
        const TPM2B_ECC_PARAMETER& s = sig.signature.ecdsa.signatureS;
        if (r.size > kP256 || s.size > kP256) {
            return AttestationStatus::PolicyRejected;
        }
        // Left-pad each to 32 bytes -> fixed 64-byte r||s the verifier accepts.
        std::memset(out.signature, 0, 64);
        std::memcpy(out.signature + (kP256 - r.size), r.buffer, r.size);
        std::memcpy(out.signature + kP256 + (kP256 - s.size), s.buffer, s.size);
        out.signature_len = 64;

        // SEC1 uncompressed AK public: 0x04 || X || Y.
        const TPMS_ECC_POINT& pt = ak_pub.publicArea.unique.ecc;
        if (pt.x.size > kP256 || pt.y.size > kP256) {
            return AttestationStatus::PolicyRejected;
        }
        out.ak_pub[0] = 0x04;
        std::memcpy(out.ak_pub + 1 + (kP256 - pt.x.size), pt.x.buffer, pt.x.size);
        std::memcpy(out.ak_pub + 1 + kP256 + (kP256 - pt.y.size), pt.y.buffer, pt.y.size);
        out.ak_pub_len = 1 + 2 * kP256;

        return AttestationStatus::Ok;
    }
};

} // namespace

std::unique_ptr<Attestation> Attestation::create() {
    return std::make_unique<AttestationTpm2Linux>();
}

} // namespace hk
