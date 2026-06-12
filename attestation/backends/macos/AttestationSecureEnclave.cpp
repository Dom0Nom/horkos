/*
 * Role: macOS Secure Enclave attestation backend (Security framework). Creates
 *       an ECDSA-P256 key in the Secure Enclave, signs the server nonce with it
 *       (ECDSASignatureMessageX962SHA256), and marshals the signed payload +
 *       signature + SE public key into AttestationQuote. The server verifies it
 *       with attestation_verify::verify_se_signature.
 * Target platforms: macOS only. Links Security + CoreFoundation.
 * Implements: attestation/Attestation.h
 *
 * PoC scope (handoff §8): the SE key is created per-quote and is non-permanent
 * (a real enrolment creates it ONCE and persists the handle). A locally-verified
 * SE signature proves possession of an SE-resident key but NOT remote-attestable
 * device identity — that needs Apple's DCAppAttest entitlement, which a PoC does
 * not provision. If the Secure Enclave is unavailable (no SE hardware, or the
 * process lacks the keychain entitlement), this returns HardwareUnavailable
 * rather than fabricating a software signature.
 */

#include "../../Attestation.h"

#include <CoreFoundation/CoreFoundation.h>
#include <Security/Security.h>

#include <cstring>

namespace hk {

namespace {

template <typename T>
void release(T ref) {
    if (ref) CFRelease(ref);
}

class AttestationSecureEnclave final : public Attestation {
public:
    AttestationStatus quote(const uint8_t* nonce, size_t nonce_len,
                            AttestationQuote& quote_out) override {
        if (!nonce || nonce_len < 8 || nonce_len > sizeof(quote_out.attest)) {
            return AttestationStatus::PolicyRejected;
        }

        AttestationStatus status = AttestationStatus::HardwareUnavailable;

        CFErrorRef error = nullptr;
        SecAccessControlRef access = SecAccessControlCreateWithFlags(
            kCFAllocatorDefault, kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly,
            kSecAccessControlPrivateKeyUsage, &error);
        if (!access) {
            release(error);
            return AttestationStatus::HardwareUnavailable;
        }

        const void* priv_keys[] = {kSecAttrIsPermanent, kSecAttrAccessControl};
        const void* priv_vals[] = {kCFBooleanFalse, access};
        CFDictionaryRef priv_attrs = CFDictionaryCreate(
            kCFAllocatorDefault, priv_keys, priv_vals, 2,
            &kCFTypeDictionaryKeyCallBacks, &kCFTypeDictionaryValueCallBacks);

        int bits = 256;
        CFNumberRef bits_ref = CFNumberCreate(kCFAllocatorDefault, kCFNumberIntType, &bits);
        const void* keys[] = {kSecAttrKeyType, kSecAttrKeySizeInBits,
                              kSecAttrTokenID, kSecPrivateKeyAttrs};
        const void* vals[] = {kSecAttrKeyTypeECSECPrimeRandom, bits_ref,
                              kSecAttrTokenIDSecureEnclave, priv_attrs};
        CFDictionaryRef attrs = CFDictionaryCreate(
            kCFAllocatorDefault, keys, vals, 4,
            &kCFTypeDictionaryKeyCallBacks, &kCFTypeDictionaryValueCallBacks);

        SecKeyRef priv = SecKeyCreateRandomKey(attrs, &error);
        if (priv) {
            status = sign_and_marshal(priv, nonce, nonce_len, quote_out);
            CFRelease(priv);
        } else {
            // SE unavailable / not entitled: fail closed, never fabricate.
            release(error);
        }

        release(attrs);
        release(bits_ref);
        release(priv_attrs);
        release(access);
        return status;
    }

private:
    static AttestationStatus sign_and_marshal(SecKeyRef priv,
                                              const uint8_t* nonce, size_t nonce_len,
                                              AttestationQuote& out) {
        CFErrorRef error = nullptr;

        CFDataRef payload = CFDataCreate(kCFAllocatorDefault, nonce,
                                         static_cast<CFIndex>(nonce_len));
        CFDataRef sig = SecKeyCreateSignature(
            priv, kSecKeyAlgorithmECDSASignatureMessageX962SHA256, payload, &error);
        if (!sig) {
            release(error);
            release(payload);
            return AttestationStatus::HardwareUnavailable;
        }

        SecKeyRef pub = SecKeyCopyPublicKey(priv);
        CFDataRef pub_data = pub ? SecKeyCopyExternalRepresentation(pub, &error) : nullptr;
        AttestationStatus status = AttestationStatus::HardwareUnavailable;

        if (pub_data &&
            CFDataGetLength(sig) <= static_cast<CFIndex>(sizeof(out.signature)) &&
            CFDataGetLength(pub_data) <= static_cast<CFIndex>(sizeof(out.ak_pub))) {
            // attest = the signed nonce payload.
            std::memcpy(out.attest, nonce, nonce_len);
            out.attest_len = static_cast<uint32_t>(nonce_len);
            // signature = DER ECDSA.
            std::memcpy(out.signature, CFDataGetBytePtr(sig),
                        static_cast<size_t>(CFDataGetLength(sig)));
            out.signature_len = static_cast<uint32_t>(CFDataGetLength(sig));
            // ak_pub = SEC1 public key.
            std::memcpy(out.ak_pub, CFDataGetBytePtr(pub_data),
                        static_cast<size_t>(CFDataGetLength(pub_data)));
            out.ak_pub_len = static_cast<uint32_t>(CFDataGetLength(pub_data));
            status = AttestationStatus::Ok;
        } else {
            release(error);
        }

        release(pub_data);
        release(pub);
        release(sig);
        release(payload);
        return status;
    }
};

} // namespace

std::unique_ptr<Attestation> Attestation::create() {
    return std::make_unique<AttestationSecureEnclave>();
}

} // namespace hk
