//! Role: end-to-end cross-component proof for the macOS path. These bytes are a
//! REAL Secure Enclave signature produced by the macOS backend
//! (`attestation/backends/macos/AttestationSecureEnclave.cpp`) running on an
//! Apple Silicon Mac — SecKeyCreateRandomKey(SecureEnclave) +
//! SecKeyCreateSignature, not a synthesized fixture. The server verifier
//! accepting them proves the SE backend and `verify_se_signature` agree on the
//! wire (DER ECDSA-P256 over the nonce payload, SEC1 SE public key).

use attestation_verify::{verify_se_signature, AttestError};

const PAYLOAD: &str = "090807060504030201000a0b0c0d0e0f"; // the signed nonce
const SIG: &str = "3045022022253050c1c5d33152eaf4f9cd5e2505b5212a5ba22c6dd3339c87c227f156a1022100be3f3fc0f2e36a4ca1ee291950542bbbce994fac42643c1ff2e6c9f0e89390a7";
const PUB: &str = "04e66b4811b34cdb4120f4afd5574e73ceec3682602ad0fa50625ddba4e88f27f6747d0002fa54164e9cac62c9a76d39e978c33e5c6b1fd2fc083c6edb0095d661";

#[test]
fn real_secure_enclave_signature_verifies() {
    let payload = hex::decode(PAYLOAD).unwrap();
    let sig = hex::decode(SIG).unwrap();
    let pubk = hex::decode(PUB).unwrap();
    verify_se_signature(&payload, &sig, &pubk).expect("real SE signature verifies");
}

#[test]
fn se_signature_rejects_tampered_payload() {
    let mut payload = hex::decode(PAYLOAD).unwrap();
    let sig = hex::decode(SIG).unwrap();
    let pubk = hex::decode(PUB).unwrap();
    payload[0] ^= 0xFF; // a different nonce was never signed
    assert_eq!(
        verify_se_signature(&payload, &sig, &pubk),
        Err(AttestError::SignatureInvalid)
    );
}

#[test]
fn se_signature_rejects_wrong_key() {
    let payload = hex::decode(PAYLOAD).unwrap();
    let sig = hex::decode(SIG).unwrap();
    assert_eq!(
        verify_se_signature(&payload, &sig, &[0x04, 0x00]),
        Err(AttestError::BadAkKey)
    );
}
