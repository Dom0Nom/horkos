//! src/lib.rs
//!
//! Role: server-side TPM 2.0 attestation verifier. Parses the `TPMS_ATTEST`
//! structure a client's TPM produces via `TPM2_Quote` (emitted by the
//! `tpm2-tss` Linux/Windows backends behind `Attestation.h`), binds it to the
//! server-issued nonce, and verifies the Attestation Key (AK) signature.
//!
//! What is verified (the honest PoC subset — matches handoff §8):
//! `magic == TPM_GENERATED_VALUE` (the structure was produced by a TPM, not
//! forged in software — a TPM will not sign a TPMS_ATTEST with this magic over
//! attacker-chosen data); `type == TPM_ST_ATTEST_QUOTE`; `extraData == nonce`
//! (freshness / anti-replay — the server's challenge is bound into the signed
//! structure); and the AK signature over the raw attest bytes verifies against
//! the pinned AK public key (ECDSA-P256, a common TPM AK type). The PCR digest
//! and reset/restart counters are returned for the caller's policy layer.
//!
//! NOT verified here (documented PoC limits, handoff §8): the EK certificate
//! chain to a TPM vendor root (no manufacturer roots in a PoC), and the AK
//! attribute attestation (restricted/fixedTPM) which happens at enrolment.
//!
//! Target platforms: server.
//!
//! Guardrails: #8 — `thiserror` error type; no `unwrap()` outside tests; total
//! over adversarial input (every read is bounds-checked; a short/forged
//! structure returns a typed error, never panics).

use p256::ecdsa::signature::Verifier;
use p256::ecdsa::{Signature, VerifyingKey};
use thiserror::Error;

/// `TPM_GENERATED_VALUE` — present in every TPM-generated attestation structure.
pub const TPM_GENERATED_VALUE: u32 = 0xff54_4347; // 'TCG' with high bit set
/// `TPM_ST_ATTEST_QUOTE`.
pub const TPM_ST_ATTEST_QUOTE: u16 = 0x8018;

#[derive(Debug, Error, PartialEq, Eq)]
pub enum AttestError {
    #[error("attest structure truncated at {0}")]
    Truncated(&'static str),
    #[error("not a TPM-generated structure (bad magic {0:#x})")]
    BadMagic(u32),
    #[error("attestation type {0:#x} is not a quote")]
    NotAQuote(u16),
    #[error("nonce mismatch (replayed or wrong challenge)")]
    NonceMismatch,
    #[error("AK signature invalid")]
    SignatureInvalid,
    #[error("malformed AK public key")]
    BadAkKey,
    #[error("malformed signature")]
    BadSignature,
}

/// The trustworthy facts extracted from a verified quote.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifiedQuote {
    /// The PCR digest the TPM signed (the measured-boot state hash).
    pub pcr_digest: Vec<u8>,
    /// TPM reset count (increments on every TPM reset / cold boot).
    pub reset_count: u32,
    /// TPM restart count (increments on resume/restart).
    pub restart_count: u32,
    /// Firmware version field.
    pub firmware_version: u64,
}

/// A minimal big-endian cursor with bounds checks (the TPM wire is big-endian).
struct Reader<'a> {
    b: &'a [u8],
    pos: usize,
}

impl<'a> Reader<'a> {
    fn new(b: &'a [u8]) -> Self {
        Reader { b, pos: 0 }
    }
    fn take(&mut self, n: usize, what: &'static str) -> Result<&'a [u8], AttestError> {
        let end = self
            .pos
            .checked_add(n)
            .ok_or(AttestError::Truncated(what))?;
        if end > self.b.len() {
            return Err(AttestError::Truncated(what));
        }
        let s = &self.b[self.pos..end];
        self.pos = end;
        Ok(s)
    }
    fn u8(&mut self, what: &'static str) -> Result<u8, AttestError> {
        Ok(self.take(1, what)?[0])
    }
    fn u16(&mut self, what: &'static str) -> Result<u16, AttestError> {
        let s = self.take(2, what)?;
        Ok(u16::from_be_bytes([s[0], s[1]]))
    }
    fn u32(&mut self, what: &'static str) -> Result<u32, AttestError> {
        let s = self.take(4, what)?;
        Ok(u32::from_be_bytes([s[0], s[1], s[2], s[3]]))
    }
    fn u64(&mut self, what: &'static str) -> Result<u64, AttestError> {
        let s = self.take(8, what)?;
        let mut a = [0u8; 8];
        a.copy_from_slice(s);
        Ok(u64::from_be_bytes(a))
    }
    /// A `TPM2B_*` field: u16 length prefix then that many bytes.
    fn sized(&mut self, what: &'static str) -> Result<&'a [u8], AttestError> {
        let n = self.u16(what)? as usize;
        self.take(n, what)
    }
}

/// Parse + structurally validate a `TPMS_ATTEST`, returning the bound nonce
/// (extraData) and the quote facts. Does NOT verify the signature (see
/// `verify_quote`); split out so the parse is independently testable.
pub fn parse_attest(attest: &[u8]) -> Result<(&[u8], VerifiedQuote), AttestError> {
    let mut r = Reader::new(attest);

    let magic = r.u32("magic")?;
    if magic != TPM_GENERATED_VALUE {
        return Err(AttestError::BadMagic(magic));
    }
    let typ = r.u16("type")?;
    if typ != TPM_ST_ATTEST_QUOTE {
        return Err(AttestError::NotAQuote(typ));
    }
    let _qualified_signer = r.sized("qualifiedSigner")?; // TPM2B_NAME
    let extra_data = r.sized("extraData")?; // TPM2B_DATA == the nonce

    // TPMS_CLOCK_INFO: clock(u64) resetCount(u32) restartCount(u32) safe(u8).
    let _clock = r.u64("clock")?;
    let reset_count = r.u32("resetCount")?;
    let restart_count = r.u32("restartCount")?;
    let _safe = r.u8("safe")?;

    let firmware_version = r.u64("firmwareVersion")?;

    // TPMS_QUOTE_INFO.pcrSelect: TPML_PCR_SELECTION.
    let count = r.u32("pcrSelectionCount")?;
    for _ in 0..count {
        let _hash = r.u16("pcrSelHash")?;
        let size_of_select = r.u8("sizeOfSelect")? as usize;
        let _bits = r.take(size_of_select, "pcrSelectBits")?;
    }
    // TPMS_QUOTE_INFO.pcrDigest: TPM2B_DIGEST.
    let pcr_digest = r.sized("pcrDigest")?.to_vec();

    Ok((
        extra_data,
        VerifiedQuote {
            pcr_digest,
            reset_count,
            restart_count,
            firmware_version,
        },
    ))
}

/// Verify a quote end-to-end: structure, nonce binding, and the AK signature
/// over the raw attest bytes.
///
/// - `attest`    : the raw `TPMS_ATTEST` bytes the TPM signed.
/// - `signature` : the AK signature (ECDSA-P256, ASN.1 DER or fixed 64-byte r||s).
/// - `ak_pub_sec1`: the AK public key, SEC1-encoded (0x04 || X || Y, 65 bytes).
/// - `nonce`     : the server-issued challenge that must equal `extraData`.
pub fn verify_quote(
    attest: &[u8],
    signature: &[u8],
    ak_pub_sec1: &[u8],
    nonce: &[u8],
) -> Result<VerifiedQuote, AttestError> {
    let (extra_data, quote) = parse_attest(attest)?;

    // Freshness: the server's nonce must be bound into the signed structure.
    if extra_data != nonce {
        return Err(AttestError::NonceMismatch);
    }

    let vk = VerifyingKey::from_sec1_bytes(ak_pub_sec1).map_err(|_| AttestError::BadAkKey)?;
    // Accept both DER and fixed-width (raw r||s) signature encodings — the TPM
    // backend emits raw r||s; other producers may emit DER.
    let sig = Signature::from_der(signature)
        .or_else(|_| Signature::from_slice(signature))
        .map_err(|_| AttestError::BadSignature)?;
    // TPM ECDSA signatures may carry a non-normalized (high) S; normalize before
    // verify so a valid-but-high-S signature is not spuriously rejected.
    let sig = sig.normalize_s().unwrap_or(sig);

    // The TPM signs the SHA-256 digest of `attest`; `Verifier::verify` applies
    // SHA-256 to its message argument, so verify over `attest` itself (NOT a
    // pre-computed digest, which would double-hash).
    vk.verify(attest, &sig)
        .map_err(|_| AttestError::SignatureInvalid)?;

    Ok(quote)
}

/// Verify a macOS Secure Enclave attestation: an ECDSA-P256 signature over a
/// signed payload (the server nonce, possibly prefixed with enrolment context)
/// against the SE public key. The SE path is NOT a TPM quote — there is no
/// TPMS_ATTEST structure — so freshness is enforced by the caller checking that
/// `payload` contains the issued nonce. Returns `Ok(())` on a valid signature.
///
/// PoC limit (handoff §8): a locally-verifiable SE signature proves possession
/// of an SE-resident key but NOT remote-attestable device identity — that needs
/// Apple's DCAppAttest / App Attest entitlement, which a PoC does not provision.
pub fn verify_se_signature(
    payload: &[u8],
    signature: &[u8],
    se_pub_sec1: &[u8],
) -> Result<(), AttestError> {
    let vk = VerifyingKey::from_sec1_bytes(se_pub_sec1).map_err(|_| AttestError::BadAkKey)?;
    let sig = Signature::from_der(signature)
        .or_else(|_| Signature::from_slice(signature))
        .map_err(|_| AttestError::BadSignature)?;
    let sig = sig.normalize_s().unwrap_or(sig);
    vk.verify(payload, &sig)
        .map_err(|_| AttestError::SignatureInvalid)
}

#[cfg(test)]
mod tests {
    use super::*;
    use p256::ecdsa::signature::Signer;
    use p256::ecdsa::SigningKey;

    fn build_attest(nonce: &[u8], pcr_digest: &[u8]) -> Vec<u8> {
        let mut v = Vec::new();
        v.extend_from_slice(&TPM_GENERATED_VALUE.to_be_bytes());
        v.extend_from_slice(&TPM_ST_ATTEST_QUOTE.to_be_bytes());
        // qualifiedSigner (TPM2B_NAME): a 34-byte name (alg + sha256).
        let name = [0u8; 34];
        v.extend_from_slice(&(name.len() as u16).to_be_bytes());
        v.extend_from_slice(&name);
        // extraData = nonce.
        v.extend_from_slice(&(nonce.len() as u16).to_be_bytes());
        v.extend_from_slice(nonce);
        // clockInfo.
        v.extend_from_slice(&1234u64.to_be_bytes()); // clock
        v.extend_from_slice(&3u32.to_be_bytes()); // resetCount
        v.extend_from_slice(&1u32.to_be_bytes()); // restartCount
        v.push(1); // safe
                   // firmwareVersion.
        v.extend_from_slice(&0xAABB_CCDD_1122_3344u64.to_be_bytes());
        // pcrSelect: 1 selection, sha256, 3 select bytes.
        v.extend_from_slice(&1u32.to_be_bytes());
        v.extend_from_slice(&0x000Bu16.to_be_bytes()); // TPM_ALG_SHA256
        v.push(3);
        v.extend_from_slice(&[0xFF, 0xFF, 0xFF]);
        // pcrDigest.
        v.extend_from_slice(&(pcr_digest.len() as u16).to_be_bytes());
        v.extend_from_slice(pcr_digest);
        v
    }

    fn sign(sk: &SigningKey, attest: &[u8]) -> Vec<u8> {
        // Sign over the message (Signer hashes with SHA-256 once), matching how
        // the TPM signs and how `verify_quote` verifies.
        let sig: p256::ecdsa::Signature = sk.sign(attest);
        sig.to_der().as_bytes().to_vec()
    }

    #[test]
    fn valid_quote_verifies() {
        let sk = SigningKey::from_bytes(&[7u8; 32].into()).unwrap();
        let pk = sk.verifying_key().to_encoded_point(false);
        let nonce = b"server-nonce-0001";
        let pcr = [0xABu8; 32];
        let attest = build_attest(nonce, &pcr);
        let sig = sign(&sk, &attest);

        let q = verify_quote(&attest, &sig, pk.as_bytes(), nonce).expect("verify");
        assert_eq!(q.pcr_digest, pcr);
        assert_eq!(q.reset_count, 3);
        assert_eq!(q.restart_count, 1);
    }

    #[test]
    fn wrong_nonce_is_replay_rejected() {
        let sk = SigningKey::from_bytes(&[7u8; 32].into()).unwrap();
        let pk = sk.verifying_key().to_encoded_point(false);
        let attest = build_attest(b"server-nonce-0001", &[0xAB; 32]);
        let sig = sign(&sk, &attest);
        assert_eq!(
            verify_quote(&attest, &sig, pk.as_bytes(), b"different-nonce"),
            Err(AttestError::NonceMismatch)
        );
    }

    #[test]
    fn tampered_attest_fails_signature() {
        let sk = SigningKey::from_bytes(&[7u8; 32].into()).unwrap();
        let pk = sk.verifying_key().to_encoded_point(false);
        let nonce = b"server-nonce-0001";
        let mut attest = build_attest(nonce, &[0xAB; 32]);
        let sig = sign(&sk, &attest);
        // Flip a byte in the PCR digest region (after signing).
        let n = attest.len();
        attest[n - 1] ^= 0xFF;
        assert_eq!(
            verify_quote(&attest, &sig, pk.as_bytes(), nonce),
            Err(AttestError::SignatureInvalid)
        );
    }

    #[test]
    fn wrong_ak_key_fails() {
        let sk = SigningKey::from_bytes(&[7u8; 32].into()).unwrap();
        let other = SigningKey::from_bytes(&[9u8; 32].into()).unwrap();
        let other_pk = other.verifying_key().to_encoded_point(false);
        let nonce = b"server-nonce-0001";
        let attest = build_attest(nonce, &[0xAB; 32]);
        let sig = sign(&sk, &attest);
        assert_eq!(
            verify_quote(&attest, &sig, other_pk.as_bytes(), nonce),
            Err(AttestError::SignatureInvalid)
        );
    }

    #[test]
    fn bad_magic_rejected() {
        let mut attest = build_attest(b"n0123456", &[0xAB; 32]);
        attest[0] = 0x00; // corrupt magic
        assert!(matches!(
            parse_attest(&attest),
            Err(AttestError::BadMagic(_))
        ));
    }

    #[test]
    fn truncated_structure_does_not_panic() {
        let attest = build_attest(b"n0123456", &[0xAB; 32]);
        for cut in 0..attest.len() {
            // Every prefix either parses or errors — never panics.
            let _ = parse_attest(&attest[..cut]);
        }
    }
}
