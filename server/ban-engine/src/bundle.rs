//! Role: Rule bundle data structures + the Ed25519 verifier. A bundle carries
//! the signed-rule parameters (fusion thresholds, cadence params, ...); the
//! verifier is the trust boundary between the rule author and the ban path.
//!
//! Security invariants enforced here:
//!
//! - The deserialiser REJECTS bundles whose signature field is missing or
//!   empty. Untrusted input cannot bypass signing.
//! - Verification is `verify_strict` (rejects the malleable/small-order edge
//!   cases plain `verify` accepts) over the CANONICAL bundle bytes — the
//!   serialized `{metadata, rules}` pair, NOT the incoming wire bytes, so a
//!   re-encoded-but-semantically-identical bundle verifies and a tampered
//!   field never does.
//! - Expiry is checked BEFORE the signature result is reported: an expired
//!   bundle with a valid signature is a replay, rejected as `BundleExpired`.
//! - A loader without a trust root NEVER accepts: `VerifierNotImplemented`
//!   (fail closed). The dev-only escape hatch only compiles with the
//!   `unverified_bundles_dev_only` feature, and even then refuses to compile
//!   in `--release` via `compile_error!`.
//!
//! Target platforms: server.

use ed25519_dalek::{Signature, VerifyingKey};
use serde::{Deserialize, Serialize};
use time::format_description::well_known::Rfc3339;
use time::OffsetDateTime;

use crate::error::BanEngineError;

/// Metadata describing the active rule bundle as exposed to clients.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct BundleMetadata {
    pub version: u32,
    pub sha256: String,
    pub signed_by: String,
    pub expires_at: String, // RFC 3339
}

/// Wire representation of a signed bundle. Real-format bundles always include
/// a `signature` field; the deserialiser refuses bundles without one so a
/// malicious upstream cannot trick the loader by omitting the field.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RuleBundle {
    pub metadata: BundleMetadata,
    /// Hex-encoded Ed25519 signature (64 bytes) over `canonical_bytes()`.
    /// Missing or empty -> deserializes to "" and is rejected by `parse`
    /// (both surface as the unsigned-bundle path, fail-closed).
    #[serde(default)]
    pub signature: String,
    #[serde(default)]
    pub rules: Vec<serde_json::Value>,
}

/// The signed view of a bundle: everything EXCEPT the signature itself, in
/// fixed field order. Serialization of this struct defines the canonical
/// bytes both the signer and the verifier operate on.
#[derive(Serialize)]
struct CanonicalBundle<'a> {
    metadata: &'a BundleMetadata,
    rules: &'a [serde_json::Value],
}

impl RuleBundle {
    /// Deserialise + structural validate. Refuses bundles without a signature.
    pub fn parse(bytes: &[u8]) -> Result<Self, BanEngineError> {
        let bundle: RuleBundle =
            serde_json::from_slice(bytes).map_err(|_| BanEngineError::BundleSignatureInvalid)?;
        if bundle.signature.trim().is_empty() {
            return Err(BanEngineError::BundleUnsigned);
        }
        Ok(bundle)
    }

    /// The exact bytes the signature covers. Re-serialized from the parsed
    /// fields (canonical form), never the raw wire bytes.
    pub fn canonical_bytes(&self) -> Result<Vec<u8>, BanEngineError> {
        Ok(serde_json::to_vec(&CanonicalBundle {
            metadata: &self.metadata,
            rules: &self.rules,
        })?)
    }
}

/// Verification gate. Carries the pinned trust root (the rule author's
/// Ed25519 public key). Without one, verification fails closed.
#[derive(Debug, Clone, Copy)]
pub struct BundleLoader {
    pub must_verify: bool,
    trust_root: Option<VerifyingKey>,
}

impl Default for BundleLoader {
    fn default() -> Self {
        // Fail-closed default per CLAUDE.md guardrail #8 and the plan: no
        // trust root configured = nothing verifies.
        Self {
            must_verify: true,
            trust_root: None,
        }
    }
}

impl BundleLoader {
    /// Loader pinned to one trust root.
    pub fn with_trust_root(key: VerifyingKey) -> Self {
        Self {
            must_verify: true,
            trust_root: Some(key),
        }
    }

    /// Loader from a hex-encoded 32-byte Ed25519 public key (deployment
    /// configuration, e.g. `HORKOS_BUNDLE_PUBKEY`).
    pub fn from_hex_key(hex_key: &str) -> Result<Self, BanEngineError> {
        let bytes: [u8; 32] = hex::decode(hex_key.trim())
            .ok()
            .and_then(|v| v.try_into().ok())
            .ok_or(BanEngineError::InvalidTrustRoot)?;
        let key = VerifyingKey::from_bytes(&bytes).map_err(|_| BanEngineError::InvalidTrustRoot)?;
        Ok(Self::with_trust_root(key))
    }

    /// Verify a parsed bundle against the pinned trust root.
    ///
    /// Order matters: expiry first (a validly-signed but expired bundle is a
    /// REPLAY — `BundleExpired`, not "valid"), then strict signature
    /// verification over the canonical bytes.
    pub fn verify(&self, bundle: &RuleBundle) -> Result<(), BanEngineError> {
        check_expiry(&bundle.metadata)?;

        let Some(key) = &self.trust_root else {
            return self.verify_without_trust_root(bundle);
        };

        let sig_bytes: [u8; 64] = hex::decode(bundle.signature.trim())
            .ok()
            .and_then(|v| v.try_into().ok())
            .ok_or(BanEngineError::BundleSignatureInvalid)?;
        let sig = Signature::from_bytes(&sig_bytes);
        let canonical = bundle.canonical_bytes()?;
        key.verify_strict(&canonical, &sig)
            .map_err(|_| BanEngineError::BundleSignatureInvalid)
    }

    /// No trust root configured: fail closed...
    #[cfg(not(feature = "unverified_bundles_dev_only"))]
    fn verify_without_trust_root(&self, _bundle: &RuleBundle) -> Result<(), BanEngineError> {
        Err(BanEngineError::VerifierNotImplemented)
    }

    /// ...unless the dev-only feature is on. The authoritative fail-closed
    /// guarantee is the CI/build-policy ban on the feature for release
    /// branches (see Cargo.toml); the `debug_assertions` gate below is
    /// defense-in-depth that fires for the usual `--release` profile.
    #[cfg(feature = "unverified_bundles_dev_only")]
    fn verify_without_trust_root(&self, bundle: &RuleBundle) -> Result<(), BanEngineError> {
        #[cfg(not(debug_assertions))]
        compile_error!(
            "feature 'unverified_bundles_dev_only' must not be used in release builds; \
             a release binary must use the real Ed25519 verifier."
        );

        if self.must_verify && bundle.signature.trim().is_empty() {
            return Err(BanEngineError::BundleUnsigned);
        }
        // Dev builds only: accept without a trust root.
        Ok(())
    }
}

/// Reject bundles whose `expires_at` is malformed or in the past. A bundle
/// that cannot prove its freshness window is treated as expired (fail closed),
/// never as "no expiry".
fn check_expiry(meta: &BundleMetadata) -> Result<(), BanEngineError> {
    let expires = OffsetDateTime::parse(&meta.expires_at, &Rfc3339)
        .map_err(|_| BanEngineError::BundleExpired)?;
    if expires <= OffsetDateTime::now_utc() {
        return Err(BanEngineError::BundleExpired);
    }
    Ok(())
}

/// The placeholder bundle returned by `GET /api/rules/current` in Phase 2.
/// Once the durable rule store lands, this is replaced with a store-backed
/// loader.
pub fn placeholder_metadata() -> BundleMetadata {
    BundleMetadata {
        version: 0,
        sha256: "0000000000000000000000000000000000000000000000000000000000000000".to_string(),
        signed_by: "horkos-dev-placeholder".to_string(),
        expires_at: "1970-01-01T00:00:00Z".to_string(),
    }
}
