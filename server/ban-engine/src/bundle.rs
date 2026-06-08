//! src/bundle.rs
//!
//! Role: Rule bundle data structures and the FAIL-CLOSED placeholder verifier.
//! The real Ed25519 verifier lands in a follow-up /tdd phase.
//!
//! Security invariants enforced here:
//!
//! - The deserialiser REJECTS bundles whose signature field is missing or
//!   empty. Untrusted input cannot bypass signing.
//! - The placeholder verifier only compiles when the
//!   `unverified_bundles_dev_only` feature is enabled.
//! - Even with the feature on, a `--release` build refuses to compile via a
//!   `compile_error!` so no release artifact can accept unverified bundles.
//!
//! Target platforms: server.

use serde::{Deserialize, Serialize};

use crate::error::BanEngineError;

/// Metadata describing the active rule bundle as exposed to clients.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct BundleMetadata {
    pub version: u32,
    pub sha256: String,
    pub signed_by: String,
    pub expires_at: String, // RFC 3339; flips to chrono in /tdd phase.
}

/// Wire representation of a signed bundle. Real-format bundles always include
/// a `signature` field; the deserialiser refuses bundles without one so a
/// malicious upstream cannot trick the loader by omitting the field.
#[derive(Debug, Clone, Deserialize)]
pub struct RuleBundle {
    pub metadata: BundleMetadata,
    /// Hex-encoded signature over the canonical metadata + rules bytes.
    /// Missing or empty -> deserializes to "" and is rejected by `parse`
    /// (both surface as the unsigned-bundle path, fail-closed).
    #[serde(default)]
    pub signature: String,
    #[serde(default)]
    pub rules: Vec<serde_json::Value>,
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
}

/// Verification gate. `must_verify` defaults to true. The fail-closed
/// path is the only one that ships in non-feature-flag builds.
#[derive(Debug, Clone, Copy)]
pub struct BundleLoader {
    pub must_verify: bool,
}

impl Default for BundleLoader {
    fn default() -> Self {
        // Fail-closed default per CLAUDE.md guardrail #8 and the plan.
        Self { must_verify: true }
    }
}

impl BundleLoader {
    /// Verify a parsed bundle. Without the dev-only feature this always
    /// returns `VerifierNotImplemented` — the route surface is reachable
    /// but no client can be granted bundle acceptance until the real
    /// Ed25519 verifier lands.
    #[cfg(not(feature = "unverified_bundles_dev_only"))]
    pub fn verify(&self, _bundle: &RuleBundle) -> Result<(), BanEngineError> {
        Err(BanEngineError::VerifierNotImplemented)
    }

    /// Dev-only placeholder verifier. The authoritative fail-closed guarantee is
    /// the CI/build-policy ban on the `unverified_bundles_dev_only` feature for
    /// release branches (see Cargo.toml); the `debug_assertions` gate below is
    /// defense-in-depth that fires for the usual `--release` profile.
    #[cfg(feature = "unverified_bundles_dev_only")]
    pub fn verify(&self, bundle: &RuleBundle) -> Result<(), BanEngineError> {
        // Defense-in-depth: refuse to compile under the standard release profile
        // (debug_assertions off). The hard gate is the CI feature ban above.
        #[cfg(not(debug_assertions))]
        compile_error!(
            "feature 'unverified_bundles_dev_only' must not be used in release builds; \
             a release binary must use the real Ed25519 verifier."
        );

        if self.must_verify && bundle.signature.trim().is_empty() {
            return Err(BanEngineError::BundleUnsigned);
        }
        // Placeholder: pretend the signature is valid in dev builds only.
        Ok(())
    }
}

/// The placeholder bundle returned by `GET /api/rules/current` in Phase 2.
/// Once the durable rule store and Ed25519 verifier land, this is replaced
/// with a database-backed loader.
pub fn placeholder_metadata() -> BundleMetadata {
    BundleMetadata {
        version: 0,
        sha256: "0000000000000000000000000000000000000000000000000000000000000000".to_string(),
        signed_by: "horkos-dev-placeholder".to_string(),
        expires_at: "1970-01-01T00:00:00Z".to_string(),
    }
}
