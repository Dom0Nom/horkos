//! Role: merge-gate bypass tests (guardrail #12) for the signed-rule-bundle
//! trust boundary. The attacker model: control of the bundle distribution
//! channel (CDN, MITM, compromised mirror) but NOT the signing key. Every
//! test is an attempt to get an unauthorized rule set accepted by the ban
//! path. Registered as a `[[test]]` in `server/ban-engine/Cargo.toml`.
//!
//! Target platforms: server (host CI).

use ban_engine::bundle::{BundleLoader, BundleMetadata, RuleBundle};
use ban_engine::error::BanEngineError;
use ed25519_dalek::{Signer, SigningKey};

fn attacker_key() -> SigningKey {
    SigningKey::from_bytes(&[0x41u8; 32])
}

fn legit_key() -> SigningKey {
    SigningKey::from_bytes(&[0x07u8; 32])
}

fn bundle_signed_by(key: &SigningKey, expires_at: &str, rules: serde_json::Value) -> RuleBundle {
    let mut bundle = RuleBundle {
        metadata: BundleMetadata {
            version: 1,
            sha256: "00".repeat(32),
            signed_by: "whoever".to_string(),
            expires_at: expires_at.to_string(),
        },
        signature: String::new(),
        rules: vec![rules],
    };
    let canonical = bundle.canonical_bytes().expect("canonical");
    bundle.signature = hex::encode(key.sign(&canonical).to_bytes());
    bundle
}

/// ATTACK: ship a bundle signed by the ATTACKER's key (e.g. lowering the ban
/// threshold to mass-false-ban, or zeroing weights to blind the engine).
#[test]
fn attacker_signed_bundle_is_rejected() {
    let loader = BundleLoader::with_trust_root(legit_key().verifying_key());
    let bundle = bundle_signed_by(
        &attacker_key(),
        "2099-01-01T00:00:00Z",
        serde_json::json!({ "fusion": { "ban_threshold": 1 } }),
    );
    assert!(matches!(
        loader.verify(&bundle),
        Err(BanEngineError::BundleSignatureInvalid)
    ));
}

/// ATTACK: take a legitimately-signed bundle and swap the rules payload
/// (signature stripping / splice).
#[test]
fn spliced_rules_under_legit_signature_are_rejected() {
    let key = legit_key();
    let loader = BundleLoader::with_trust_root(key.verifying_key());
    let mut bundle = bundle_signed_by(
        &key,
        "2099-01-01T00:00:00Z",
        serde_json::json!({ "fusion": { "ban_threshold": 70 } }),
    );
    bundle.rules = vec![serde_json::json!({ "fusion": { "ban_threshold": 10_000 } })];
    assert!(loader.verify(&bundle).is_err());
}

/// ATTACK: replay an OLD validly-signed bundle (e.g. one with weaker
/// detections) after it expired.
#[test]
fn expired_replay_is_rejected_despite_valid_signature() {
    let key = legit_key();
    let loader = BundleLoader::with_trust_root(key.verifying_key());
    let bundle = bundle_signed_by(
        &key,
        "2024-01-01T00:00:00Z",
        serde_json::json!({ "fusion": { "ban_threshold": 70 } }),
    );
    assert!(matches!(
        loader.verify(&bundle),
        Err(BanEngineError::BundleExpired)
    ));
}

/// ATTACK: strip the expiry to dodge the replay check (malformed dates must
/// fail closed, never parse as "no expiry").
#[test]
fn unparseable_expiry_fails_closed() {
    let key = legit_key();
    let loader = BundleLoader::with_trust_root(key.verifying_key());
    for bad in ["", "never", "9999999999", "2099-13-45T99:99:99Z"] {
        let bundle = bundle_signed_by(
            &key,
            bad,
            serde_json::json!({ "fusion": { "ban_threshold": 70 } }),
        );
        assert!(
            loader.verify(&bundle).is_err(),
            "expiry {bad:?} must not verify"
        );
    }
}

/// ATTACK: omit or blank the signature field entirely.
#[test]
fn unsigned_wire_bundle_never_parses() {
    for json in [
        r#"{"metadata":{"version":1,"sha256":"00","signed_by":"x","expires_at":"2099-01-01T00:00:00Z"},"rules":[]}"#,
        r#"{"metadata":{"version":1,"sha256":"00","signed_by":"x","expires_at":"2099-01-01T00:00:00Z"},"signature":"","rules":[]}"#,
        r#"{"metadata":{"version":1,"sha256":"00","signed_by":"x","expires_at":"2099-01-01T00:00:00Z"},"signature":"   ","rules":[]}"#,
    ] {
        assert!(matches!(
            RuleBundle::parse(json.as_bytes()),
            Err(BanEngineError::BundleUnsigned)
        ));
    }
}

/// ATTACK: feed a loader that has NO configured trust root (misdeployment).
/// It must accept NOTHING — not even a validly-signed bundle.
#[cfg(not(feature = "unverified_bundles_dev_only"))]
#[test]
fn loader_without_trust_root_accepts_nothing() {
    let key = legit_key();
    let bundle = bundle_signed_by(
        &key,
        "2099-01-01T00:00:00Z",
        serde_json::json!({ "fusion": { "ban_threshold": 70 } }),
    );
    assert!(BundleLoader::default().verify(&bundle).is_err());
}
