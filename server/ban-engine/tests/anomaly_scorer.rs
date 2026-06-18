//! Role: train/serve contract tests for the server behavioral-anomaly scorer.
//! Target platform: server test hosts. Interfaces: the shared feature manifest,
//! deterministic ONNX fixture, and `ban_engine::anomaly` public API.

use std::path::PathBuf;

use ban_engine::anomaly::{
    AnomalyScorer, BehaviorObservation, BEHAVIOR_FEATURE_DIM, BEHAVIOR_FEATURE_NAMES,
    SIGNAL_BEHAVIOR_ANOMALY,
};

fn manifest() -> serde_json::Value {
    serde_json::from_str(include_str!("../../ml/behavior_features.json")).unwrap()
}

fn manifest_vector(key: &str) -> [f32; BEHAVIOR_FEATURE_DIM] {
    let manifest = manifest();
    let values: Vec<f32> = manifest[key]
        .as_array()
        .unwrap()
        .iter()
        .map(|value| value.as_f64().unwrap() as f32)
        .collect();
    values.try_into().unwrap()
}

#[test]
fn rust_feature_names_match_the_training_manifest() {
    let manifest = manifest();
    let names: Vec<&str> = manifest["feature_names"]
        .as_array()
        .unwrap()
        .iter()
        .map(|value| value.as_str().unwrap())
        .collect();

    assert_eq!(names, BEHAVIOR_FEATURE_NAMES);
}

fn fixture_path() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/anomaly_score.onnx")
}

#[test]
fn canonical_anomalous_window_emits_signal_217() {
    let scorer = AnomalyScorer::from_file(&fixture_path()).unwrap();
    let observation = BehaviorObservation {
        features: manifest_vector("canonical_anomalous"),
        sample_count: 8,
        window_ticks: 1023,
    };

    let event = scorer.score(41, &observation, 2.5).unwrap();

    assert_eq!(event.player_id, 41);
    assert_eq!(event.signal_id, SIGNAL_BEHAVIOR_ANOMALY);
    assert!(event.zscore.is_finite());
    assert!(event.zscore >= 2.5);
    assert_eq!(event.sample_count, 8);
    assert_eq!(event.window_ticks, 1023);
}

#[test]
fn canonical_honest_window_does_not_emit() {
    let scorer = AnomalyScorer::from_file(&fixture_path()).unwrap();
    let observation = BehaviorObservation {
        features: manifest_vector("canonical_honest"),
        sample_count: 8,
        window_ticks: 1023,
    };

    assert!(scorer.score(42, &observation, 2.5).is_none());
}
