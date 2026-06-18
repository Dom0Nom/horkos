//! Role: compatibility test for dual optional model scorers in the live server
//! pipeline. Target platform: server test hosts. Interface: `pipeline` spawn APIs.

use std::sync::Arc;

use ban_engine::pipeline::{
    spawn_with_scorer, spawn_with_scorers, PipelineConfig, PipelineScorers,
};
use ban_engine::store::DecisionStore;

#[tokio::test]
async fn pipeline_starts_with_both_optional_scorers_disabled() {
    let scorers = PipelineScorers::new(Arc::new(None), Arc::new(None));

    let handle = spawn_with_scorers(
        PipelineConfig::default(),
        Arc::new(DecisionStore::memory()),
        scorers,
    );

    assert!(handle.alive.load(std::sync::atomic::Ordering::Acquire));
}

#[tokio::test]
async fn aim_only_spawn_wrapper_remains_compatible() {
    let handle = spawn_with_scorer(
        PipelineConfig::default(),
        Arc::new(DecisionStore::memory()),
        Arc::new(None),
    );

    assert!(handle.alive.load(std::sync::atomic::Ordering::Acquire));
}
