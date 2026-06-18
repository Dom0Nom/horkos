#!/usr/bin/env python3
"""Evaluate the saved server behavioral-anomaly ONNX artifact.

Role: validates model metadata and executes the exported graph against seeded
synthetic honest/anomalous windows. Target platform: Horkos server development
hosts. Interface: ``eval_anomaly_model.py MODEL_PATH``. Dependencies are NumPy
and ONNX only; all reported metrics are circular synthetic pipeline sanity
checks, not real-world efficacy claims.
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path

import numpy as np
import onnx
from onnx.reference import ReferenceEvaluator

from synth_behavior import FEATURE_DIM, FEATURE_NAMES, gen_anomalous, gen_honest


EVAL_SEED = 20260620
EVAL_ROWS = 4_000
DECISION_FLOOR = 2.5
MIN_AUC = 0.85
MAX_HONEST_FPR = 0.02
MIN_ANOMALOUS_DETECTION = 0.70


def _metadata(model: onnx.ModelProto) -> dict[str, str]:
    return {entry.key: entry.value for entry in model.metadata_props}


def _validate_metadata(model: onnx.ModelProto) -> None:
    metadata = _metadata(model)
    try:
        names = tuple(json.loads(metadata["horkos.feature_names"]))
        dimension = int(metadata["horkos.feature_dim"])
    except (KeyError, TypeError, ValueError, json.JSONDecodeError) as exc:
        raise ValueError("model feature metadata is missing or malformed") from exc
    if names != FEATURE_NAMES or dimension != FEATURE_DIM:
        raise ValueError("model feature metadata does not match behavior_features.json")
    if metadata.get("horkos.manifest_version") != "1":
        raise ValueError("model manifest version must be 1")
    if metadata.get("horkos.q99_maps_to") != "2.5":
        raise ValueError("model calibration metadata must map q99 to 2.5")


def _score_rows(
    evaluator: ReferenceEvaluator, rows: np.ndarray
) -> np.ndarray:
    scores = np.empty(rows.shape[0], dtype=np.float64)
    for index, row in enumerate(rows):
        outputs = evaluator.run(None, {"features": row[np.newaxis, :].astype(np.float32)})
        if len(outputs) != 1:
            raise ValueError(f"model returned {len(outputs)} outputs, expected one")
        scalar = np.asarray(outputs[0]).reshape(-1)
        if scalar.size != 1 or not np.isfinite(scalar[0]):
            raise ValueError("model output must be one finite scalar per row")
        scores[index] = float(scalar[0])
    return scores


def _pairwise_auc(honest: np.ndarray, anomalous: np.ndarray) -> float:
    """Tie-aware Mann-Whitney AUC without sklearn or a quadratic allocation."""
    wins = 0.0
    for score in anomalous:
        wins += float(np.count_nonzero(score > honest))
        wins += 0.5 * float(np.count_nonzero(score == honest))
    return wins / float(honest.size * anomalous.size)


def _quantiles(scores: np.ndarray) -> str:
    values = np.quantile(scores, [0.5, 0.95, 0.99, 0.999])
    return " ".join(
        f"{name}={value:.4f}"
        for name, value in zip(("p50", "p95", "p99", "p999"), values, strict=True)
    )


def evaluate(model_path: Path) -> tuple[float, float, float]:
    if not model_path.is_file():
        raise FileNotFoundError(f"model does not exist: {model_path}")

    model = onnx.load(model_path)
    onnx.checker.check_model(model)
    _validate_metadata(model)
    evaluator = ReferenceEvaluator(model)

    rng = np.random.default_rng(EVAL_SEED)
    honest_rows = gen_honest(EVAL_ROWS, rng)
    anomalous_rows = gen_anomalous(EVAL_ROWS, rng)
    honest_scores = _score_rows(evaluator, honest_rows)
    anomalous_scores = _score_rows(evaluator, anomalous_rows)

    auc = _pairwise_auc(honest_scores, anomalous_scores)
    honest_fpr = float(np.mean(honest_scores >= DECISION_FLOOR))
    anomalous_detection = float(np.mean(anomalous_scores >= DECISION_FLOOR))

    print(f"model: {model_path}")
    print(f"honest: {_quantiles(honest_scores)}")
    print(f"anomalous: {_quantiles(anomalous_scores)}")
    print(f"ROC-AUC: {auc:.4f}")
    print(f"honest FPR at {DECISION_FLOOR:.1f}: {honest_fpr:.4f}")
    print(
        f"anomalous detection at {DECISION_FLOOR:.1f}: "
        f"{anomalous_detection:.4f}"
    )
    print("thresholds are synthetic pipeline sanity gates, not efficacy claims")

    failures = []
    if auc < MIN_AUC:
        failures.append(f"AUC {auc:.4f} < {MIN_AUC:.2f}")
    if honest_fpr > MAX_HONEST_FPR:
        failures.append(f"honest FPR {honest_fpr:.4f} > {MAX_HONEST_FPR:.2f}")
    if anomalous_detection < MIN_ANOMALOUS_DETECTION:
        failures.append(
            "anomalous detection "
            f"{anomalous_detection:.4f} < {MIN_ANOMALOUS_DETECTION:.2f}"
        )
    if failures:
        raise RuntimeError("synthetic pipeline sanity gates failed: " + "; ".join(failures))
    return auc, honest_fpr, anomalous_detection


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("model", type=Path)
    args = parser.parse_args()
    evaluate(args.model)


if __name__ == "__main__":
    main()
