#!/usr/bin/env python3
"""Train and export the server behavioral-anomaly PCA autoencoder.

Role: fits an honest-only linear reconstruction model, calibrates its error on
an independent honest split, and writes an opset-13 ONNX artifact. Target
platform: Horkos server development/deployment tooling. Interface:
``train_anomaly_model.py [OUTPUT]``. Dependencies are NumPy and ONNX only.
The source distributions are synthetic PoC data, not efficacy evidence.
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path

import numpy as np
import onnx
from onnx import TensorProto, helper

from synth_behavior import (
    FEATURE_DIM,
    FEATURE_NAMES,
    canonical_anomalous,
    canonical_honest,
    gen_honest,
)


TRAIN_SEED = 20260618
CALIBRATION_SEED = 20260619
TRAIN_ROWS = 12_000
CALIBRATION_ROWS = 4_000
BOTTLENECK_RANK = 4
STD_EPSILON = 1.0e-6
FUSION_WEAK_FLOOR = 2.5


def _require_finite(name: str, values: np.ndarray) -> None:
    if not np.isfinite(values).all():
        raise ValueError(f"{name} contains non-finite values")


def _reconstruction_error(
    rows: np.ndarray,
    feature_mean: np.ndarray,
    feature_std: np.ndarray,
    encoder: np.ndarray,
    decoder: np.ndarray,
) -> np.ndarray:
    normalized = (rows - feature_mean) / feature_std
    reconstructed = (normalized @ encoder) @ decoder
    errors = np.mean(np.square(normalized - reconstructed), axis=1, keepdims=True)
    _require_finite("reconstruction error", errors)
    return errors


def _strength(
    rows: np.ndarray,
    feature_mean: np.ndarray,
    feature_std: np.ndarray,
    encoder: np.ndarray,
    decoder: np.ndarray,
    calibration_center: float,
    calibration_scale: float,
) -> np.ndarray:
    errors = _reconstruction_error(rows, feature_mean, feature_std, encoder, decoder)
    return np.maximum((errors - calibration_center) / calibration_scale, 0.0)


def _tensor(name: str, values: np.ndarray) -> onnx.TensorProto:
    values = np.asarray(values, dtype=np.float32)
    return helper.make_tensor(
        name,
        TensorProto.FLOAT,
        list(values.shape),
        values.reshape(-1).tolist(),
    )


def _add_metadata(model: onnx.ModelProto) -> None:
    metadata = {
        "horkos.manifest_version": "1",
        "horkos.feature_dim": str(FEATURE_DIM),
        "horkos.feature_names": json.dumps(FEATURE_NAMES, separators=(",", ":")),
        "horkos.bottleneck_rank": str(BOTTLENECK_RANK),
        "horkos.train_seed": str(TRAIN_SEED),
        "horkos.calibration_seed": str(CALIBRATION_SEED),
        "horkos.q99_maps_to": f"{FUSION_WEAK_FLOOR:.1f}",
    }
    for key, value in metadata.items():
        entry = model.metadata_props.add()
        entry.key = key
        entry.value = value


def train(output: Path) -> None:
    if FEATURE_DIM != 10 or len(FEATURE_NAMES) != FEATURE_DIM:
        raise ValueError("behavior feature manifest must define exactly 10 features")
    if not 0 < BOTTLENECK_RANK < FEATURE_DIM:
        raise ValueError("bottleneck rank must be between zero and feature dimension")

    train_rows = gen_honest(TRAIN_ROWS, np.random.default_rng(TRAIN_SEED)).astype(
        np.float64
    )
    calibration_rows = gen_honest(
        CALIBRATION_ROWS, np.random.default_rng(CALIBRATION_SEED)
    ).astype(np.float64)
    _require_finite("training rows", train_rows)
    _require_finite("calibration rows", calibration_rows)

    feature_mean = train_rows.mean(axis=0)
    feature_std = train_rows.std(axis=0)
    feature_std = np.where(feature_std < STD_EPSILON, 1.0, feature_std)
    normalized = (train_rows - feature_mean) / feature_std
    _require_finite("normalized training rows", normalized)

    _, _, vt = np.linalg.svd(normalized, full_matrices=False)
    encoder = vt[:BOTTLENECK_RANK].T
    decoder = vt[:BOTTLENECK_RANK]
    _require_finite("encoder", encoder)
    _require_finite("decoder", decoder)

    calibration_errors = _reconstruction_error(
        calibration_rows, feature_mean, feature_std, encoder, decoder
    )
    calibration_center = float(np.median(calibration_errors))
    calibration_q99 = float(np.quantile(calibration_errors, 0.99))
    if not np.isfinite(calibration_center) or not np.isfinite(calibration_q99):
        raise ValueError("calibration statistics must be finite")
    if calibration_q99 <= calibration_center:
        raise ValueError("calibration q99 must be greater than its median")
    calibration_scale = (calibration_q99 - calibration_center) / FUSION_WEAK_FLOOR
    if not np.isfinite(calibration_scale) or calibration_scale <= 0.0:
        raise ValueError("calibration scale must be finite and positive")

    feature_mean_f32 = feature_mean.astype(np.float32)
    feature_std_f32 = feature_std.astype(np.float32)
    encoder_f32 = encoder.astype(np.float32)
    decoder_f32 = decoder.astype(np.float32)
    center_f32 = np.asarray([calibration_center], dtype=np.float32)
    scale_f32 = np.asarray([calibration_scale], dtype=np.float32)

    graph = helper.make_graph(
        nodes=[
            helper.make_node(
                "Sub", ["features", "feature_mean"], ["centered_features"]
            ),
            helper.make_node(
                "Div", ["centered_features", "feature_std"], ["normalized_features"]
            ),
            helper.make_node(
                "MatMul", ["normalized_features", "encoder"], ["encoded"]
            ),
            helper.make_node("MatMul", ["encoded", "decoder"], ["reconstructed"]),
            helper.make_node(
                "Sub", ["normalized_features", "reconstructed"], ["residual"]
            ),
            helper.make_node("Mul", ["residual", "residual"], ["squared_error"]),
            helper.make_node(
                "ReduceMean",
                ["squared_error"],
                ["reconstruction_error"],
                axes=[1],
                keepdims=1,
            ),
            helper.make_node(
                "Sub",
                ["reconstruction_error", "calibration_center"],
                ["centered_error"],
            ),
            helper.make_node(
                "Div", ["centered_error", "calibration_scale"], ["raw_strength"]
            ),
            helper.make_node("Relu", ["raw_strength"], ["anomaly_strength"]),
        ],
        name="behavioral_anomaly_pca_autoencoder",
        inputs=[
            helper.make_tensor_value_info(
                "features", TensorProto.FLOAT, [1, FEATURE_DIM]
            )
        ],
        outputs=[
            helper.make_tensor_value_info(
                "anomaly_strength", TensorProto.FLOAT, [1, 1]
            )
        ],
        initializer=[
            _tensor("feature_mean", feature_mean_f32),
            _tensor("feature_std", feature_std_f32),
            _tensor("encoder", encoder_f32),
            _tensor("decoder", decoder_f32),
            _tensor("calibration_center", center_f32),
            _tensor("calibration_scale", scale_f32),
        ],
    )
    model = helper.make_model(graph, opset_imports=[helper.make_opsetid("", 13)])
    model.ir_version = 9
    _add_metadata(model)
    onnx.checker.check_model(model)

    canonical_rows = np.vstack((canonical_honest(), canonical_anomalous())).astype(
        np.float64
    )
    canonical_strengths = _strength(
        canonical_rows,
        feature_mean,
        feature_std,
        encoder,
        decoder,
        calibration_center,
        calibration_scale,
    ).reshape(-1)

    output.parent.mkdir(parents=True, exist_ok=True)
    onnx.save(model, output)
    print(f"training rows: {TRAIN_ROWS}")
    print(f"calibration rows: {CALIBRATION_ROWS}")
    print(f"bottleneck rank: {BOTTLENECK_RANK}")
    print(f"calibration median: {calibration_center:.8f}")
    print(f"calibration q99: {calibration_q99:.8f}")
    print(f"calibration scale: {calibration_scale:.8f}")
    print(f"canonical honest strength: {canonical_strengths[0]:.4f}")
    print(f"canonical anomalous strength: {canonical_strengths[1]:.4f}")
    print(f"wrote {output}")


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("output", nargs="?", type=Path, default=Path("anomaly_score.onnx"))
    args = parser.parse_args()
    train(args.output)


if __name__ == "__main__":
    main()
