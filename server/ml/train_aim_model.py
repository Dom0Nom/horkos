#!/usr/bin/env python3
"""Train the aim-kinematics anomaly model and export ONNX.

Role: produces the trained model the hand-built fixture stands in for
that `ban_engine::scoring::AimScorer` loads. Trains a logistic-regression
classifier on SYNTHETIC honest-vs-bot aim-kinematics feature distributions
(166/167/169 share the [overshoot, settle_ms, jerk_abs, pad] input shape the
Rust feature flattener produces), folds feature standardization INTO the
exported weights so the ONNX consumes RAW features (exactly what scoring.rs
feeds), and emits the same Gemm+Sigmoid graph the scorer expects.

HONESTY: this is trained on synthetic distributions, not real player telemetry
(a PoC has no labelled population). The pipeline, the standardization fold, and
the ONNX export are real; the *data* is a stand-in. A production model trains
this exact graph on the honest-population baseline corpus.

Usage: python3 train_aim_model.py [out.onnx]
Deps: numpy, onnx (no sklearn — logistic regression is hand-fit).
"""

import sys
import numpy as np
import onnx
from onnx import helper, TensorProto

RNG = np.random.default_rng(20260611)
FEATURE_DIM = 4  # [overshoot_ratio, settle_ms, jerk_abs, pad]


def synth(n):
    """Synthetic feature distributions.

    Honest human flicks: real overshoot, human settle time, moderate jerk.
    Aim-bot flicks: near-zero overshoot, near-instant settle, extreme jerk —
    the structural signature the segmenter extracts.
    """
    # honest
    h_overshoot = np.clip(RNG.normal(0.25, 0.10, n), 0, None)
    h_settle = np.clip(RNG.normal(120.0, 40.0, n), 1, None)
    h_jerk = np.clip(RNG.normal(8.0, 3.0, n), 0, None)
    H = np.stack([h_overshoot, h_settle, h_jerk, np.zeros(n)], axis=1)
    # bot
    b_overshoot = np.clip(RNG.normal(0.02, 0.02, n), 0, None)
    b_settle = np.clip(RNG.normal(15.0, 8.0, n), 1, None)
    b_jerk = np.clip(RNG.normal(45.0, 15.0, n), 0, None)
    B = np.stack([b_overshoot, b_settle, b_jerk, np.zeros(n)], axis=1)
    X = np.vstack([H, B])
    y = np.concatenate([np.zeros(n), np.ones(n)])  # 0=honest, 1=bot
    return X, y


def fit_logreg(Xs, y, iters=4000, lr=0.5):
    """Plain batch-gradient logistic regression on standardized features."""
    n, d = Xs.shape
    w = np.zeros(d)
    b = 0.0
    for _ in range(iters):
        z = Xs @ w + b
        p = 1.0 / (1.0 + np.exp(-z))
        gw = Xs.T @ (p - y) / n
        gb = float(np.sum(p - y) / n)
        w -= lr * gw
        b -= lr * gb
    return w, b


def main():
    out = sys.argv[1] if len(sys.argv) > 1 else "aim_score.onnx"
    X, y = synth(4000)

    # Standardize (the 3 live features have wildly different scales). The pad
    # column is constant 0 -> guard its std.
    mu = X.mean(axis=0)
    sigma = X.std(axis=0)
    sigma[sigma == 0] = 1.0
    Xs = (X - mu) / sigma

    w, b = fit_logreg(Xs, y)

    # Fold standardization into raw-feature weights so the ONNX takes raw input:
    #   z = w·((x-mu)/sigma) + b = (w/sigma)·x + (b - sum(w*mu/sigma))
    w_raw = (w / sigma).astype(np.float32)
    b_raw = np.float32(b - float(np.sum(w * mu / sigma)))

    # Report training accuracy (sanity).
    z = X.astype(np.float32) @ w_raw + b_raw
    p = 1.0 / (1.0 + np.exp(-z))
    acc = float(np.mean((p > 0.5) == (y > 0.5)))
    print(f"train accuracy: {acc:.3f}")
    print(f"raw weights: {w_raw.tolist()}  bias: {float(b_raw):.4f}")

    # Same Gemm+Sigmoid graph the scorer expects: features[1,4] -> Gemm -> Sigmoid.
    W = w_raw.reshape(FEATURE_DIM, 1)
    graph = helper.make_graph(
        nodes=[
            helper.make_node("Gemm", ["features", "W", "B"], ["logit"],
                             alpha=1.0, beta=1.0, transB=0),
            helper.make_node("Sigmoid", ["logit"], ["score"]),
        ],
        name="aim_score",
        inputs=[helper.make_tensor_value_info("features", TensorProto.FLOAT, [1, FEATURE_DIM])],
        outputs=[helper.make_tensor_value_info("score", TensorProto.FLOAT, [1, 1])],
        initializer=[
            helper.make_tensor("W", TensorProto.FLOAT, [FEATURE_DIM, 1], W.flatten().tolist()),
            helper.make_tensor("B", TensorProto.FLOAT, [1], [float(b_raw)]),
        ],
    )
    model = helper.make_model(graph, opset_imports=[helper.make_opsetid("", 13)])
    model.ir_version = 9
    onnx.checker.check_model(model)
    onnx.save(model, out)
    print(f"wrote {out}")


if __name__ == "__main__":
    main()
