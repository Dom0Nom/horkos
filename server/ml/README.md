# Horkos aim-kinematics model training

`train_aim_model.py` trains the ONNX model that `ban_engine::scoring::AimScorer`
loads (via `HORKOS_AIM_MODEL`, or the committed test fixture at
`server/ban-engine/tests/fixtures/aim_score.onnx`).

```
python3 train_aim_model.py [out.onnx]   # deps: numpy, onnx
```

## What it produces

A logistic-regression classifier over the 4-feature aim-kinematics vector
`[overshoot_ratio, settle_ms, jerk_abs, pad]` (the shape the Rust feature
flattener emits for signals 166/167/169), exported as a `Gemm + Sigmoid` ONNX
graph that consumes **raw** features — feature standardization is folded into
the exported weights, so no client/server scaling step is needed.

## Honesty

The training data is **synthetic**: drawn from hand-specified honest-human vs.
aim-bot feature distributions (humans overshoot and settle slowly with moderate
jerk; bots drive overshoot→0, settle→instant, jerk→extreme). A PoC has no
labelled player population. The pipeline, the standardization fold, and the
ONNX export are real and exactly what a production run uses — only the corpus
is a stand-in. The same applies to the analyzers' population baselines
(`OCCLUDED_LOCK_BASELINE` et al. in `server/telemetry/src/analyzers/`): they
remain documented placeholders until a real honest-population corpus exists.
