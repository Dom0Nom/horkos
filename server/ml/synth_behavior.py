#!/usr/bin/env python3
"""Generate synthetic behavioral-window features for the server anomaly model.

Role: provides deterministic honest and anomalous window-level aggregates that
match ``behavior_features.json``. Target platform: Horkos server training and
evaluation tooling. The generated distributions are synthetic PoC inputs, not
evidence of real-world detection efficacy.
"""

from __future__ import annotations

import json
from pathlib import Path

import numpy as np
from numpy.typing import NDArray


_MANIFEST_PATH = Path(__file__).with_name("behavior_features.json")
_MANIFEST = json.loads(_MANIFEST_PATH.read_text(encoding="utf-8"))

FEATURE_NAMES = tuple(_MANIFEST["feature_names"])
FEATURE_DIM = int(_MANIFEST["dimension"])

if FEATURE_DIM != 10 or len(FEATURE_NAMES) != FEATURE_DIM:
    raise ValueError("behavior feature manifest must define exactly 10 features")


def _normal(
    rng: np.random.Generator, mean: float, std: float | NDArray[np.float64], n: int
) -> NDArray[np.float64]:
    return rng.normal(mean, std, n)


def _validate(rows: NDArray[np.float64], n: int) -> NDArray[np.float32]:
    if rows.shape != (n, FEATURE_DIM):
        raise ValueError(f"expected feature shape {(n, FEATURE_DIM)}, got {rows.shape}")
    if not np.isfinite(rows).all():
        raise ValueError("generated behavioral features contain non-finite values")
    return rows.astype(np.float32)


def gen_honest(n: int, rng: np.random.Generator) -> NDArray[np.float32]:
    """Return ``n`` correlated synthetic honest-population window rows."""
    if n < 0:
        raise ValueError("row count must be non-negative")

    skill = _normal(rng, 0.0, 1.0, n)
    tempo = _normal(rng, 0.0, 1.0, n)
    device = _normal(rng, 0.0, 1.0, n)
    clock = _normal(rng, 0.0, 1.0, n)

    overshoot = np.clip(
        0.25 - 0.03 * skill + 0.04 * tempo + _normal(rng, 0.0, 0.03, n),
        0.0,
        1.5,
    )
    settle = np.clip(
        120.0 - 15.0 * skill + 10.0 * tempo + _normal(rng, 0.0, 12.0, n),
        1.0,
        500.0,
    )
    jerk = np.clip(
        8.0 + 1.5 * skill - 0.8 * tempo + _normal(rng, 0.0, 1.5, n),
        0.0,
        100.0,
    )
    mean_rt = np.clip(
        240.0 - 20.0 * skill + 10.0 * tempo + _normal(rng, 0.0, 15.0, n),
        1.0,
        1000.0,
    )
    min_rt = np.clip(mean_rt - np.abs(_normal(rng, 55.0, 12.0, n)), 1.0, mean_rt)
    switch_latency = np.clip(
        180.0 - 18.0 * skill + 12.0 * tempo + _normal(rng, 0.0, 15.0, n),
        1.0,
        1000.0,
    )
    switch_ang_sep = np.clip(
        0.55 + 0.08 * tempo + _normal(rng, 0.0, 0.08, n), 0.2, 3.2
    )
    log_hid_var = np.clip(
        23.0 + 1.5 * device + 0.3 * tempo + _normal(rng, 0.0, 0.5, n),
        0.0,
        40.0,
    )
    remapper = rng.random(n) >= 0.9
    injected_fraction = np.zeros(n, dtype=np.float64)
    injected_fraction[remapper] = 0.25 * rng.beta(1.0, 20.0, remapper.sum())
    injected_fraction = np.clip(injected_fraction, 0.0, 255.0 / 256.0)
    clock_drift = np.clip(
        np.abs(_normal(rng, 0.0, 8.0 + 4.0 * np.abs(clock), n)), 0.0, 2.0e9
    )

    rows = np.column_stack(
        (
            overshoot,
            settle,
            jerk,
            mean_rt,
            min_rt,
            switch_latency,
            switch_ang_sep,
            log_hid_var,
            injected_fraction,
            clock_drift,
        )
    )
    return _validate(rows, n)


def gen_anomalous(n: int, rng: np.random.Generator) -> NDArray[np.float32]:
    """Return ``n`` synthetic off-manifold windows across three anomaly modes."""
    if n < 0:
        raise ValueError("row count must be non-negative")

    rows = gen_honest(n, rng).astype(np.float64)
    modes = rng.permutation(np.arange(n) % 3)

    precision = modes == 0
    p_count = int(precision.sum())
    rows[precision, 0] = rng.uniform(0.0, 0.03, p_count)
    rows[precision, 1] = rng.uniform(5.0, 25.0, p_count)
    rows[precision, 2] = rng.uniform(35.0, 60.0, p_count)
    rows[precision, 3] = rng.uniform(25.0, 60.0, p_count)
    rows[precision, 4] = rng.uniform(10.0, 30.0, p_count)
    rows[precision, 5] = rng.uniform(15.0, 45.0, p_count)
    rows[precision, 6] = rng.uniform(0.7, 1.2, p_count)

    input_automation = modes == 1
    rows[input_automation, 0] -= 0.12
    rows[input_automation, 1] -= 44.0
    rows[input_automation, 2] += 4.6
    rows[input_automation, 3] -= 54.0
    rows[input_automation, 4] -= 54.0
    rows[input_automation, 5] -= 53.0
    rows[input_automation, 6] += 0.23
    ia_count = int(input_automation.sum())
    rows[input_automation, 7] = rng.uniform(5.0, 10.0, ia_count)
    rows[input_automation, 8] = rng.uniform(0.25, 0.9, ia_count)

    timing = modes == 2
    t_count = int(timing.sum())
    rows[timing, 3] = rng.uniform(25.0, 60.0, t_count)
    rows[timing, 4] = rng.uniform(10.0, 30.0, t_count)
    rows[timing, 5] = rng.uniform(15.0, 45.0, t_count)
    rows[timing, 6] = rng.uniform(0.7, 1.2, t_count)
    rows[timing, 9] = rng.uniform(300.0, 2000.0, t_count)

    rows[:, 0] = np.clip(rows[:, 0], 0.0, 1.5)
    rows[:, 1] = np.clip(rows[:, 1], 1.0, 500.0)
    rows[:, 2] = np.clip(rows[:, 2], 0.0, 100.0)
    rows[:, 3] = np.clip(rows[:, 3], 1.0, 1000.0)
    rows[:, 4] = np.minimum(np.clip(rows[:, 4], 1.0, 1000.0), rows[:, 3])
    rows[:, 5] = np.clip(rows[:, 5], 1.0, 1000.0)
    rows[:, 6] = np.clip(rows[:, 6], 0.2, 3.2)
    rows[:, 7] = np.clip(rows[:, 7], 0.0, 40.0)
    rows[:, 8] = np.clip(rows[:, 8], 0.0, 255.0 / 256.0)
    rows[:, 9] = np.clip(rows[:, 9], 0.0, 2.0e9)
    return _validate(rows, n)


def _canonical(name: str) -> NDArray[np.float32]:
    row = np.asarray(_MANIFEST[name], dtype=np.float32)
    if row.shape != (FEATURE_DIM,) or not np.isfinite(row).all():
        raise ValueError(f"manifest {name} must be a finite {FEATURE_DIM}-vector")
    return row.copy()


def canonical_honest() -> NDArray[np.float32]:
    return _canonical("canonical_honest")


def canonical_anomalous() -> NDArray[np.float32]:
    return _canonical("canonical_anomalous")
