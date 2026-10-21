"""Tests for evaluate.py that are not in test_cox_model.py. Small made-up data."""

import numpy as np
import pytest

from vesper.components.b_survival.evaluate import (
    bootstrap_metrics,
    brier_ipcw,
    c_index,
    c_index_fast,
    censoring_survival,
    listed_within,
    precision_at_k,
)


def test_c_index_without_any_event_is_not_a_number():
    time, event, risk = [10, 20, 30], [0, 0, 0], [3.0, 2.0, 1.0]

    assert np.isnan(c_index_fast(time, event, risk))


def test_c_index_of_a_reversed_ranking_is_zero():
    time, event = [1, 2, 3, 4], [1, 1, 1, 0]
    risk = [1.0, 2.0, 3.0, 4.0]  # the CVE listed first has the lowest risk

    assert c_index_fast(time, event, risk) == pytest.approx(0.0)
    assert c_index(time, event, risk) == pytest.approx(0.0)


def test_brier_refuses_a_horizon_where_every_cve_is_censored():
    time = np.array([5, 5, 5])
    event = np.array([0, 0, 0])
    censoring = censoring_survival(time, event)

    with pytest.raises(ValueError, match="Censoring weight is zero"):
        brier_ipcw(time, event, np.array([0.1, 0.1, 0.1]), 30, censoring)


def test_listed_within_counts_only_events_inside_the_window():
    time = np.array([10, 365, 366, 10])
    event = np.array([1, 1, 1, 0])

    assert listed_within(time, event).tolist() == [True, True, False, False]


def test_precision_at_k_with_k_larger_than_the_set_uses_every_cve():
    assert precision_at_k([0.9, 0.1], [True, False], k=100) == pytest.approx(0.5)


def test_bootstrap_uses_the_same_resamples_for_every_model():
    rng = np.random.default_rng(0)
    time = rng.integers(1, 400, 200)
    event = (rng.random(200) < 0.2).astype(int)
    risk = rng.random(200)
    listed = np.tile([0.1, 0.2, 0.3], (200, 1))

    # Two identical models must get identical intervals
    intervals = bootstrap_metrics(
        time, event, {"a": (risk, listed), "b": (risk.copy(), listed.copy())}, n_resamples=20
    )

    assert intervals["a"] == intervals["b"]
