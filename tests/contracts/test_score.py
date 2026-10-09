from dataclasses import FrozenInstanceError, replace
from datetime import date, datetime, timezone

import pytest

from vesper.contracts.score import Component, Score, ScoreKind, ScoreStatus


def make_score() -> Score:
    return Score(
        cve_id="CVE-2021-44228",
        component=Component.A_TEXT,
        decision_time=datetime(2021, 12, 10, 10, 15, tzinfo=timezone.utc),
        horizon_days=90,
        score=0.87,
        score_kind=ScoreKind.RANKING_SCORE,
        status=ScoreStatus.AVAILABLE,
        reason=None,
        model_version="a_text-0.1",
        snapshot_date=date(2026, 10, 1),
    )


def test_score_keeps_the_given_values():
    score = make_score()

    assert score.component is Component.A_TEXT
    assert score.score == 0.87
    assert score.horizon_days == 90


def test_score_cannot_be_changed_after_creation():
    score = make_score()

    with pytest.raises(FrozenInstanceError):
        score.score = 1.0


def test_component_without_an_answer_gives_an_empty_score():
    score = replace(
        make_score(),
        score=None,
        status=ScoreStatus.ALREADY_EXPLOITED,
        reason="Listed in KEV before the decision time",
    )

    assert score.score is None


def test_invalid_cve_identifier_is_rejected():
    with pytest.raises(ValueError, match="Invalid CVE identifier"):
        replace(make_score(), cve_id="2021-44228")


def test_decision_time_without_a_time_zone_is_rejected():
    with pytest.raises(ValueError, match="time zone"):
        replace(make_score(), decision_time=datetime(2021, 12, 10, 10, 15))


@pytest.mark.parametrize("horizon_days", [0, -30])
def test_horizon_that_is_not_positive_is_rejected(horizon_days: int):
    with pytest.raises(ValueError, match="must be positive"):
        replace(make_score(), horizon_days=horizon_days)


@pytest.mark.parametrize("value", [None, float("nan"), float("inf")])
def test_available_score_must_be_a_finite_number(value: float | None):
    with pytest.raises(ValueError, match="finite number"):
        replace(make_score(), score=value)


def test_score_that_is_not_available_must_be_empty():
    with pytest.raises(ValueError, match="must be empty"):
        replace(make_score(), status=ScoreStatus.ABSTAINED)
