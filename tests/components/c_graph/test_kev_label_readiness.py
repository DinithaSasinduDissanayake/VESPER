from datetime import UTC, datetime

import pandas as pd
import pytest

from vesper.components.c_graph.kev_labels import classify_outcome


def classify(
    *,
    published="2020-01-01T00:00:00Z",
    date_added=None,
    cutoff="2022-01-01T00:00:00Z",
    as_of="2022-03-01T00:00:00Z",
    days=30,
):
    return classify_outcome(
        published=published,
        date_added=date_added,
        decision_time=cutoff,
        horizon_days=days,
        catalog_as_of=as_of,
    )


def test_publication_at_cutoff_is_not_yet_eligible():
    status, label, _ = classify(published="2022-01-01T00:00:00Z")
    assert (status, label) == ("not_published_at_cutoff", None)


def test_date_added_at_cutoff_is_already_listed():
    status, label, _ = classify(date_added="2022-01-01")
    assert (status, label) == ("already_in_kev_at_cutoff", None)


def test_future_keV_addition_inside_horizon_is_positive():
    status, label, end = classify(date_added="2022-01-31")
    assert (status, label) == ("positive_within_horizon", True)
    assert end == pd.Timestamp("2022-01-31T00:00:00Z")


def test_negative_requires_complete_horizon_observation():
    status, label, _ = classify(date_added=None, as_of="2022-01-30T00:00:00Z")
    assert (status, label) == ("censored_horizon_not_fully_observed", None)
    status, label, _ = classify(date_added=None, as_of="2022-01-31T00:00:00Z")
    assert (status, label) == ("negative_full_horizon_observed", False)


def test_cutoffs_before_kev_catalog_start_are_unknown():
    status, label, _ = classify(cutoff="2021-10-01T00:00:00Z", as_of="2022-03-01T00:00:00Z")
    assert (status, label) == ("catalog_not_yet_operational", None)


@pytest.mark.parametrize("days", [0, -1, True, 1.5])
def test_horizon_must_be_positive_integer(days):
    with pytest.raises(ValueError, match="horizon_days"):
        classify_outcome(
            published=datetime(2020, 1, 1, tzinfo=UTC),
            date_added=None,
            decision_time=datetime(2022, 1, 1, tzinfo=UTC),
            horizon_days=days,
            catalog_as_of=datetime(2022, 3, 1, tzinfo=UTC),
        )
