"""Leakage tests for features.py, alone and after split_data. Small made-up data.

The encoder itself is also tested in test_cox_model.py. These tests check that
nothing dated on or after the cut-off, and nothing made from the outcome, can
change a train feature.
"""

from datetime import date

import pandas as pd
import pytest

from vesper.components.b_survival.features import FLAG_COLUMN, FeatureEncoder
from vesper.components.b_survival.split_data import split_at_cutoff
from vesper.components.b_survival.survival_table import OUTPUT_COLUMNS

CUTOFF = date(2024, 1, 1)


def survival_rows(rows):
    """A made-up survival table.

    A row is (cve_id, published_at, duration_days, event, exploit_first_date,
    exploit_at_publication, cvss_base_score). The other columns get fixed values.
    """
    table = pd.DataFrame(
        rows,
        columns=[
            "cve_id",
            "published_at",
            "duration_days",
            "event",
            "exploit_first_date",
            "exploit_at_publication",
            "cvss_base_score",
        ],
    )
    table["published_at"] = pd.to_datetime(table["published_at"], format="ISO8601", utc=True)
    table["exploit_first_date"] = pd.to_datetime(
        table["exploit_first_date"], format="ISO8601", utc=True
    )
    table["already_exploited"] = False
    table["kev_launch_group"] = False
    table["cvss_attack_vector"] = ["NETWORK", "LOCAL"] * (len(table) // 2) + ["NETWORK"] * (
        len(table) % 2
    )
    table["cvss_attack_complexity"] = "LOW"
    table["cvss_privileges_required"] = "NONE"
    table["cvss_user_interaction"] = "NONE"
    table["cvss_missing"] = False
    table["cvss_is_primary"] = pd.array([True] * len(table), dtype="boolean")
    table["cwe_ids"] = "CWE-79"
    return table[OUTPUT_COLUMNS]


@pytest.fixture
def table():
    return survival_rows(
        [
            # Exploit on the publication day: a Day-0 fact, so the flag is set
            ("CVE-2023-0001", "2023-03-01", 1000, 0, "2023-03-01", True, 9.8),
            # Exploit after publication but before the cut-off: not a Day-0 fact
            ("CVE-2023-0002", "2023-03-01", 100, 1, "2023-05-01", False, 7.5),
            # Exploit after the cut-off: did not exist at the cut-off
            ("CVE-2023-0003", "2023-06-01", 900, 1, "2024-02-01", False, 8.8),
            # Exploit on the cut-off day: also not known yet
            ("CVE-2023-0004", "2023-09-01", 500, 0, "2024-01-01", False, 5.3),
            ("CVE-2023-0005", "2023-10-01", 50, 1, None, False, 6.1),
            ("CVE-2023-0006", "2023-11-01", 700, 0, None, False, 4.3),
            # Test CVE
            ("CVE-2024-0001", "2024-02-01", 600, 0, None, False, 7.0),
        ]
    )


def encoded_train(table, cutoff=CUTOFF):
    train, _, _ = split_at_cutoff(table, cutoff)
    return train, FeatureEncoder().fit(train).transform(train)


def test_no_train_exploit_date_on_or_after_the_cutoff(table):
    train, _ = encoded_train(table)

    cutoff_day = pd.Timestamp(CUTOFF, tz="UTC")
    assert not (train["exploit_first_date"] >= cutoff_day).any()
    # The two future exploit dates were removed, the past ones kept
    kept = train.set_index("cve_id")["exploit_first_date"]
    assert kept[["CVE-2023-0003", "CVE-2023-0004"]].isna().all()
    assert kept[["CVE-2023-0001", "CVE-2023-0002"]].notna().all()


def test_only_an_exploit_on_or_before_publication_sets_the_flag(table):
    train, features = encoded_train(table)

    flags = dict(zip(train["cve_id"], features[FLAG_COLUMN], strict=True))
    assert flags == {
        "CVE-2023-0001": 1,
        "CVE-2023-0002": 0,
        "CVE-2023-0003": 0,
        "CVE-2023-0004": 0,
        "CVE-2023-0005": 0,
        "CVE-2023-0006": 0,
    }


def test_moving_an_exploit_date_after_publication_does_not_change_any_feature(table):
    _, before = encoded_train(table)
    moved = table.copy()
    # Move every later exploit to a different later day, before and after the cut-off
    later = ~moved["exploit_at_publication"] & moved["exploit_first_date"].notna()
    moved.loc[later, "exploit_first_date"] = pd.Timestamp("2023-12-01", tz="UTC")

    _, after = encoded_train(moved)

    pd.testing.assert_frame_equal(before, after)


def test_changing_the_outcome_does_not_change_any_feature(table):
    _, before = encoded_train(table)
    changed = table.copy()
    changed["event"] = 1 - changed["event"]
    changed["duration_days"] = changed["duration_days"] // 3
    changed["kev_launch_group"] = True

    _, after = encoded_train(changed)

    pd.testing.assert_frame_equal(before, after)


def test_the_encoder_fitted_on_train_ignores_test_rows(table):
    train, _ = encoded_train(table)
    with_extreme_test = table.copy()
    with_extreme_test.loc[with_extreme_test["cve_id"] == "CVE-2024-0001", "cvss_base_score"] = 0.1

    train_again, _ = encoded_train(with_extreme_test)
    first = FeatureEncoder().fit(train)
    second = FeatureEncoder().fit(train_again)

    assert (first.score_mean, first.score_std) == (second.score_mean, second.score_std)


def test_events_on_or_after_the_cutoff_are_censored_before_the_model_sees_them(table):
    train, _ = encoded_train(table)

    rows = train.set_index("cve_id")
    # 2023-06-01 + 900 days is after the cut-off: censored at the cut-off (214 days)
    assert rows.loc["CVE-2023-0003", "event"] == 0
    assert rows.loc["CVE-2023-0003", "duration_days"] == 214
    # 2023-03-01 + 100 days is before the cut-off: the event is kept
    assert rows.loc["CVE-2023-0002", "event"] == 1
    assert rows.loc["CVE-2023-0002", "duration_days"] == 100
    stop = rows["published_at"].dt.normalize() + pd.to_timedelta(rows["duration_days"], "D")
    assert (stop <= pd.Timestamp(CUTOFF, tz="UTC")).all()
