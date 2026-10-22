"""Tests for score_history. Small made-up data, no real files.

D's file check (d_fusion.fusion._read_component) is called here, in a test only.
"""

import json
from datetime import date

import numpy as np
import pandas as pd
import pytest

from vesper.components.b_survival.score_history import (
    DECISION_DATES,
    METADATA_FILE,
    check_grid,
    file_names,
    main,
    monthly_grid,
    score_one_time,
)
from vesper.components.b_survival.survival_table import OUTPUT_COLUMNS
from vesper.components.d_fusion.fusion import _read_component
from vesper.config import load_settings

SNAPSHOT = pd.Timestamp("2026-10-01", tz="UTC")
EARLY = date(2024, 7, 1)
LATE = date(2025, 1, 1)


def cve_rows(n, seed=0):
    """Made-up survival rows published 2020-2025, followed up to the snapshot.

    Higher CVSS is listed sooner. Some CVEs have an exploit date after publication.
    """
    rng = np.random.default_rng(seed)
    published = pd.Timestamp("2020-01-01", tz="UTC") + pd.to_timedelta(
        rng.integers(0, 5 * 365, n), "D"
    )
    follow_up = (SNAPSHOT - published).days.to_numpy()
    score = rng.choice([4.3, 5.5, 6.5, 7.5, 8.8, 9.8], n)
    time_to_listing = np.floor(rng.exponential(4000 / np.exp(0.9 * (score - 7))))
    event = (time_to_listing < follow_up).astype(int)
    exploit_lag = rng.integers(1, 900, n)
    has_exploit = rng.random(n) < 0.3
    table = pd.DataFrame(
        {
            "cve_id": [f"CVE-2020-{10000 + i}" for i in range(n)],
            "published_at": published,
            "duration_days": np.where(event == 1, time_to_listing, follow_up).astype(int),
            "event": event,
            "already_exploited": False,
            "kev_launch_group": False,
            "cvss_base_score": score,
            "cvss_attack_vector": rng.choice(["NETWORK", "LOCAL"], n),
            "cvss_attack_complexity": rng.choice(["LOW", "HIGH"], n),
            "cvss_privileges_required": rng.choice(["NONE", "LOW"], n),
            "cvss_user_interaction": rng.choice(["NONE", "REQUIRED"], n),
            "cvss_missing": False,
            "cvss_is_primary": pd.array([True] * n, dtype="boolean"),
            "cwe_ids": rng.choice(["CWE-79", "CWE-89", None], n),
            "exploit_at_publication": False,
            "exploit_first_date": pd.Series(
                np.where(has_exploit, published + pd.to_timedelta(exploit_lag, "D"), pd.NaT),
                dtype="datetime64[ns, UTC]",
            ),
        }
    )
    return table[OUTPUT_COLUMNS]


@pytest.fixture(scope="module")
def table():
    return cve_rows(1500, seed=7)


@pytest.fixture(scope="module")
def early(table):
    return score_one_time(table, EARLY)


def start(day):
    return pd.Timestamp(day, tz="UTC")


# --- The grid ---------------------------------------------------------------------


def test_the_default_grid_is_monthly_from_2024_07_to_2026_09():
    assert len(DECISION_DATES) == 27
    assert DECISION_DATES[0] == date(2024, 7, 1)
    assert DECISION_DATES[-1] == date(2026, 9, 1)
    assert monthly_grid(date(2025, 11, 1), date(2026, 2, 1)) == (
        date(2025, 11, 1),
        date(2025, 12, 1),
        date(2026, 1, 1),
        date(2026, 2, 1),
    )


def test_a_decision_whose_label_window_reaches_the_snapshot_is_refused():
    assert check_grid((date(2026, 9, 1),)) == (date(2026, 9, 1),)
    with pytest.raises(ValueError, match="unfinished label window"):
        check_grid((date(2026, 9, 2),))
    with pytest.raises(ValueError, match="repeated"):
        check_grid((EARLY, EARLY))


# --- No look-ahead ----------------------------------------------------------------


def test_the_model_for_t_is_trained_only_on_cves_published_before_t(table, early):
    _, _, info = early

    before = table[
        (table["published_at"] >= start("2021-11-03")) & (table["published_at"] < start(EARLY))
    ]
    assert info["train_rows"] == len(before)
    # Events are only those listed before T; later ones were re-censored
    stop = before["published_at"].dt.normalize() + pd.to_timedelta(before["duration_days"], "D")
    assert info["train_events"] == int(((before["event"] == 1) & (stop < start(EARLY))).sum())
    assert info["train_max_follow_up_days"] <= (EARLY - date(2021, 11, 3)).days


def test_early_scores_do_not_change_when_data_after_t_changes(table, early):
    ranked, raw, _ = early
    changed = table.copy()
    published_day = changed["published_at"].dt.normalize()
    stop = published_day + pd.to_timedelta(changed["duration_days"], "D")
    after = stop >= start(EARLY)
    # Every outcome after T flips (listed <-> not listed), and listings move
    changed.loc[after, "event"] = 1 - changed.loc[after, "event"]
    changed.loc[after, "duration_days"] = (start("2026-09-30") - published_day[after]).dt.days
    # Every exploit date on or after T moves to another day after T
    late_exploit = changed["exploit_first_date"] >= start(EARLY)
    changed.loc[late_exploit, "exploit_first_date"] = start("2026-01-01")
    # New CVEs published on or after T
    extra = cve_rows(200, seed=99)
    extra["cve_id"] = [f"CVE-2025-{20000 + i}" for i in range(200)]
    extra["published_at"] = start(EARLY) + pd.to_timedelta(np.arange(200), "D")
    changed = pd.concat([changed, extra], ignore_index=True)

    ranked_again, raw_again, _ = score_one_time(changed, EARLY)

    pd.testing.assert_frame_equal(ranked, ranked_again)
    pd.testing.assert_frame_equal(raw, raw_again)


def test_an_exploit_date_on_or_after_t_never_reaches_a_feature(table, early):
    ranked, _, _ = early
    changed = table.copy()
    # Exploits dated exactly on T, or later, must not count
    changed["exploit_first_date"] = start(EARLY)

    ranked_again, _, _ = score_one_time(changed, EARLY)

    pd.testing.assert_frame_equal(ranked, ranked_again)


# --- Statuses ---------------------------------------------------------------------


def test_listed_before_t_is_already_exploited_and_listed_after_t_is_scored(table):
    rows = table.copy()
    # Both published 2023-01-01; one listed 2024-06-30, the other 2024-07-01 (on T)
    rows.loc[0, ["published_at", "duration_days", "event"]] = [start("2023-01-01"), 546, 1]
    rows.loc[1, ["published_at", "duration_days", "event"]] = [start("2023-01-01"), 547, 1]

    ranked, raw, _ = score_one_time(rows, EARLY)

    status = ranked.set_index("cve_id")["status"]
    assert status[rows.loc[0, "cve_id"]] == "already_exploited"
    assert status[rows.loc[1, "cve_id"]] == "available"


def test_one_row_per_cve_published_before_t(table, early):
    ranked, raw, _ = early

    expected = set(table.loc[table["published_at"] < start(EARLY), "cve_id"])
    assert set(ranked["cve_id"]) == expected
    assert not ranked["cve_id"].duplicated().any()
    assert ranked["cve_id"].tolist() == sorted(ranked["cve_id"])
    assert ranked["status"].tolist() == raw["status"].tolist()


# --- The run folder ---------------------------------------------------------------


def write_table(table, settings):
    folder = settings.data_processed / "b_survival"
    folder.mkdir(parents=True, exist_ok=True)
    saved = table.copy()
    saved["exploit_first_date"] = saved["exploit_first_date"].dt.strftime("%Y-%m-%d")
    saved.to_csv(folder / "survival_table.csv", index=False, date_format="%Y-%m-%dT%H:%M:%S.%fZ")


def test_main_writes_one_file_pair_per_t_that_passes_d_checks(table, tmp_path):
    settings = load_settings(tmp_path)
    write_table(table, settings)

    folder = main(settings, decision_dates=(LATE, EARLY), workers=1)

    assert folder.name == "run-001"
    metadata = json.loads((folder / METADATA_FILE).read_text())
    assert metadata["decision_grid"] == ["2024-07-01", "2025-01-01"]
    assert "Retrospective replay" in metadata["limits"][0]
    keys = set()
    for day, info in zip((EARLY, LATE), metadata["decision_times"], strict=True):
        name, raw_name = file_names(day)
        frame = _read_component(folder / name, "b_survival")
        raw = _read_component(folder / raw_name, "b_survival")
        assert set(frame["decision_time"]) == {start(day).isoformat()}
        assert set(frame["trained_through"]) == {start(day).isoformat()}
        assert set(frame["model_version"]) == {f"b_survival-cox-percentile-{day}-0.1"}
        assert frame["cve_id"].tolist() == raw["cve_id"].tolist()
        assert info["rows"] == len(frame)
        keys |= set(zip(frame["cve_id"], frame["decision_time"], strict=True))
    assert len(keys) == sum(info["rows"] for info in metadata["decision_times"])


def test_a_second_run_never_overwrites_the_first(table, tmp_path):
    settings = load_settings(tmp_path)
    write_table(table, settings)

    first = main(settings, decision_dates=(EARLY,), workers=1)
    before = (first / METADATA_FILE).read_text()
    second = main(settings, decision_dates=(EARLY,), workers=1)

    assert (first.name, second.name) == ("run-001", "run-002")
    assert (first / METADATA_FILE).read_text() == before
