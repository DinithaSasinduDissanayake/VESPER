"""Tests for split_data. They use small made-up tables, not the real files."""

from datetime import date

import pandas as pd
import pytest

from vesper.components.b_survival import split_data
from vesper.components.b_survival.split_data import (
    check_no_forbidden_columns,
    check_no_negative_durations,
    check_no_shared_cve_ids,
    check_rows_in_cohort,
    check_test_follow_up,
    check_train_exploit_dates_before_cutoff,
    check_train_follow_up_within_cutoff,
    check_train_published_before_cutoff,
    describe_split,
    main,
    recensor_train,
    run_checks,
    small_train_warning,
    split_at_cutoff,
)
from vesper.components.b_survival.survival_table import OUTPUT_COLUMNS
from vesper.config import load_settings

CUTOFF = date(2022, 1, 1)
SNAPSHOT = date(2026, 10, 1)


def day(text):
    return pd.Timestamp(text, tz="UTC")


def survival_rows(rows):
    """A made-up survival table.

    A row is (cve_id, published_at, duration_days, event, already_exploited,
    exploit_first_date, kev_launch_group). The other columns get fixed values.
    """
    table = pd.DataFrame(
        rows,
        columns=[
            "cve_id",
            "published_at",
            "duration_days",
            "event",
            "already_exploited",
            "exploit_first_date",
            "kev_launch_group",
        ],
    )
    table["published_at"] = pd.to_datetime(table["published_at"], format="ISO8601", utc=True)
    table["exploit_first_date"] = pd.to_datetime(
        table["exploit_first_date"], format="ISO8601", utc=True
    )
    table["cvss_base_score"] = 7.5
    table["cvss_attack_vector"] = "NETWORK"
    table["cvss_attack_complexity"] = "LOW"
    table["cvss_privileges_required"] = "NONE"
    table["cvss_user_interaction"] = "NONE"
    table["cvss_missing"] = False
    table["cvss_is_primary"] = pd.array([True] * len(table), dtype="boolean")
    table["cwe_ids"] = "CWE-79"
    table["exploit_at_publication"] = False
    return table[OUTPUT_COLUMNS]


def row(cve_id, published, duration, event=0, already=False, exploit=None, launch=False):
    return (cve_id, published, duration, event, already, exploit, launch)


def train_for(rows, cutoff=CUTOFF):
    train, _, _ = split_at_cutoff(survival_rows(rows), cutoff)
    return train.set_index("cve_id")


# --- Which CVEs go where -----------------------------------------------------


def test_train_is_before_the_cutoff_and_test_is_the_next_365_days():
    table = survival_rows(
        [
            row("CVE-A", "2021-12-31T23:59:59.999", 100),  # last moment of train
            row("CVE-B", "2022-01-01T00:00:00.000", 100),  # exactly the cut-off: test
            row("CVE-C", "2022-12-31T23:59:59", 100),  # cut-off + 364 days: last test day
            row("CVE-D", "2023-01-01T00:00:00", 100),  # cut-off + 365 days: not used
            row("CVE-E", "2023-06-01T00:00:00", 100),  # after the window: not used
        ]
    )

    train, test, info = split_at_cutoff(table, CUTOFF)

    assert list(train["cve_id"]) == ["CVE-A"]
    assert list(test["cve_id"]) == ["CVE-B", "CVE-C"]
    assert info["rows_not_used"] == 2


def test_the_test_window_follows_the_window_argument():
    table = survival_rows([row("CVE-A", "2022-01-05", 100), row("CVE-B", "2022-02-05", 100)])

    _, test, _ = split_at_cutoff(table, CUTOFF, window_days=30)

    assert list(test["cve_id"]) == ["CVE-A"]


def test_already_exploited_rows_are_removed_from_both_sets_and_counted():
    table = survival_rows(
        [
            row("CVE-A", "2021-06-01", -5, event=1, already=True),
            row("CVE-B", "2021-06-01", 30, event=1),
            row("CVE-C", "2022-03-01", -2, event=1, already=True),
            row("CVE-D", "2022-03-01", 50),
        ]
    )

    train, test, info = split_at_cutoff(table, CUTOFF)

    assert list(train["cve_id"]) == ["CVE-B"]
    assert list(test["cve_id"]) == ["CVE-D"]
    assert info["train_already_exploited_removed"] == 1
    assert info["test_already_exploited_removed"] == 1


def test_kev_launch_group_stays_as_a_column():
    table = survival_rows([row("CVE-A", "2021-06-01", 150, event=1, launch=True)])

    train, _, _ = split_at_cutoff(table, CUTOFF)

    assert "kev_launch_group" in train.columns
    assert bool(train.loc[0, "kev_launch_group"]) is True


def test_columns_are_the_same_as_the_survival_table():
    table = survival_rows([row("CVE-A", "2021-06-01", 30), row("CVE-B", "2022-03-01", 50)])

    train, test, _ = split_at_cutoff(table, CUTOFF)

    assert list(train.columns) == OUTPUT_COLUMNS
    assert list(test.columns) == OUTPUT_COLUMNS


# --- Re-censoring the train set ----------------------------------------------


def test_a_late_event_becomes_censored_at_the_cutoff():
    # Published 2021-12-01, listed in KEV 2022-03-01 (91 days later)
    train = train_for([row("CVE-A", "2021-12-01T10:00:00", 90, event=1)])

    assert train.loc["CVE-A", "event"] == 0
    # From 2021-12-01 to 2022-01-01 is 31 days
    assert train.loc["CVE-A", "duration_days"] == 31


def test_an_early_event_is_kept_unchanged():
    # Published 2021-12-01, listed 2021-12-11: known before the cut-off
    train = train_for([row("CVE-A", "2021-12-01T10:00:00", 10, event=1)])

    assert train.loc["CVE-A", "event"] == 1
    assert train.loc["CVE-A", "duration_days"] == 10


def test_an_event_listed_the_day_before_the_cutoff_is_known():
    train = train_for([row("CVE-A", "2021-12-01", 30, event=1)])  # listed 2021-12-31

    assert train.loc["CVE-A", "event"] == 1
    assert train.loc["CVE-A", "duration_days"] == 30


def test_an_event_listed_on_the_cutoff_day_is_not_known_yet():
    # The cut-off is the start of the day, so a listing on that day is after it
    train = train_for([row("CVE-A", "2021-12-01", 31, event=1)])  # listed 2022-01-01

    assert train.loc["CVE-A", "event"] == 0
    assert train.loc["CVE-A", "duration_days"] == 31


def test_a_row_censored_at_the_snapshot_is_cut_back_to_the_cutoff():
    # Not exploited up to the snapshot: duration reaches 2026-10-01
    train = train_for([row("CVE-A", "2021-11-01T08:00:00", 1795)])

    assert train.loc["CVE-A", "event"] == 0
    assert train.loc["CVE-A", "duration_days"] == 61  # 2021-11-01 to 2022-01-01


def test_an_event_far_in_the_future_is_censored_not_dropped():
    table = survival_rows([row("CVE-A", "2021-12-31T23:00:00", 900, event=1)])

    train, _, info = split_at_cutoff(table, CUTOFF)

    assert len(train) == 1
    assert train.loc[0, "event"] == 0
    assert train.loc[0, "duration_days"] == 1  # published the day before the cut-off
    assert info["train_events_recensored"] == 1


def test_exploit_dates_from_the_future_are_removed_from_train():
    train = train_for(
        [
            row("CVE-A", "2021-10-01", 5, exploit="2021-11-15"),  # known
            row("CVE-B", "2021-10-01", 5, exploit="2022-01-01"),  # on the cut-off day
            row("CVE-C", "2021-10-01", 5, exploit="2022-06-01"),  # after
            row("CVE-D", "2021-10-01", 5, exploit=None),
        ]
    )

    assert train.loc["CVE-A", "exploit_first_date"] == day("2021-11-15")
    assert pd.isna(train.loc["CVE-B", "exploit_first_date"])
    assert pd.isna(train.loc["CVE-C", "exploit_first_date"])
    assert pd.isna(train.loc["CVE-D", "exploit_first_date"])


def test_kev_launch_group_is_cleared_when_its_event_is_recensored():
    # A cut-off before the KEV start date: the launch-day listing is in the future
    cutoff = date(2021, 6, 1)
    table = survival_rows(
        [
            row("CVE-A", "2021-05-01", 186, event=1, launch=True),  # listed 2021-11-03
            row("CVE-B", "2021-05-01", 10, event=1, launch=False),
        ]
    )

    train, _, _ = split_at_cutoff(table, cutoff)
    train = train.set_index("cve_id")

    assert train.loc["CVE-A", "event"] == 0
    assert bool(train.loc["CVE-A", "kev_launch_group"]) is False
    assert train.loc["CVE-B", "event"] == 1


def test_recensor_train_returns_the_counts():
    table = survival_rows(
        [
            row("CVE-A", "2021-12-01", 90, event=1, exploit="2022-02-01"),
            row("CVE-B", "2021-12-01", 10, event=1),
            row("CVE-C", "2021-12-01", 300),
        ]
    )

    result, recensored, exploit_dates = recensor_train(table, CUTOFF)

    assert recensored == 1
    assert exploit_dates == 1
    assert list(result["event"]) == [0, 1, 0]


def test_the_test_set_is_not_changed():
    table = survival_rows(
        [
            row("CVE-A", "2022-03-01T10:00:00", 400, event=1, exploit="2022-09-01"),
            row("CVE-B", "2022-03-01T10:00:00", 1675),
        ]
    )

    _, test, _ = split_at_cutoff(table, CUTOFF)

    pd.testing.assert_frame_equal(test, table.reset_index(drop=True))


def test_the_input_table_is_not_changed():
    table = survival_rows([row("CVE-A", "2021-12-01", 90, event=1, exploit="2022-02-01")])
    before = table.copy()

    split_at_cutoff(table, CUTOFF)

    pd.testing.assert_frame_equal(table, before)


def test_describe_split():
    table = survival_rows(
        [row("CVE-A", "2021-12-01", 5, event=1), row("CVE-B", "2021-12-01", 5)] * 2
    )

    assert describe_split(table) == {"rows": 4, "events": 2, "censored": 2, "event_rate": 50.0}
    assert describe_split(table.iloc[0:0])["event_rate"] is None


# --- Leakage checks: each passes on a good split and fails on a bad one ------


def good_split():
    table = survival_rows(
        [
            row("CVE-A", "2021-12-01", 90, event=1, exploit="2022-02-01"),
            row("CVE-B", "2021-12-01", 10, event=1),
            row("CVE-C", "2021-06-01", 900),
            row("CVE-D", "2022-03-01", 400, event=1),
            row("CVE-E", "2022-03-01", 1675),
        ]
    )
    train, test, _ = split_at_cutoff(table, CUTOFF)
    return train, test


def test_a_good_split_passes_every_check():
    train, test = good_split()

    checks = run_checks(train, test, CUTOFF)

    assert set(checks.values()) == {0}
    assert len(checks) == 11


def test_check_train_published_before_cutoff_fails_on_a_late_row():
    train, _ = good_split()
    assert check_train_published_before_cutoff(train, CUTOFF) == 0

    train.loc[0, "published_at"] = day("2022-01-01")  # exactly the cut-off
    assert check_train_published_before_cutoff(train, CUTOFF) == 1


def test_check_train_follow_up_fails_on_a_duration_past_the_cutoff():
    train, _ = good_split()
    assert check_train_follow_up_within_cutoff(train, CUTOFF) == 0

    train.loc[2, "duration_days"] = train.loc[2, "duration_days"] + 1
    assert check_train_follow_up_within_cutoff(train, CUTOFF) == 1


def test_check_train_follow_up_fails_on_an_event_on_the_cutoff_day():
    train, _ = good_split()
    # An event that stops exactly at the cut-off is not known at the cut-off
    train.loc[0, "event"] = 1
    train.loc[0, "duration_days"] = 31  # published 2021-12-01 -> stops 2022-01-01
    assert check_train_follow_up_within_cutoff(train, CUTOFF) == 1


def test_check_train_follow_up_allows_a_censored_row_that_stops_at_the_cutoff():
    train = pd.DataFrame(
        {
            "published_at": [day("2021-12-01")],
            "duration_days": [31],
            "event": [0],
        }
    )

    assert check_train_follow_up_within_cutoff(train, CUTOFF) == 0


def test_check_train_exploit_dates_fails_on_a_future_exploit():
    train, _ = good_split()
    assert check_train_exploit_dates_before_cutoff(train, CUTOFF) == 0

    train.loc[0, "exploit_first_date"] = day("2022-01-01")
    assert check_train_exploit_dates_before_cutoff(train, CUTOFF) == 1


def test_check_no_shared_cve_ids_fails_when_a_cve_is_in_both_sets():
    train, test = good_split()
    assert check_no_shared_cve_ids(train, test) == 0

    test.loc[0, "cve_id"] = train.loc[0, "cve_id"]
    assert check_no_shared_cve_ids(train, test) == 1


def test_check_no_negative_durations_fails_on_a_negative_duration():
    train, test = good_split()
    assert check_no_negative_durations(train) == 0
    assert check_no_negative_durations(test) == 0

    train.loc[0, "duration_days"] = -1
    assert check_no_negative_durations(train) == 1


@pytest.mark.parametrize("column", ["kev_date_added", "has_exploit", "exploit_count", "in_kev"])
def test_check_no_forbidden_columns_fails_on_each_forbidden_column(column):
    train, _ = good_split()
    assert check_no_forbidden_columns(train) == 0

    train[column] = 1
    assert check_no_forbidden_columns(train) == 1


def test_check_test_follow_up_fails_on_a_cve_too_close_to_the_snapshot():
    _, test = good_split()
    assert check_test_follow_up(test, SNAPSHOT, 365) == 0

    test.loc[0, "published_at"] = day("2026-06-01")  # 122 days before the snapshot
    assert check_test_follow_up(test, SNAPSHOT, 365) == 1
    # Exactly 365 days before the snapshot is allowed
    test.loc[0, "published_at"] = day("2025-10-01")
    assert check_test_follow_up(test, SNAPSHOT, 365) == 0


def test_run_checks_names_the_failed_check():
    train, test = good_split()
    train.loc[0, "duration_days"] = -1

    checks = run_checks(train, test, CUTOFF)

    assert checks["no negative duration in train"] == 1
    assert sum(problems > 0 for problems in checks.values()) >= 1


# --- The whole run -----------------------------------------------------------


def write_survival_table(settings, rows):
    processed = settings.data_processed / "b_survival"
    processed.mkdir(parents=True)
    table = survival_rows(rows)
    out = table.copy()
    out["exploit_first_date"] = out["exploit_first_date"].dt.strftime("%Y-%m-%d")
    out.to_csv(processed / "survival_table.csv", index=False, date_format="%Y-%m-%dT%H:%M:%S.%fZ")
    return processed


MAIN_ROWS = [
    row("CVE-A", "2021-12-01T10:00:00", 90, event=1, exploit="2022-02-01"),
    row("CVE-B", "2021-06-01T10:00:00", 30, event=1),
    row("CVE-C", "2022-03-01T10:00:00", 400, event=1),
    row("CVE-D", "2022-03-01T10:00:00", 1675),
    row("CVE-E", "2021-02-01T10:00:00", -4, event=1, already=True),
]


def test_main_saves_the_split_files_of_both_cohorts(tmp_path):
    # A made-up project folder, so the real data is never touched
    settings = load_settings(tmp_path)
    processed = write_survival_table(settings, MAIN_ROWS)

    splits_dir = main(settings, cutoffs=(CUTOFF,))

    assert splits_dir == processed / "splits"
    assert sorted(path.name for path in splits_dir.iterdir()) == [
        "full",
        "post_kev",
        "split_summary.csv",
    ]
    for cohort in ("full", "post_kev"):
        assert sorted(path.name for path in (splits_dir / cohort).iterdir()) == [
            "test_2022-01-01.csv",
            "train_2022-01-01.csv",
        ]
    train = pd.read_csv(splits_dir / "full" / "train_2022-01-01.csv")
    test = pd.read_csv(splits_dir / "full" / "test_2022-01-01.csv")
    assert list(train.columns) == OUTPUT_COLUMNS
    assert sorted(train["cve_id"]) == ["CVE-A", "CVE-B"]
    assert sorted(test["cve_id"]) == ["CVE-C", "CVE-D"]
    # post_kev: CVE-B (published 2021-06-01) is before KEV started, so it is left out
    post_train = pd.read_csv(splits_dir / "post_kev" / "train_2022-01-01.csv")
    post_test = pd.read_csv(splits_dir / "post_kev" / "test_2022-01-01.csv")
    assert sorted(post_train["cve_id"]) == ["CVE-A"]
    assert sorted(post_test["cve_id"]) == ["CVE-C", "CVE-D"]
    # CVE-A: late event re-censored; its future exploit date is removed
    late = train.set_index("cve_id").loc["CVE-A"]
    assert late["event"] == 0
    assert late["duration_days"] == 31
    assert pd.isna(late["exploit_first_date"])
    # The survival table itself is not changed
    assert (processed / "survival_table.csv").exists()


def test_main_saves_nothing_when_a_check_fails(tmp_path, monkeypatch):
    settings = load_settings(tmp_path)
    processed = write_survival_table(settings, MAIN_ROWS)
    real_split = split_data.split_at_cutoff

    def leaky_split(table, cutoff):
        train, test, info = real_split(table, cutoff)
        train.loc[0, "duration_days"] = 5000  # reaches far past the cut-off
        return train, test, info

    monkeypatch.setattr(split_data, "split_at_cutoff", leaky_split)

    with pytest.raises(ValueError, match="Splits not saved"):
        main(settings, cutoffs=(CUTOFF,))

    assert not (processed / "splits").exists()


def test_main_runs_every_leakage_check_on_both_cohorts(tmp_path, capsys):
    settings = load_settings(tmp_path)
    write_survival_table(settings, MAIN_ROWS)

    main(settings, cutoffs=(CUTOFF,))

    printed = capsys.readouterr().out
    for cohort in ("full", "post_kev"):
        assert f"[{cohort}] Cut-off 2022-01-01" in printed
    # 11 checks per cohort, all passed
    assert printed.count("(ok)") == 22
    assert "FAILED" not in printed


def test_main_saves_nothing_when_a_post_kev_check_fails(tmp_path, monkeypatch):
    settings = load_settings(tmp_path)
    processed = write_survival_table(settings, MAIN_ROWS)
    real_split = split_data.split_at_cutoff

    def leaky_post_kev_split(table, cutoff):
        train, test, info = real_split(table, cutoff)
        if len(table) < 5:  # only the post_kev cohort is this small here
            train.loc[0, "duration_days"] = 5000
        return train, test, info

    monkeypatch.setattr(split_data, "split_at_cutoff", leaky_post_kev_split)

    with pytest.raises(ValueError, match="post_kev"):
        main(settings, cutoffs=(CUTOFF,))

    # The full cohort passed, but nothing is saved for any cohort
    assert not (processed / "splits").exists()


# --- Cohorts and the small-train warning --------------------------------------


def test_check_rows_in_cohort_fails_on_a_row_from_before_kev():
    table = survival_rows(
        [
            row("CVE-A", "2021-11-03T00:00:00", 5),
            row("CVE-B", "2021-11-02T23:59:59", 5),
        ]
    )

    assert check_rows_in_cohort(table, "full") == 0
    assert check_rows_in_cohort(table, "post_kev") == 1


def test_small_train_warning_fires_below_the_minimum_only():
    train = survival_rows([row(f"CVE-{i}", "2021-12-01", 5, event=1) for i in range(3)])

    assert small_train_warning(train, min_events=3) is None
    warning = small_train_warning(train, min_events=4)
    assert warning is not None
    assert "only 3 train events" in warning


def test_small_train_warning_is_printed_and_recorded_not_dropped(tmp_path, capsys):
    settings = load_settings(tmp_path)
    write_survival_table(settings, MAIN_ROWS)

    # full train: CVE-B is a known event (1 event); post_kev train: CVE-A is
    # re-censored (0 events). With a minimum of 1, only post_kev is too small.
    splits_dir = main(settings, cutoffs=(CUTOFF,), min_train_events=1)

    printed = capsys.readouterr().out
    assert "WARNING [post_kev 2022-01-01]: only 0 train events" in printed
    assert "WARNING [full" not in printed
    summary = pd.read_csv(splits_dir / "split_summary.csv").set_index("cohort")
    assert bool(summary.loc["post_kev", "small_train_warning"]) is True
    assert bool(summary.loc["full", "small_train_warning"]) is False
    assert summary.loc["full", "train_events"] == 1
    assert summary.loc["post_kev", "train_events"] == 0
    # The cut-off is kept: its files are saved
    assert (splits_dir / "post_kev" / "train_2022-01-01.csv").exists()
