"""Tests for survival_table. They use small made-up tables, not the real files."""

from datetime import date

import pandas as pd
import pytest

from vesper.components.b_survival.eda import build_study_table
from vesper.components.b_survival.link_sources import link_sources
from vesper.components.b_survival.survival_table import (
    INPUT_COLUMNS,
    OUTPUT_COLUMNS,
    build_survival_table,
    check_duration_not_negative,
    check_event_is_zero_or_one,
    check_no_duplicate_cve_ids,
    check_no_publication_after_snapshot,
    check_row_count,
    main,
    run_checks,
    summarize,
)
from vesper.config import load_settings

SNAPSHOT = date(2026, 10, 1)
STUDY_START = date(2016, 1, 1)


def linked_table(rows):
    """A made-up linked table (the output of link_sources).

    A row is (cve_id, published_at, kev_date_added, first_exploit_date).
    An empty kev_date_added means "not in KEV".
    """
    table = pd.DataFrame(
        rows, columns=["cve_id", "published_at", "kev_date_added", "first_exploit_date"]
    )
    for column in ("published_at", "kev_date_added", "first_exploit_date"):
        table[column] = pd.to_datetime(table[column], format="ISO8601", utc=True)
    table["in_kev"] = table["kev_date_added"].notna()
    table["added_on_kev_start_date"] = table["kev_date_added"] == pd.Timestamp(
        "2021-11-03", tz="UTC"
    )
    table["cvss_base_score"] = 7.5
    table["cvss_attack_vector"] = "NETWORK"
    table["cvss_attack_complexity"] = "LOW"
    table["cvss_privileges_required"] = "NONE"
    table["cvss_user_interaction"] = "NONE"
    table["cvss_missing"] = False
    table["cvss_is_primary"] = pd.array([True] * len(table), dtype="boolean")
    table["cwe_ids"] = "CWE-79"
    return table


def build(rows):
    return build_survival_table(linked_table(rows), SNAPSHOT)


def by_cve(table):
    return table.set_index("cve_id")


# --- Duration and event ------------------------------------------------------


def test_listed_cve_stops_at_the_kev_day_and_is_an_event():
    table = by_cve(build([("CVE-2022-0001", "2022-03-01T18:30:00", "2022-03-11", None)]))

    assert table.loc["CVE-2022-0001", "duration_days"] == 10
    assert table.loc["CVE-2022-0001", "event"] == 1


def test_unlisted_cve_stops_at_the_snapshot_and_is_censored():
    table = by_cve(build([("CVE-2026-0001", "2026-09-21T23:00:00", None, None)]))

    # From 2026-09-21 to 2026-10-01 is 10 calendar days
    assert table.loc["CVE-2026-0001", "duration_days"] == 10
    assert table.loc["CVE-2026-0001", "event"] == 0


def test_zero_day_duration_stays_an_event_with_duration_zero():
    table = by_cve(build([("CVE-2022-0001", "2022-03-01T18:30:00", "2022-03-01", None)]))

    assert table.loc["CVE-2022-0001", "duration_days"] == 0
    assert table.loc["CVE-2022-0001", "event"] == 1
    assert not table.loc["CVE-2022-0001", "already_exploited"]


def test_listed_before_publication_is_kept_flagged_and_not_clipped():
    table = by_cve(build([("CVE-2022-0001", "2022-03-10T00:00:00", "2022-03-01", None)]))

    assert table.loc["CVE-2022-0001", "duration_days"] == -9
    assert table.loc["CVE-2022-0001", "event"] == 1
    assert table.loc["CVE-2022-0001", "already_exploited"]


def test_cve_published_on_the_snapshot_day_has_duration_zero_and_is_censored():
    table = by_cve(build([("CVE-2026-0001", "2026-10-01T09:00:00", None, None)]))

    assert table.loc["CVE-2026-0001", "duration_days"] == 0
    assert table.loc["CVE-2026-0001", "event"] == 0


def test_kev_launch_group_is_the_kev_start_date():
    table = by_cve(
        build(
            [
                ("CVE-2020-0001", "2020-01-01", "2021-11-03", None),
                ("CVE-2020-0002", "2020-01-01", "2021-11-04", None),
                ("CVE-2020-0003", "2020-01-01", None, None),
            ]
        )
    )

    assert table["kev_launch_group"].to_dict() == {
        "CVE-2020-0001": True,
        "CVE-2020-0002": False,
        "CVE-2020-0003": False,
    }


def test_duration_and_event_agree_with_the_eda_module():
    # The same made-up CVEs go through eda.py and through the survival table
    nvd = pd.DataFrame(
        {
            "cve_id": ["CVE-2022-0001", "CVE-2022-0002", "CVE-2022-0003", "CVE-2022-0004"],
            "published_at": pd.to_datetime(
                ["2022-03-01T18:30:00", "2022-03-10T00:00:00", "2022-03-01T05:00:00", "2026-09-01"],
                format="ISO8601",
                utc=True,
            ),
            "after_snapshot": False,
        }
    )
    kev = pd.DataFrame(
        {
            "cve_id": ["CVE-2022-0001", "CVE-2022-0002", "CVE-2022-0003"],
            "date_added": pd.to_datetime(["2022-03-11", "2022-03-01", "2022-03-01"], utc=True),
            "added_on_kev_start_date": False,
            "after_snapshot": False,
        }
    )
    nvd["cvss_base_score"] = 5.0
    for column in ("cvss_attack_vector", "cvss_attack_complexity", "cvss_privileges_required"):
        nvd[column] = "LOW"
    nvd["cvss_user_interaction"] = "NONE"
    nvd["cvss_missing"] = False
    nvd["cvss_is_primary"] = True
    nvd["cwe_ids"] = None
    exploits = pd.DataFrame(
        {
            "cve_id": pd.Series(dtype="object"),
            "exploit_id": pd.Series(dtype="object"),
            "date_published": pd.Series(dtype="datetime64[ns, UTC]"),
            "after_snapshot": pd.Series(dtype="bool"),
        }
    )

    linked, _ = link_sources(nvd, kev, [exploits], STUDY_START)
    table = build_survival_table(linked, SNAPSHOT).set_index("cve_id")

    eda_nvd = nvd[["cve_id", "published_at"]]
    eda_kev = kev[["cve_id", "date_added"]]
    eda_exploits = exploits[["cve_id", "date_published"]]
    eda = build_study_table(eda_nvd, eda_kev, eda_exploits, STUDY_START, SNAPSHOT)
    eda = eda.set_index("cve_id")

    for cve_id in eda.index:
        in_kev = bool(eda.loc[cve_id, "in_kev"])
        assert table.loc[cve_id, "event"] == int(in_kev)
        if in_kev:
            assert table.loc[cve_id, "duration_days"] == eda.loc[cve_id, "days_to_kev"]


# --- Day-0 inputs and leakage ------------------------------------------------


def test_exploit_at_publication_is_true_only_for_an_exploit_on_or_before_publication():
    table = by_cve(
        build(
            [
                ("CVE-2020-0001", "2020-06-10T15:00:00", None, "2020-06-01"),  # before
                ("CVE-2020-0002", "2020-06-10T15:00:00", None, "2020-06-10"),  # same day
                ("CVE-2020-0003", "2020-06-10T15:00:00", None, "2020-06-11"),  # after
                ("CVE-2020-0004", "2020-06-10T15:00:00", None, None),  # no exploit
            ]
        )
    )

    assert table["exploit_at_publication"].to_dict() == {
        "CVE-2020-0001": True,
        "CVE-2020-0002": True,
        "CVE-2020-0003": False,
        "CVE-2020-0004": False,
    }


def test_exploit_first_date_is_kept_as_a_day_and_empty_when_there_is_no_exploit():
    table = by_cve(
        build(
            [
                ("CVE-2020-0001", "2020-06-10", None, "2020-08-01T13:00:00"),
                ("CVE-2020-0002", "2020-06-10", None, None),
            ]
        )
    )

    assert table.loc["CVE-2020-0001", "exploit_first_date"] == pd.Timestamp("2020-08-01", tz="UTC")
    assert pd.isna(table.loc["CVE-2020-0002", "exploit_first_date"])


def test_there_is_no_plain_has_any_exploit_column():
    table = build([("CVE-2020-0001", "2020-06-10", None, "2020-08-01")])

    # An exploit that appears later would leak the future into the inputs
    assert not any(
        "has" in column or "any_exploit" in column or column == "exploit_count"
        for column in table.columns
    )
    assert "kev_date_added" not in table.columns
    assert list(table.columns) == OUTPUT_COLUMNS


def test_input_columns_do_not_change_when_the_kev_date_changes():
    rows = [
        ("CVE-2022-0001", "2022-03-01T18:30:00", "2022-03-11", "2022-03-05"),
        ("CVE-2022-0002", "2022-03-10T00:00:00", "2021-11-03", None),
        ("CVE-2022-0003", "2022-03-01T05:00:00", None, "2022-04-01"),
    ]
    original = linked_table(rows)
    changed = original.copy()
    # Move every KEV date, and add or remove listings
    changed["kev_date_added"] = pd.to_datetime(["2023-07-07", "2022-03-01", "2022-05-05"], utc=True)
    changed["in_kev"] = [False, True, True]
    changed["added_on_kev_start_date"] = [True, False, False]

    before = build_survival_table(original, SNAPSHOT)
    after = build_survival_table(changed, SNAPSHOT)

    # The outcome columns do change ...
    assert not before["duration_days"].equals(after["duration_days"])
    assert not before["event"].equals(after["event"])
    # ... but every input and the time-varying column stay exactly the same
    pd.testing.assert_frame_equal(before[INPUT_COLUMNS], after[INPUT_COLUMNS])
    pd.testing.assert_series_equal(before["exploit_first_date"], after["exploit_first_date"])


# --- Checks ------------------------------------------------------------------


def good_table():
    return build(
        [
            ("CVE-2022-0001", "2022-03-01", "2022-03-11", None),
            ("CVE-2022-0002", "2022-03-10", "2022-03-01", None),  # already exploited
            ("CVE-2022-0003", "2022-03-01", None, None),
        ]
    )


def test_a_good_table_passes_every_check():
    checks = run_checks(good_table(), expected_rows=3, snapshot_date=SNAPSHOT)

    assert set(checks.values()) == {0}
    assert len(checks) == 5


def test_check_no_duplicate_cve_ids():
    table = good_table()
    assert check_no_duplicate_cve_ids(table) == 0

    table.loc[2, "cve_id"] = "CVE-2022-0001"
    assert check_no_duplicate_cve_ids(table) == 2  # both rows of the repeated ID


def test_check_event_is_zero_or_one():
    table = good_table()
    assert check_event_is_zero_or_one(table) == 0

    table.loc[0, "event"] = 2
    assert check_event_is_zero_or_one(table) == 1


def test_check_no_publication_after_snapshot():
    table = good_table()
    assert check_no_publication_after_snapshot(table, SNAPSHOT) == 0

    table.loc[0, "published_at"] = pd.Timestamp("2026-10-02T00:00:00", tz="UTC")
    assert check_no_publication_after_snapshot(table, SNAPSHOT) == 1
    # The snapshot day itself is allowed
    table.loc[0, "published_at"] = pd.Timestamp("2026-10-01T23:59:59", tz="UTC")
    assert check_no_publication_after_snapshot(table, SNAPSHOT) == 0


def test_check_duration_not_negative_ignores_already_exploited_rows():
    table = good_table()
    # CVE-2022-0002 has a negative duration but is flagged: allowed
    assert (table["duration_days"] < 0).sum() == 1
    assert check_duration_not_negative(table) == 0

    table.loc[0, "duration_days"] = -5  # negative and not flagged: a problem
    assert check_duration_not_negative(table) == 1


def test_check_row_count():
    table = good_table()
    assert check_row_count(table, 3) == 0
    assert check_row_count(table, 5) == 2


# --- Summary and the whole run -----------------------------------------------


def test_summary_counts():
    table = build(
        [
            ("CVE-2020-0001", "2020-01-01", "2021-11-03", "2019-12-01"),  # launch, exploit before
            ("CVE-2022-0002", "2022-03-10", "2022-03-01", None),  # already exploited
            ("CVE-2022-0003", "2022-03-01", "2022-03-01", None),  # zero day
            ("CVE-2022-0004", "2022-03-01", None, "2022-03-01"),  # censored, exploit same day
        ]
    )

    summary = summarize(table)

    assert summary["rows"] == 4
    assert summary["events"] == 3
    assert summary["censored"] == 1
    assert summary["already_exploited"] == 1
    assert summary["kev_launch_group"] == 1
    assert summary["zero_day_events"] == 1
    assert summary["percent_exploit_at_publication_among_events"] == pytest.approx(100 / 3)
    assert summary["percent_exploit_at_publication_among_all"] == 50.0
    # Durations of the events: 672 (worked out here with dates), -9 and 0
    launch_days = (date(2021, 11, 3) - date(2020, 1, 1)).days
    assert launch_days == 672
    assert summary["median_duration_events"] == 0
    assert summary["median_duration_events_not_already_exploited"] == launch_days / 2


def test_main_writes_the_survival_table_and_stops_when_a_check_fails(tmp_path):
    # A made-up project folder, so the real data is never touched
    settings = load_settings(tmp_path)
    processed = settings.data_processed / "b_survival"
    processed.mkdir(parents=True)
    pd.DataFrame(
        {
            "cve_id": ["CVE-2022-0001", "CVE-2022-0002", "CVE-2015-0001"],
            "published_at": [
                "2022-03-01T10:00:00.000000Z",
                "2022-04-01T10:00:00.000000Z",
                "2015-04-01T10:00:00.000000Z",
            ],
            "last_modified_at": ["2022-05-01T10:00:00.000000Z"] * 3,
            "cvss_base_score": [9.8, None, 5.0],
            "cvss_version": ["3.1", None, "3.0"],
            "cvss_missing": [False, True, False],
            "cvss_is_primary": [True, None, False],
            "cvss_attack_vector": ["NETWORK", None, "LOCAL"],
            "cvss_attack_complexity": ["LOW", None, "LOW"],
            "cvss_privileges_required": ["NONE", None, "LOW"],
            "cvss_user_interaction": ["NONE", None, "NONE"],
            "cwe_ids": ["CWE-79", None, "CWE-89"],
            "after_snapshot": [False, False, False],
        }
    ).to_csv(processed / "nvd_clean.csv", index=False)
    pd.DataFrame(
        {
            "cve_id": ["CVE-2022-0001"],
            "date_added": ["2022-03-11T00:00:00Z"],
            "added_on_kev_start_date": [False],
            "after_snapshot": [False],
        }
    ).to_csv(processed / "kev_clean.csv", index=False)
    pd.DataFrame(
        {
            "exploit_id": ["55"],
            "cve_id": ["CVE-2022-0001"],
            "date_published": ["2022-03-05T00:00:00Z"],
            "after_snapshot": [False],
        }
    ).to_csv(processed / "exploitdb_clean.csv", index=False)

    output_path = main(settings)

    assert output_path == processed / "survival_table.csv"
    saved = pd.read_csv(output_path, dtype={"exploit_first_date": "str"})
    assert list(saved.columns) == OUTPUT_COLUMNS
    # The 2015 CVE is outside the study window
    assert list(saved["cve_id"]) == ["CVE-2022-0001", "CVE-2022-0002"]
    assert list(saved["event"]) == [1, 0]
    assert saved.loc[0, "duration_days"] == 10
    assert saved.loc[0, "exploit_first_date"] == "2022-03-05"
    assert pd.isna(saved.loc[1, "exploit_first_date"])
    assert saved.loc[0, "published_at"] == "2022-03-01T10:00:00.000000Z"
