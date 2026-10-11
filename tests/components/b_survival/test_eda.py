"""Tests for the EDA calculations. They use small made-up tables, not the real files.

The figures are not tested: they only draw the numbers that are tested here.
"""

from datetime import date

import pandas as pd
import pytest

from vesper.components.b_survival.eda import (
    build_study_table,
    cves_per_year,
    describe_days,
    event_rate,
    exploit_shares,
    kev_match,
    kev_timing_checks,
    main,
    published_since,
)
from vesper.config import load_settings

STUDY_START = date(2016, 1, 1)
SNAPSHOT = date(2026, 10, 1)
KEV_START = date(2021, 11, 3)


def table(columns, rows):
    """A made-up table. The second column holds dates, which are read as UTC."""
    frame = pd.DataFrame(rows, columns=columns)
    frame[columns[1]] = pd.to_datetime(frame[columns[1]], utc=True)
    return frame


def nvd_table(rows):
    return table(["cve_id", "published_at"], rows)


def kev_table(rows):
    return table(["cve_id", "date_added"], rows)


def exploit_table(rows):
    return table(["cve_id", "date_published"], rows)


def study_table(nvd_rows, kev_rows=(), exploit_rows=()):
    return build_study_table(
        nvd_table(list(nvd_rows)),
        kev_table(list(kev_rows)),
        exploit_table(list(exploit_rows)),
        STUDY_START,
        SNAPSHOT,
    )


# --- The study window --------------------------------------------------------


def test_only_cves_published_inside_the_study_window_are_kept():
    study = study_table(
        [
            ("CVE-2015-0001", "2015-12-31T23:59:59"),  # the day before the study starts
            ("CVE-2016-0001", "2016-01-01T00:00:00"),  # the first day
            ("CVE-2026-0001", "2026-10-01T23:59:59"),  # the snapshot day itself
            ("CVE-2026-0002", "2026-10-02T00:00:00"),  # the day after the snapshot
        ]
    )

    assert list(study["cve_id"]) == ["CVE-2016-0001", "CVE-2026-0001"]
    assert list(study["year"]) == [2016, 2026]


def test_kev_listing_after_the_snapshot_is_not_counted():
    study = study_table(
        [("CVE-2026-0001", "2026-09-01T10:00:00"), ("CVE-2026-0002", "2026-09-01T10:00:00")],
        kev_rows=[("CVE-2026-0001", "2026-10-01"), ("CVE-2026-0002", "2026-10-02")],
    )

    assert list(study["in_kev"]) == [True, False]


def test_exploit_after_the_snapshot_is_not_counted():
    study = study_table(
        [("CVE-2026-0001", "2026-09-01T10:00:00")],
        exploit_rows=[("CVE-2026-0001", "2026-10-02")],
    )

    assert list(study["has_exploit"]) == [False]


# --- Days to KEV -------------------------------------------------------------


def test_days_to_kev_are_counted_between_calendar_days():
    study = study_table(
        [
            ("CVE-2024-0001", "2024-05-01T18:30:00"),  # listed the same day, earlier hour
            ("CVE-2024-0002", "2024-05-01T18:30:00"),
            ("CVE-2024-0003", "2024-05-01T18:30:00"),  # listed before publication
            ("CVE-2024-0004", "2024-05-01T18:30:00"),  # not in KEV
        ],
        kev_rows=[
            ("CVE-2024-0001", "2024-05-01"),
            ("CVE-2024-0002", "2024-05-11"),
            ("CVE-2024-0003", "2024-04-28"),
        ],
    )

    days = study.set_index("cve_id")["days_to_kev"]
    assert days["CVE-2024-0001"] == 0
    assert days["CVE-2024-0002"] == 10
    assert days["CVE-2024-0003"] == -3
    assert pd.isna(days["CVE-2024-0004"])


def test_describe_days_gives_the_five_numbers():
    assert describe_days([0, 10, 20, 30, 40]) == {
        "count": 5,
        "min": 0.0,
        "q25": 10.0,
        "median": 20.0,
        "q75": 30.0,
        "max": 40.0,
    }


def test_describe_days_ignores_empty_values_and_handles_no_values():
    assert describe_days([5, None, 15])["median"] == 10.0
    assert describe_days([5, None, 15])["count"] == 2
    assert describe_days([]) == {
        "count": 0,
        "min": None,
        "q25": None,
        "median": None,
        "q75": None,
        "max": None,
    }


def test_kev_timing_checks_count_the_special_groups():
    study = study_table(
        [
            ("CVE-2020-0001", "2020-03-01T00:00:00"),  # old CVE, listed the day KEV started
            ("CVE-2022-0001", "2022-03-10T00:00:00"),  # listed before publication
            ("CVE-2022-0002", "2022-03-10T12:00:00"),  # listed on the publication day
            ("CVE-2022-0003", "2022-03-10T00:00:00"),  # listed later
            ("CVE-2022-0004", "2022-03-10T00:00:00"),  # not in KEV
        ],
        kev_rows=[
            ("CVE-2020-0001", "2021-11-03"),
            ("CVE-2022-0001", "2022-03-01"),
            ("CVE-2022-0002", "2022-03-10"),
            ("CVE-2022-0003", "2022-06-01"),
        ],
    )

    assert kev_timing_checks(study, KEV_START) == {
        "listed before publication (negative days)": 1,
        "listed on the publication day (0 days)": 1,
        "listed on the KEV start date": 1,
    }


def test_published_since_keeps_the_given_day_and_later():
    study = study_table(
        [
            ("CVE-2021-0001", "2021-11-02T23:00:00"),
            ("CVE-2021-0002", "2021-11-03T00:00:00"),
            ("CVE-2022-0001", "2022-01-01T00:00:00"),
        ]
    )

    assert list(published_since(study, KEV_START)["cve_id"]) == ["CVE-2021-0002", "CVE-2022-0001"]


# --- Per year, match and event rate ------------------------------------------


def test_cves_per_year_counts_cves_and_kev_cves():
    study = study_table(
        [
            ("CVE-2020-0001", "2020-02-01T00:00:00"),
            ("CVE-2020-0002", "2020-03-01T00:00:00"),
            ("CVE-2020-0003", "2020-04-01T00:00:00"),
            ("CVE-2020-0004", "2020-05-01T00:00:00"),
            ("CVE-2021-0001", "2021-02-01T00:00:00"),
        ],
        kev_rows=[("CVE-2020-0001", "2022-01-01")],
    )

    per_year = cves_per_year(study)

    assert per_year["cves"].to_dict() == {2020: 4, 2021: 1}
    assert per_year["in_kev"].to_dict() == {2020: 1, 2021: 0}
    assert per_year["percent_in_kev"].to_dict() == {2020: 25.0, 2021: 0.0}


def test_kev_match_gives_a_reason_for_every_kev_cve():
    nvd = nvd_table(
        [
            ("CVE-2015-0001", "2015-06-01T00:00:00"),  # in the NVD table, before the study
            ("CVE-2020-0001", "2020-06-01T00:00:00"),
            ("CVE-2026-0001", "2026-10-03T00:00:00"),  # published after the snapshot
        ]
    )
    kev = kev_table(
        [
            ("CVE-2020-0001", "2022-01-01"),
            ("CVE-2015-0001", "2022-01-01"),
            ("CVE-2026-0001", "2026-09-30"),
            ("CVE-2012-0001", "2022-01-01"),  # older than the NVD download (starts in 2015)
            ("CVE-2021-0001", "2022-01-01"),  # missing for another reason
            ("CVE-2020-0002", "2026-10-05"),  # listed after the snapshot: not counted at all
        ]
    )

    match = kev_match(nvd, kev, STUDY_START, SNAPSHOT)

    assert list(match.values()) == [1, 1, 1, 1, 1]
    assert match["in the study"] == 1
    assert match["not in the study: published before STUDY_START"] == 1
    assert match["not in the study: published after SNAPSHOT_DATE"] == 1
    # Every KEV CVE listed up to the snapshot has exactly one reason
    assert sum(match.values()) == 5


def test_event_rate_is_the_percent_of_study_cves_in_kev():
    study = study_table(
        [(f"CVE-2020-000{i}", "2020-02-01T00:00:00") for i in range(1, 5)],
        kev_rows=[("CVE-2020-0001", "2022-01-01")],
    )

    assert event_rate(study) == 25.0


# --- Exploit code ------------------------------------------------------------


def test_exploit_by_publication_uses_the_earliest_exploit():
    study = study_table(
        [
            ("CVE-2020-0001", "2020-06-10T15:00:00"),  # exploit before publication
            ("CVE-2020-0002", "2020-06-10T15:00:00"),  # exploit on the publication day
            ("CVE-2020-0003", "2020-06-10T15:00:00"),  # exploit only after publication
            ("CVE-2020-0004", "2020-06-10T15:00:00"),  # two exploits; the earliest counts
            ("CVE-2020-0005", "2020-06-10T15:00:00"),  # no exploit
        ],
        exploit_rows=[
            ("CVE-2020-0001", "2020-06-01"),
            ("CVE-2020-0002", "2020-06-10"),
            ("CVE-2020-0003", "2020-06-11"),
            ("CVE-2020-0004", "2020-08-01"),
            ("CVE-2020-0004", "2020-06-05"),
        ],
    )

    assert list(study["has_exploit"]) == [True, True, True, True, False]
    assert list(study["exploit_by_publication"]) == [True, True, False, True, False]
    assert len(study) == 5  # two exploits do not make two rows


def test_exploit_shares_among_kev_cves_and_all_cves():
    study = study_table(
        [(f"CVE-2020-000{i}", "2020-06-10T00:00:00") for i in range(1, 9)],
        kev_rows=[("CVE-2020-0001", "2021-12-01"), ("CVE-2020-0002", "2021-12-01")],
        exploit_rows=[
            ("CVE-2020-0001", "2020-06-01"),  # KEV, exploit before publication
            ("CVE-2020-0003", "2020-07-01"),  # not KEV, exploit after publication
        ],
    )

    shares = exploit_shares(study)

    kev_row = shares.loc["KEV CVEs"]
    assert kev_row["cves"] == 2
    assert kev_row["with_any_exploit"] == 1
    assert kev_row["percent_with_any_exploit"] == 50.0
    assert kev_row["with_exploit_by_publication"] == 1
    all_row = shares.loc["all CVEs"]
    assert all_row["cves"] == 8
    assert all_row["with_any_exploit"] == 2
    assert all_row["percent_with_any_exploit"] == 25.0
    assert all_row["with_exploit_by_publication"] == 1
    assert all_row["percent_with_exploit_by_publication"] == pytest.approx(12.5)


# --- The whole run -----------------------------------------------------------


def test_main_writes_figures_and_summary_to_outputs_and_no_joined_table(tmp_path):
    # A made-up project folder, so the real data and outputs are never touched
    settings = load_settings(tmp_path)
    processed = settings.data_processed / "b_survival"
    processed.mkdir(parents=True)
    pd.DataFrame(
        {
            "cve_id": ["CVE-2022-0001", "CVE-2022-0002"],
            "published_at": ["2022-03-01T10:00:00.000000Z", "2022-04-01T10:00:00.000000Z"],
        }
    ).to_csv(processed / "nvd_clean.csv", index=False)
    pd.DataFrame({"cve_id": ["CVE-2022-0001"], "date_added": ["2022-03-11T00:00:00Z"]}).to_csv(
        processed / "kev_clean.csv", index=False
    )
    pd.DataFrame({"cve_id": ["CVE-2022-0001"], "date_published": ["2022-03-05T00:00:00Z"]}).to_csv(
        processed / "exploitdb_clean.csv", index=False
    )

    output_dir = main(settings)

    assert output_dir == tmp_path / "outputs" / "b_survival" / "eda"
    assert sorted(path.name for path in output_dir.iterdir()) == [
        "01_cves_per_year.png",
        "02_days_to_kev.png",
        "03_days_to_kev_published_since_kev_start.png",
        "eda_summary.csv",
    ]
    summary = pd.read_csv(output_dir / "eda_summary.csv", dtype=str)
    assert list(summary.columns) == ["section", "measure", "value"]
    values = summary.set_index("measure")["value"]
    assert values["days, median"].iloc[0] == "10"
    assert values["percent in KEV"] == "50"
    # Nothing new was written next to the clean tables
    assert sorted(path.name for path in processed.iterdir()) == [
        "exploitdb_clean.csv",
        "kev_clean.csv",
        "nvd_clean.csv",
    ]
