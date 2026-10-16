"""Tests for link_sources. They use small made-up tables, not the real files."""

from datetime import date

import pandas as pd
import pytest

from vesper.components.b_survival.link_sources import (
    REASON_AFTER_SNAPSHOT,
    REASON_BEFORE_START,
    REASON_OLD_ID,
    REASON_OTHER,
    explain_unmatched,
    first_exploit_dates,
    link_sources,
    main,
)
from vesper.config import load_settings

STUDY_START = date(2016, 1, 1)


def nvd_table(rows):
    """Made-up NVD table. A row is (cve_id, published_at, after_snapshot)."""
    table = pd.DataFrame(rows, columns=["cve_id", "published_at", "after_snapshot"])
    table["published_at"] = pd.to_datetime(table["published_at"], utc=True)
    table["cvss_base_score"] = 7.5
    return table


def kev_table(rows):
    """Made-up KEV table. A row is (cve_id, date_added, after_snapshot)."""
    table = pd.DataFrame(rows, columns=["cve_id", "date_added", "after_snapshot"])
    table["date_added"] = pd.to_datetime(table["date_added"], utc=True)
    table["added_on_kev_start_date"] = table["date_added"] == pd.Timestamp("2021-11-03", tz="UTC")
    return table


def exploit_table(rows):
    """Made-up exploit table. A row is (exploit_id, cve_id, date_published, after_snapshot)."""
    table = pd.DataFrame(rows, columns=["exploit_id", "cve_id", "date_published", "after_snapshot"])
    table["date_published"] = pd.to_datetime(table["date_published"], utc=True)
    return table


def link(nvd_rows, kev_rows=(), exploit_rows=()):
    return link_sources(
        nvd_table(list(nvd_rows)),
        kev_table(list(kev_rows)),
        [exploit_table(list(exploit_rows))],
        STUDY_START,
    )


# --- The study window and the base table -------------------------------------


def test_only_cves_inside_the_study_window_are_kept():
    linked, report = link(
        [
            ("CVE-2015-0001", "2015-12-31T23:59:59", False),  # before STUDY_START
            ("CVE-2016-0001", "2016-01-01T00:00:00", False),  # the first day
            ("CVE-2026-0001", "2026-10-01T23:00:00", False),  # the snapshot day
            ("CVE-2026-0002", "2026-10-02T00:00:00", True),  # after the snapshot
        ]
    )

    assert list(linked["cve_id"]) == ["CVE-2016-0001", "CVE-2026-0001"]
    assert report["nvd_rows"] == 4
    assert report["study_cves"] == 2


def test_nvd_columns_are_kept_and_there_is_one_row_per_cve():
    linked, _ = link(
        [("CVE-2020-0001", "2020-01-01", False), ("CVE-2020-0002", "2020-01-02", False)],
        kev_rows=[("CVE-2020-0001", "2022-01-01", False)],
        exploit_rows=[
            ("1", "CVE-2020-0001", "2020-02-01", False),
            ("2", "CVE-2020-0001", "2020-03-01", False),
        ],
    )

    assert linked["cve_id"].is_unique
    assert list(linked["cvss_base_score"]) == [7.5, 7.5]


# --- KEV ---------------------------------------------------------------------


def test_kev_is_attached_with_a_left_join():
    linked, report = link(
        [("CVE-2020-0001", "2020-01-01", False), ("CVE-2020-0002", "2020-01-02", False)],
        kev_rows=[("CVE-2020-0001", "2021-11-03", False)],
    )

    row = linked.set_index("cve_id")
    assert bool(row.loc["CVE-2020-0001", "in_kev"]) is True
    assert row.loc["CVE-2020-0001", "kev_date_added"] == pd.Timestamp("2021-11-03", tz="UTC")
    assert bool(row.loc["CVE-2020-0001", "added_on_kev_start_date"]) is True
    assert bool(row.loc["CVE-2020-0002", "in_kev"]) is False
    assert pd.isna(row.loc["CVE-2020-0002", "kev_date_added"])
    assert bool(row.loc["CVE-2020-0002", "added_on_kev_start_date"]) is False
    assert report["kev_matched"] == 1


def test_kev_listing_after_the_snapshot_is_not_used():
    linked, report = link(
        [("CVE-2026-0001", "2026-09-01", False)],
        kev_rows=[("CVE-2026-0001", "2026-10-02", True)],
    )

    assert list(linked["in_kev"]) == [False]
    assert report["kev_rows_up_to_snapshot"] == 0


def test_unmatched_kev_cves_get_a_reason():
    nvd = [
        ("CVE-2015-0001", "2015-06-01", False),  # in NVD, before STUDY_START
        ("CVE-2020-0001", "2020-06-01", False),  # in the study
        ("CVE-2026-0001", "2026-10-03", True),  # published after the snapshot
    ]
    kev = [
        ("CVE-2020-0001", "2022-01-01", False),
        ("CVE-2015-0001", "2022-01-01", False),
        ("CVE-2026-0001", "2026-09-30", False),
        ("CVE-2012-0001", "2022-01-01", False),  # older than the NVD download (starts 2015)
        ("CVE-2021-0001", "2022-01-01", False),  # not in NVD for another reason
    ]

    _, report = link(nvd, kev_rows=kev)

    assert report["kev_matched"] == 1
    assert report["kev_unmatched"] == {
        REASON_BEFORE_START: 1,
        REASON_AFTER_SNAPSHOT: 1,
        REASON_OLD_ID: 1,
        REASON_OTHER: 1,
    }
    # Every KEV CVE is either matched or has exactly one reason
    assert report["kev_matched"] + sum(report["kev_unmatched"].values()) == 5


def test_explain_unmatched_with_nothing_to_explain():
    nvd = nvd_table([("CVE-2020-0001", "2020-06-01", False)])

    assert explain_unmatched([], nvd, ["CVE-2020-0001"], STUDY_START) == {
        REASON_BEFORE_START: 0,
        REASON_AFTER_SNAPSHOT: 0,
        REASON_OLD_ID: 0,
        REASON_OTHER: 0,
    }


# --- Exploit code ------------------------------------------------------------


def test_first_exploit_date_is_the_earliest_and_exploits_are_counted():
    exploits = exploit_table(
        [
            ("10", "CVE-2020-0001", "2020-08-01T00:00:00", False),
            ("11", "CVE-2020-0001", "2020-06-05T00:00:00", False),
            ("12", "CVE-2020-0002", "2021-01-01T00:00:00", False),
        ]
    )

    result = first_exploit_dates([exploits]).set_index("cve_id")

    assert result.loc["CVE-2020-0001", "first_exploit_date"] == pd.Timestamp("2020-06-05", tz="UTC")
    assert result.loc["CVE-2020-0001", "exploit_count"] == 2
    assert result.loc["CVE-2020-0002", "exploit_count"] == 1


def test_exploits_after_the_snapshot_are_not_used():
    exploits = exploit_table(
        [
            ("10", "CVE-2026-0001", "2026-09-01", False),
            ("11", "CVE-2026-0001", "2026-10-05", True),
            ("12", "CVE-2026-0002", "2026-10-05", True),
        ]
    )

    result = first_exploit_dates([exploits]).set_index("cve_id")

    assert list(result.index) == ["CVE-2026-0001"]
    assert result.loc["CVE-2026-0001", "exploit_count"] == 1


def test_a_second_source_can_be_added_to_the_list():
    first_source = exploit_table([("10", "CVE-2020-0001", "2020-08-01", False)])
    # The same exploit id in another source is a different exploit
    second_source = exploit_table(
        [("10", "CVE-2020-0001", "2020-05-01", False), ("7", "CVE-2020-0003", "2020-09-01", False)]
    )

    result = first_exploit_dates([first_source, second_source]).set_index("cve_id")

    assert result.loc["CVE-2020-0001", "first_exploit_date"] == pd.Timestamp("2020-05-01", tz="UTC")
    assert result.loc["CVE-2020-0001", "exploit_count"] == 2
    assert result.loc["CVE-2020-0003", "exploit_count"] == 1


def test_no_exploit_tables_gives_an_empty_result():
    assert len(first_exploit_dates([])) == 0
    assert len(first_exploit_dates([exploit_table([])])) == 0


def test_cve_without_an_exploit_has_an_empty_date_and_a_count_of_zero():
    linked, report = link(
        [("CVE-2020-0001", "2020-01-01", False), ("CVE-2020-0002", "2020-01-02", False)],
        exploit_rows=[("1", "CVE-2020-0001", "2020-02-01", False)],
    )

    row = linked.set_index("cve_id")
    assert row.loc["CVE-2020-0001", "exploit_count"] == 1
    assert row.loc["CVE-2020-0002", "exploit_count"] == 0
    assert pd.isna(row.loc["CVE-2020-0002", "first_exploit_date"])
    assert report["exploit_cves_matched"] == 1


def test_unmatched_exploit_cves_get_a_reason():
    _, report = link(
        [("CVE-2015-0001", "2015-06-01", False), ("CVE-2020-0001", "2020-06-01", False)],
        exploit_rows=[
            ("1", "CVE-2020-0001", "2020-07-01", False),
            ("2", "CVE-2015-0001", "2015-07-01", False),
            ("3", "CVE-2010-0001", "2010-07-01", False),
        ],
    )

    assert report["exploit_cves"] == 3
    assert report["exploit_cves_matched"] == 1
    assert report["exploit_unmatched"][REASON_BEFORE_START] == 1
    assert report["exploit_unmatched"][REASON_OLD_ID] == 1


def test_a_cve_twice_in_the_base_table_stops_the_join():
    nvd = nvd_table(
        [("CVE-2020-0001", "2020-01-01", False), ("CVE-2020-0001", "2020-01-01", False)]
    )

    with pytest.raises(pd.errors.MergeError):
        link_sources(nvd, kev_table([("CVE-2020-0001", "2022-01-01", False)]), [], STUDY_START)


def test_the_verified_column_is_never_used():
    exploits = exploit_table([("1", "CVE-2020-0001", "2020-02-01", False)])
    exploits["verified"] = "1"

    result = first_exploit_dates([exploits])

    assert list(result.columns) == ["cve_id", "first_exploit_date", "exploit_count"]


# --- The whole run -----------------------------------------------------------


def test_main_reads_the_clean_files_and_returns_the_linked_table(tmp_path):
    # A made-up project folder, so the real data is never touched
    settings = load_settings(tmp_path)
    processed = settings.data_processed / "b_survival"
    processed.mkdir(parents=True)
    pd.DataFrame(
        {
            "cve_id": ["CVE-2022-0001", "CVE-2022-0002"],
            "published_at": ["2022-03-01T10:00:00.000000Z", "2022-04-01T10:00:00.000000Z"],
            "last_modified_at": ["2022-05-01T10:00:00.000000Z", "2022-05-01T10:00:00.000000Z"],
            "cvss_version": ["3.0", "3.1"],
            "cvss_is_primary": [True, None],
            "after_snapshot": [False, False],
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

    linked, report = main(settings)

    assert list(linked["cve_id"]) == ["CVE-2022-0001", "CVE-2022-0002"]
    assert list(linked["in_kev"]) == [True, False]
    assert list(linked["cvss_version"]) == ["3.0", "3.1"]
    assert report["kev_matched"] == 1
    # Nothing was written: the linked table is only returned
    assert sorted(path.name for path in processed.iterdir()) == [
        "exploitdb_clean.csv",
        "kev_clean.csv",
        "nvd_clean.csv",
    ]
