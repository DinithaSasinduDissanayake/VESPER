"""Tests for clean_kev. They use small made-up records, not the real KEV file."""

import json
from datetime import date

import pandas as pd

from vesper.components.b_survival.clean_kev import clean_kev, main
from vesper.config import load_settings

SNAPSHOT = date(2026, 10, 1)


def kev_record(cve_id, date_added):
    """One made-up KEV record, with an extra field that must not be kept."""
    return {"cveID": cve_id, "dateAdded": date_added, "vendorProject": "Example"}


def test_keeps_only_the_id_and_the_date_with_two_flags():
    table, _ = clean_kev([kev_record("CVE-2024-1111", "2024-05-01")], SNAPSHOT)

    assert list(table.columns) == [
        "cve_id",
        "date_added",
        "added_on_kev_start_date",
        "after_snapshot",
    ]


def test_date_is_read_as_utc():
    table, _ = clean_kev([kev_record("CVE-2024-1111", "2024-05-01")], SNAPSHOT)

    assert table.loc[0, "date_added"] == pd.Timestamp("2024-05-01", tz="UTC")


def test_cve_id_is_trimmed_and_upper_cased_before_the_check():
    table, report = clean_kev([kev_record(" cve-2024-1111 ", "2024-05-01")], SNAPSHOT)

    assert list(table["cve_id"]) == ["CVE-2024-1111"]
    assert report["removed_invalid_cve_id"] == 0


def test_invalid_or_missing_cve_id_is_removed_and_counted():
    records = [
        kev_record("CVE-2024-1111", "2024-05-01"),
        kev_record("CVE-2024-12", "2024-05-01"),  # too few digits
        kev_record("not a cve", "2024-05-01"),
        kev_record(None, "2024-05-01"),
    ]

    table, report = clean_kev(records, SNAPSHOT)

    assert list(table["cve_id"]) == ["CVE-2024-1111"]
    assert report["rows_before"] == 4
    assert report["removed_invalid_cve_id"] == 3
    assert report["rows_after"] == 1


def test_unreadable_or_missing_date_is_removed_and_counted():
    records = [
        kev_record("CVE-2024-1111", "2024-05-01"),
        kev_record("CVE-2024-2222", "01/05/2024"),
        kev_record("CVE-2024-3333", None),
    ]

    table, report = clean_kev(records, SNAPSHOT)

    assert list(table["cve_id"]) == ["CVE-2024-1111"]
    assert report["removed_unreadable_date"] == 2


def test_duplicate_cve_keeps_the_earliest_date_and_is_reported():
    records = [
        kev_record("CVE-2024-1111", "2024-06-10"),
        kev_record("CVE-2024-1111", "2024-05-01"),
        kev_record("CVE-2024-2222", "2024-07-01"),
        kev_record("CVE-2024-2222", "2024-07-01"),
    ]

    table, report = clean_kev(records, SNAPSHOT)

    assert list(table["cve_id"]) == ["CVE-2024-1111", "CVE-2024-2222"]
    assert table.loc[0, "date_added"] == pd.Timestamp("2024-05-01", tz="UTC")
    assert report["cves_listed_more_than_once"] == 2
    assert report["removed_duplicate_cve"] == 2
    # Only CVE-2024-1111 was listed with two different dates
    assert report["cves_with_conflicting_dates"] == 1


def test_kev_start_date_is_flagged():
    records = [
        kev_record("CVE-2020-1111", "2021-11-03"),
        kev_record("CVE-2020-2222", "2021-11-04"),
    ]

    table, report = clean_kev(records, SNAPSHOT)

    assert list(table["added_on_kev_start_date"]) == [True, False]
    assert report["flagged_added_on_kev_start_date"] == 1


def test_date_after_snapshot_is_flagged_but_not_removed():
    records = [
        kev_record("CVE-2026-1111", "2026-09-30"),
        kev_record("CVE-2026-2222", "2026-10-01"),  # the snapshot day itself is allowed
        kev_record("CVE-2026-3333", "2026-10-02"),
    ]

    table, report = clean_kev(records, SNAPSHOT)

    assert len(table) == 3
    assert list(table["after_snapshot"]) == [False, False, True]
    assert report["flagged_after_snapshot"] == 1


def test_counts_in_the_report_add_up():
    records = [
        kev_record("CVE-2024-1111", "2024-05-01"),
        kev_record("CVE-2024-1111", "2024-05-01"),
        kev_record("bad", "2024-05-01"),
        kev_record("CVE-2024-2222", "bad"),
    ]

    _, report = clean_kev(records, SNAPSHOT)

    removed = (
        report["removed_invalid_cve_id"]
        + report["removed_unreadable_date"]
        + report["removed_duplicate_cve"]
    )
    assert report["rows_before"] - removed == report["rows_after"]


def test_empty_catalogue_gives_an_empty_table():
    table, report = clean_kev([], SNAPSHOT)

    assert len(table) == 0
    assert report["rows_before"] == 0
    assert report["rows_after"] == 0


def test_main_writes_the_csv_in_the_component_processed_folder(tmp_path):
    # A made-up project folder, so the real data is never touched
    settings = load_settings(tmp_path)
    raw_dir = settings.raw_source("kev")
    raw_dir.mkdir(parents=True)
    catalogue = {"vulnerabilities": [kev_record("CVE-2020-1111", "2021-11-03")]}
    (raw_dir / "kev_2026-10-01.json").write_text(json.dumps(catalogue), encoding="utf-8")

    output_path = main(settings)

    assert output_path == tmp_path / "data" / "processed" / "b_survival" / "kev_clean.csv"
    saved = pd.read_csv(output_path)
    assert saved.loc[0, "cve_id"] == "CVE-2020-1111"
    assert saved.loc[0, "date_added"] == "2021-11-03T00:00:00Z"
    assert bool(saved.loc[0, "added_on_kev_start_date"]) is True
    assert bool(saved.loc[0, "after_snapshot"]) is False
