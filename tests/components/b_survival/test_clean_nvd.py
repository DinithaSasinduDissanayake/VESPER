"""Tests for clean_nvd. They use small made-up records, not the real NVD files."""

import gzip
import json
from datetime import date

import pandas as pd

from vesper.components.b_survival.clean_nvd import (
    clean_nvd,
    collect_cwe_ids,
    main,
    parse_vector,
    pick_cvss,
)
from vesper.config import load_settings

SNAPSHOT = date(2026, 10, 1)

VECTOR_31 = "CVSS:3.1/AV:N/AC:L/PR:L/UI:R/S:C/C:L/I:L/A:N"
VECTOR_30 = "CVSS:3.0/AV:L/AC:H/PR:H/UI:N/S:U/C:H/I:H/A:H"


def cvss_entry(version, score, entry_type="Primary", vector=None):
    """One made-up CVSS entry, shaped like the entries in an NVD record."""
    vector = vector or (VECTOR_31 if version == "3.1" else VECTOR_30)
    return {
        "type": entry_type,
        "cvssData": {"version": version, "vectorString": vector, "baseScore": score},
    }


def nvd_record(
    cve_id,
    published="2024-05-01T10:00:00.000",
    modified="2024-06-01T10:00:00.000",
    status="Analyzed",
    metrics=None,
    cwes=(),
):
    """One made-up NVD record. It includes the KEV date, which must not be kept."""
    return {
        "cve": {
            "id": cve_id,
            "published": published,
            "lastModified": modified,
            "vulnStatus": status,
            "metrics": metrics or {},
            "weaknesses": [{"type": "Primary", "description": [{"value": cwe}]} for cwe in cwes],
            "cisaExploitAdd": "2024-05-20",
        }
    }


# --- Choosing the CVSS entry -------------------------------------------------


def test_pick_cvss_prefers_version_3_1_over_3_0():
    metrics = {
        "cvssMetricV30": [cvss_entry("3.0", 9.8)],
        "cvssMetricV31": [cvss_entry("3.1", 5.4)],
    }

    assert pick_cvss(metrics)["cvssData"]["baseScore"] == 5.4


def test_pick_cvss_prefers_the_primary_entry_inside_a_version():
    metrics = {
        "cvssMetricV31": [
            cvss_entry("3.1", 7.0, "Secondary"),
            cvss_entry("3.1", 5.4, "Primary"),
        ]
    }

    assert pick_cvss(metrics)["cvssData"]["baseScore"] == 5.4


def test_pick_cvss_uses_the_first_entry_when_none_is_primary():
    metrics = {
        "cvssMetricV31": [
            cvss_entry("3.1", 7.0, "Secondary"),
            cvss_entry("3.1", 8.0, "Secondary"),
        ]
    }

    assert pick_cvss(metrics)["cvssData"]["baseScore"] == 7.0


def test_pick_cvss_version_comes_before_primary():
    # A Secondary 3.1 entry is still chosen over a Primary 3.0 entry
    metrics = {
        "cvssMetricV30": [cvss_entry("3.0", 9.8, "Primary")],
        "cvssMetricV31": [cvss_entry("3.1", 5.4, "Secondary")],
    }

    assert pick_cvss(metrics)["cvssData"]["version"] == "3.1"


def test_pick_cvss_falls_back_to_3_0():
    assert pick_cvss({"cvssMetricV30": [cvss_entry("3.0", 9.8)]})["cvssData"]["version"] == "3.0"


def test_pick_cvss_ignores_versions_2_0_and_4_0():
    metrics = {"cvssMetricV2": [cvss_entry("2.0", 4.3)], "cvssMetricV40": [cvss_entry("4.0", 9.0)]}

    assert pick_cvss(metrics) is None
    assert pick_cvss({}) is None


# --- Reading the vector and the weaknesses -----------------------------------


def test_parse_vector_gives_the_four_parts_as_words():
    assert parse_vector(VECTOR_31) == {
        "cvss_attack_vector": "NETWORK",
        "cvss_attack_complexity": "LOW",
        "cvss_privileges_required": "LOW",
        "cvss_user_interaction": "REQUIRED",
    }
    assert parse_vector(VECTOR_30) == {
        "cvss_attack_vector": "LOCAL",
        "cvss_attack_complexity": "HIGH",
        "cvss_privileges_required": "HIGH",
        "cvss_user_interaction": "NONE",
    }


def test_parse_vector_knows_adjacent_and_physical():
    assert parse_vector("CVSS:3.1/AV:A")["cvss_attack_vector"] == "ADJACENT_NETWORK"
    assert parse_vector("CVSS:3.1/AV:P")["cvss_attack_vector"] == "PHYSICAL"


def test_parse_vector_gives_none_for_a_missing_or_unknown_part():
    assert set(parse_vector(None).values()) == {None}
    assert set(parse_vector("not a vector").values()) == {None}
    parts = parse_vector("CVSS:3.1/AV:X/AC:L")
    assert parts["cvss_attack_vector"] is None  # X is not a known letter
    assert parts["cvss_attack_complexity"] == "LOW"
    assert parts["cvss_user_interaction"] is None  # UI is absent


def test_collect_cwe_ids_joins_unique_ids_in_number_order():
    weaknesses = [
        {"type": "Primary", "description": [{"value": "CWE-89"}, {"value": "CWE-79"}]},
        {"type": "Secondary", "description": [{"value": "CWE-79"}]},
    ]

    assert collect_cwe_ids(weaknesses) == "CWE-79;CWE-89"


def test_collect_cwe_ids_leaves_out_the_nvd_placeholders():
    weaknesses = [{"description": [{"value": "NVD-CWE-noinfo"}, {"value": "NVD-CWE-Other"}]}]

    assert collect_cwe_ids(weaknesses) is None
    assert collect_cwe_ids(None) is None
    assert collect_cwe_ids([]) is None


# --- The whole cleaning ------------------------------------------------------


def test_one_row_per_cve_with_the_expected_columns():
    record = nvd_record(
        "CVE-2024-1111", metrics={"cvssMetricV31": [cvss_entry("3.1", 5.4)]}, cwes=["CWE-79"]
    )

    table, _ = clean_nvd([record], SNAPSHOT)

    assert list(table.columns) == [
        "cve_id",
        "published_at",
        "last_modified_at",
        "nvd_status",
        "cvss_base_score",
        "cvss_version",
        "cvss_vector",
        "cvss_missing",
        "cvss_attack_vector",
        "cvss_attack_complexity",
        "cvss_privileges_required",
        "cvss_user_interaction",
        "cwe_ids",
        "after_snapshot",
        "modified_after_snapshot",
        "snapshot_date",
    ]
    row = table.loc[0]
    assert row["cve_id"] == "CVE-2024-1111"
    assert row["nvd_status"] == "Analyzed"
    assert row["cvss_base_score"] == 5.4
    assert row["cvss_version"] == "3.1"
    assert row["cvss_vector"] == VECTOR_31
    assert not row["cvss_missing"]
    assert row["cvss_attack_vector"] == "NETWORK"
    assert row["cwe_ids"] == "CWE-79"
    assert row["snapshot_date"] == "2026-10-01"


def test_dates_are_read_as_utc():
    table, _ = clean_nvd([nvd_record("CVE-2024-1111")], SNAPSHOT)

    assert table.loc[0, "published_at"] == pd.Timestamp("2024-05-01T10:00:00", tz="UTC")
    assert table.loc[0, "last_modified_at"] == pd.Timestamp("2024-06-01T10:00:00", tz="UTC")


def test_missing_cvss_stays_empty_and_is_flagged():
    records = [
        nvd_record("CVE-2024-1111"),  # no CVSS at all
        nvd_record("CVE-2024-2222", metrics={"cvssMetricV2": [cvss_entry("2.0", 4.3)]}),
        nvd_record("CVE-2024-3333", metrics={"cvssMetricV31": [cvss_entry("3.1", 5.4)]}),
    ]

    table, report = clean_nvd(records, SNAPSHOT)

    assert list(table["cvss_missing"]) == [True, True, False]
    assert table["cvss_base_score"].isna().tolist() == [True, True, False]
    assert table["cvss_vector"].isna().tolist() == [True, True, False]
    assert table["cvss_attack_vector"].isna().tolist() == [True, True, False]
    assert report["cvss_missing"] == 2
    assert report["cvss_missing_with_other_version"] == 1
    assert report["missing_values"]["cvss_base_score"] == 2
    assert report["missing_values"]["cve_id"] == 0


def test_report_counts_the_cvss_version_and_entry_type_used():
    records = [
        nvd_record("CVE-2024-1111", metrics={"cvssMetricV31": [cvss_entry("3.1", 5.4)]}),
        nvd_record(
            "CVE-2024-2222", metrics={"cvssMetricV30": [cvss_entry("3.0", 9.8, "Secondary")]}
        ),
    ]

    _, report = clean_nvd(records, SNAPSHOT)

    assert report["cvss_version_3_1"] == 1
    assert report["cvss_version_3_0"] == 1
    assert report["cvss_primary"] == 1
    assert report["cvss_not_primary"] == 1


def test_rejected_cves_are_dropped_and_counted():
    records = [
        nvd_record("CVE-2024-1111"),
        nvd_record("CVE-2024-2222", status="Rejected"),
        nvd_record("CVE-2024-3333", status="Modified"),
    ]

    table, report = clean_nvd(records, SNAPSHOT)

    assert list(table["cve_id"]) == ["CVE-2024-1111", "CVE-2024-3333"]
    assert report["removed_rejected"] == 1
    assert report["status_counts"] == {"Analyzed": 1, "Modified": 1}


def test_invalid_cve_id_is_removed_and_counted():
    records = [
        nvd_record("CVE-2024-1111"),
        nvd_record("CVE-2024-12"),  # too few digits
        nvd_record(None),
    ]

    table, report = clean_nvd(records, SNAPSHOT)

    assert list(table["cve_id"]) == ["CVE-2024-1111"]
    assert report["removed_invalid_cve_id"] == 2


def test_unreadable_date_is_removed_and_counted():
    records = [
        nvd_record("CVE-2024-1111"),
        nvd_record("CVE-2024-2222", published="yesterday"),
        nvd_record("CVE-2024-3333", modified=None),
    ]

    table, report = clean_nvd(records, SNAPSHOT)

    assert list(table["cve_id"]) == ["CVE-2024-1111"]
    assert report["removed_unreadable_date"] == 2


def test_duplicate_cve_keeps_the_latest_record():
    records = [
        nvd_record("CVE-2024-1111", modified="2024-06-01T10:00:00.000", status="Received"),
        nvd_record("CVE-2024-1111", modified="2024-08-01T10:00:00.000", status="Analyzed"),
    ]

    table, report = clean_nvd(records, SNAPSHOT)

    assert len(table) == 1
    assert table.loc[0, "nvd_status"] == "Analyzed"
    assert report["removed_duplicate_cve"] == 1


def test_dates_after_snapshot_are_flagged_but_not_removed():
    records = [
        # Published and modified on the snapshot day itself: allowed
        nvd_record(
            "CVE-2026-1111", published="2026-10-01T23:59:59.000", modified="2026-10-01T23:59:59.000"
        ),
        # Published before the snapshot, modified after it
        nvd_record(
            "CVE-2026-2222", published="2026-09-30T08:00:00.000", modified="2026-10-02T00:00:00.000"
        ),
        # Published after the snapshot
        nvd_record(
            "CVE-2026-3333", published="2026-10-02T00:00:00.000", modified="2026-10-03T00:00:00.000"
        ),
    ]

    table, report = clean_nvd(records, SNAPSHOT)

    flags = table.set_index("cve_id")
    assert len(table) == 3
    assert flags["after_snapshot"].to_dict() == {
        "CVE-2026-1111": False,
        "CVE-2026-2222": False,
        "CVE-2026-3333": True,
    }
    assert flags["modified_after_snapshot"].to_dict() == {
        "CVE-2026-1111": False,
        "CVE-2026-2222": True,
        "CVE-2026-3333": True,
    }
    assert report["flagged_after_snapshot"] == 1
    assert report["flagged_modified_after_snapshot"] == 2


def test_kev_date_inside_the_nvd_record_is_not_kept():
    table, _ = clean_nvd([nvd_record("CVE-2024-1111")], SNAPSHOT)

    assert not any("cisa" in column.lower() or "kev" in column.lower() for column in table.columns)
    assert "2024-05-20" not in table.to_csv()


def test_counts_in_the_report_add_up():
    records = [
        nvd_record("CVE-2024-1111"),
        nvd_record("CVE-2024-1111"),
        nvd_record("bad"),
        nvd_record("CVE-2024-2222", published=None),
        nvd_record("CVE-2024-3333", status="Rejected"),
    ]

    _, report = clean_nvd(records, SNAPSHOT)

    removed = (
        report["removed_invalid_cve_id"]
        + report["removed_unreadable_date"]
        + report["removed_rejected"]
        + report["removed_duplicate_cve"]
    )
    assert report["rows_before"] == 5
    assert report["rows_before"] - removed == report["rows_after"] == 1


def test_no_records_gives_an_empty_table():
    table, report = clean_nvd([], SNAPSHOT)

    assert len(table) == 0
    assert report["rows_before"] == 0
    assert report["rows_after"] == 0


def test_main_reads_every_monthly_file_and_writes_the_csv(tmp_path):
    # A made-up project folder, so the real data is never touched
    settings = load_settings(tmp_path)
    raw_dir = settings.raw_source("nvd")
    raw_dir.mkdir(parents=True)
    months = {
        "2024-05": nvd_record(
            "CVE-2024-1111", metrics={"cvssMetricV30": [cvss_entry("3.0", 9.8)]}, cwes=["CWE-79"]
        ),
        "2024-06": nvd_record("CVE-2024-2222", published="2024-06-02T00:00:00.000"),
    }
    for month, record in months.items():
        with gzip.open(raw_dir / f"nvd_{month}.json.gz", "wt", encoding="utf-8") as file:
            json.dump({"month": month, "totalResults": 1, "vulnerabilities": [record]}, file)

    output_path = main(settings)

    assert output_path == tmp_path / "data" / "processed" / "b_survival" / "nvd_clean.csv"
    saved = pd.read_csv(output_path, dtype=str, keep_default_na=False)
    assert list(saved["cve_id"]) == ["CVE-2024-1111", "CVE-2024-2222"]
    assert saved.loc[0, "published_at"] == "2024-05-01T10:00:00.000000Z"
    assert saved.loc[0, "cvss_version"] == "3.0"
    assert saved.loc[0, "cvss_missing"] == "False"
    assert saved.loc[1, "cvss_missing"] == "True"
    assert saved.loc[1, "cvss_base_score"] == ""
    assert saved.loc[1, "cwe_ids"] == ""
