"""Tests for the Component C pipeline."""

import gzip
import json
from datetime import date

import pandas as pd
import pytest

from vesper.components.c_graph.pipeline import run_pipeline


def write_month(path, records):
    """Write a minimal compressed NVD monthly dataset."""
    path.parent.mkdir(parents=True, exist_ok=True)
    payload = {
        "month": path.stem,
        "downloaded_at": "2026-10-14T00:00:00+00:00",
        "totalResults": len(records),
        "vulnerabilities": records,
    }
    with gzip.open(path, "wt", encoding="utf-8") as file:
        json.dump(payload, file)


def make_record(
    cve_id,
    published="2024-01-10T12:00:00.000",
    modified="2024-01-15T12:00:00.000",
):
    return {
        "cve": {
            "id": cve_id,
            "published": published,
            "lastModified": modified,
            "descriptions": [
                {"lang": "en", "value": "Example vulnerability"},
            ],
            "affected": [
                {
                    "affectedData": [
                        {
                            "vendor": "ExampleVendor",
                            "product": "ExampleProduct",
                        },
                    ],
                },
            ],
            "weaknesses": [
                {
                    "description": [
                        {"lang": "en", "value": "CWE-79"},
                    ],
                },
            ],
            "metrics": {},
            "vulnStatus": "Analyzed",
        },
    }


def test_pipeline_exports_only_records_within_cutoff(tmp_path):
    nvd_dir = tmp_path / "nvd"
    write_month(
        nvd_dir / "nvd_2024-01.json.gz",
        [
            make_record("CVE-2024-12345"),
            make_record(
                "CVE-2024-12346",
                modified="2026-10-15T12:00:00.000",
            ),
        ],
    )
    output_path = tmp_path / "outputs" / "features.csv"

    metadata = run_pipeline(
        nvd_dir,
        output_path,
        snapshot_date=date(2026, 10, 14),
    )

    result = pd.read_csv(output_path)
    assert result["cve_id"].tolist() == ["CVE-2024-12345"]
    assert metadata["parsed_cve_count"] == 1
    assert metadata["skipped_after_cutoff_count"] == 1
    assert metadata["snapshot_date"] == "2026-10-14"


def test_pipeline_rejects_duplicate_cves_across_months(tmp_path):
    nvd_dir = tmp_path / "nvd"
    record = make_record("CVE-2024-12345")

    write_month(nvd_dir / "nvd_2024-01.json.gz", [record])
    write_month(nvd_dir / "nvd_2024-02.json.gz", [record])

    with pytest.raises(ValueError, match="Duplicate CVE across input files"):
        run_pipeline(
            nvd_dir,
            tmp_path / "features.csv",
            snapshot_date=date(2026, 10, 14),
        )


def test_pipeline_records_input_and_output_metadata(tmp_path):
    nvd_dir = tmp_path / "nvd"
    write_month(
        nvd_dir / "nvd_2024-01.json.gz",
        [make_record("CVE-2024-12345")],
    )
    output_path = tmp_path / "outputs" / "features.csv"

    metadata = run_pipeline(
        nvd_dir,
        output_path,
        snapshot_date=date(2026, 10, 14),
    )

    metadata_path = output_path.with_suffix(".metadata.json")
    saved_metadata = json.loads(metadata_path.read_text(encoding="utf-8"))

    assert saved_metadata == metadata
    assert metadata["monthly_file_count"] == 1
    assert metadata["monthly_files"] == ["nvd_2024-01.json.gz"]
    assert metadata["historical_reconstruction"] == "not_performed"
    assert metadata["output_csv"] == str(output_path)


def test_pipeline_excludes_rejected_records_and_reports_count(tmp_path):
    nvd_dir = tmp_path / "nvd"

    accepted = make_record("CVE-2024-12345")
    rejected = make_record("CVE-2024-12346")
    rejected["cve"]["vulnStatus"] = "Rejected"

    write_month(
        nvd_dir / "nvd_2024-01.json.gz",
        [accepted, rejected],
    )

    output_path = tmp_path / "outputs" / "features.csv"

    metadata = run_pipeline(
        nvd_dir,
        output_path,
        snapshot_date=date(2026, 10, 14),
    )

    result = pd.read_csv(output_path)

    assert result["cve_id"].tolist() == ["CVE-2024-12345"]
    assert metadata["parsed_cve_count"] == 1
    assert metadata["skipped_rejected_count"] == 1

    saved_metadata = json.loads(
        output_path.with_suffix(".metadata.json").read_text(encoding="utf-8")
    )
    assert saved_metadata["skipped_rejected_count"] == 1
