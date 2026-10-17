"""Tests for the Component C NVD parser."""

from datetime import date

import pytest

from vesper.components.c_graph.nvd_parser import parse_nvd_record

SNAPSHOT_DATE = date(2024, 1, 31)


def make_record(**overrides):
    """Create a minimal NVD record for parser tests."""
    cve = {
        "id": "CVE-2024-12345",
        "published": "2024-01-10T12:00:00.000",
        "lastModified": "2024-01-15T12:00:00.000",
        "descriptions": [
            {"lang": "en", "value": "Example vulnerability."},
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
                    {"lang": "en", "value": "Not a CWE identifier"},
                ],
            },
        ],
        "metrics": {
            "cvssMetricV31": [
                {
                    "cvssData": {
                        "baseScore": 7.5,
                        "vectorString": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
                    },
                },
            ],
        },
        "vulnStatus": "Analyzed",
    }
    cve.update(overrides)
    return {"cve": cve}


def test_parses_core_fields_and_relationships():
    vulnerability = parse_nvd_record(make_record(), SNAPSHOT_DATE)

    assert vulnerability.cve_id == "CVE-2024-12345"
    assert vulnerability.description == "Example vulnerability."
    assert vulnerability.cwe_ids == ("CWE-79",)
    assert vulnerability.affected == (("examplevendor", "exampleproduct"),)
    assert vulnerability.cvss_base_score == 7.5
    assert vulnerability.cvss_version == "3.1"
    assert vulnerability.nvd_status == "Analyzed"
    assert vulnerability.snapshot_date == SNAPSHOT_DATE


def test_na_vendor_and_product_are_not_added():
    record = make_record(
        affected=[
            {
                "affectedData": [
                    {"vendor": "n/a", "product": "n/a"},
                    {"vendor": "ExampleVendor", "product": "n/a"},
                    {"vendor": "ExampleVendor", "product": "ExampleProduct"},
                ],
            },
        ],
    )

    vulnerability = parse_nvd_record(record, SNAPSHOT_DATE)

    assert vulnerability.affected == (("examplevendor", "exampleproduct"),)


def test_missing_optional_fields_are_handled():
    record = make_record(
        descriptions=[],
        affected=[],
        weaknesses=[],
        metrics={},
    )

    vulnerability = parse_nvd_record(record, SNAPSHOT_DATE)

    assert vulnerability.description == ""
    assert vulnerability.affected == ()
    assert vulnerability.cwe_ids == ()
    assert vulnerability.cvss_base_score is None


def test_timestamps_are_timezone_aware():
    vulnerability = parse_nvd_record(make_record(), SNAPSHOT_DATE)

    assert vulnerability.published_at.tzinfo is not None
    assert vulnerability.last_modified_at.tzinfo is not None
    assert vulnerability.published_at.utcoffset().total_seconds() == 0
    assert vulnerability.last_modified_at.utcoffset().total_seconds() == 0


def test_invalid_cve_identifier_is_rejected():
    record = make_record(id="NOT-A-CVE")

    with pytest.raises(ValueError, match="Invalid CVE identifier"):
        parse_nvd_record(record, SNAPSHOT_DATE)


def test_missing_timestamp_is_rejected():
    record = make_record(published=None)

    with pytest.raises(ValueError, match="NVD timestamp"):
        parse_nvd_record(record, SNAPSHOT_DATE)


def test_extract_affected_from_cpe_configuration():
    from vesper.components.c_graph.nvd_parser import _extract_affected

    cve = {
        "affected": [
            {
                "affectedData": [
                    {"vendor": "n/a", "product": "n/a"},
                ],
            },
        ],
        "configurations": [
            {
                "nodes": [
                    {
                        "operator": "OR",
                        "negate": False,
                        "cpeMatch": [
                            {
                                "vulnerable": True,
                                "criteria": ("cpe:2.3:a:flycms_project:flycms:*:*:*:*:*:*:*:*"),
                            },
                        ],
                    },
                ],
            },
        ],
    }

    assert _extract_affected(cve) == (("flycms_project", "flycms"),)
