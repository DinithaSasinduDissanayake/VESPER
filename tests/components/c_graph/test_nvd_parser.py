
"""Tests for the NVD record parser."""

from datetime import UTC, date

from vesper.components.c_graph.nvd_parser import parse_nvd_record


def make_nvd_record() -> dict:
    """Create a representative NVD API record for testing."""
    return {
        "cve": {
            "id": "CVE-2021-44228",
            "published": "2021-12-10T10:15:00.000Z",
            "lastModified": "2023-04-03T20:15:00.000Z",
            "vulnStatus": "Analyzed",
            "descriptions": [
                {
                    "lang": "en",
                    "value": "Example vulnerability description.",
                }
            ],
            "metrics": {
                "cvssMetricV31": [
                    {
                        "cvssData": {
                            "baseScore": 10.0,
                            "version": "3.1",
                            "vectorString": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H",
                        }
                    }
                ]
            },
            "weaknesses": [
                {
                    "description": [
                        {"lang": "en", "value": "CWE-502"},
                        {"lang": "en", "value": "NVD-CWE-Other"},
                    ]
                }
            ],
            "configurations": [
                {
                    "nodes": [
                        {
                            "cpeMatch": [
                                {
                                    "vulnerable": True,
                                    "criteria": (
                                        "cpe:2.3:a:apache:log4j:2.14.1:*:*:*:*:*:*:*"
                                    ),
                                },
                                {
                                    "vulnerable": False,
                                    "criteria": (
                                        "cpe:2.3:a:apache:unrelated:1.0:*:*:*:*:*:*:*"
                                    ),
                                },
                            ]
                        }
                    ]
                }
            ],
        }
    }


def test_parse_nvd_record_extracts_vulnerability_fields():
    snapshot = date(2026, 10, 12)

    vulnerability = parse_nvd_record(make_nvd_record(), snapshot)

    assert vulnerability.cve_id == "CVE-2021-44228"
    assert vulnerability.published_at.tzinfo is not None
    assert vulnerability.published_at.utcoffset() == UTC.utcoffset(None)
    assert vulnerability.description == "Example vulnerability description."
    assert vulnerability.cvss_base_score == 10.0
    assert vulnerability.cvss_version == "3.1"
    assert vulnerability.cwe_ids == ("CWE-502",)
    assert vulnerability.affected == (("apache", "log4j"),)
    assert vulnerability.snapshot_date == snapshot


def test_parse_nvd_record_handles_missing_optional_fields():
    record = make_nvd_record()
    cve = record["cve"]
    cve.pop("metrics")
    cve.pop("weaknesses")
    cve.pop("configurations")

    vulnerability = parse_nvd_record(record, date(2026, 10, 12))

    assert vulnerability.cvss_base_score is None
    assert vulnerability.cvss_version is None
    assert vulnerability.cvss_vector is None
    assert vulnerability.cwe_ids == ()
    assert vulnerability.affected == ()
