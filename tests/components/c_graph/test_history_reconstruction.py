
"""Tests for historical CVE relationship reconstruction."""

from datetime import date

from vesper.components.c_graph.history_reconstruction import (
    reconstruct_relationships,
)


def test_reconstructs_relationships_documented_before_snapshot():
    history = {
        "cveChanges": [
            {
                "change": {
                    "created": "2024-01-08T18:51:23.750",
                    "details": [
                        {
                            "action": "Added",
                            "type": "CWE",
                            "newValue": "NIST CWE-79",
                        },
                        {
                            "action": "Added",
                            "type": "CPE Configuration",
                            "newValue": (
                                "OR\n"
                                "     *cpe:2.3:a:flycms_project:flycms:"
                                "*:*:*:*:*:*:*:* versions up to "
                                "(including) 2019-12-20"
                            ),
                        },
                    ],
                }
            }
        ]
    }

    result = reconstruct_relationships(
        "CVE-2024-21732",
        history,
        date(2024, 2, 1),
    )

    assert result.cve_id == "CVE-2024-21732"
    assert result.snapshot_date == date(2024, 2, 1)
    assert result.cwe_ids == ("CWE-79",)
    assert result.affected == (("flycms_project", "flycms"),)
    assert result.evidence_events == 2


def test_ignores_events_after_snapshot():
    history = {
        "cveChanges": [
            {
                "change": {
                    "created": "2026-06-17T07:10:02.103",
                    "details": [
                        {
                            "action": "Added",
                            "type": "CWE",
                            "newValue": "CWE-79",
                        }
                    ],
                }
            }
        ]
    }

    result = reconstruct_relationships(
        "CVE-2024-21732",
        history,
        date(2024, 2, 1),
    )

    assert result.cwe_ids == ()
    assert result.affected == ()
    assert result.evidence_events == 0
