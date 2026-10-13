
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
    

def test_marks_history_as_incomplete_by_default():
    result = reconstruct_relationships(
        "CVE-2024-21732",
        {"cveChanges": []},
        date(2024, 2, 1),
    )

    assert result.history_complete is False
    assert result.limitations
    assert any(
        "completeness" in limitation.lower()
        for limitation in result.limitations
    )
    
def test_later_duplicate_cwe_does_not_change_historical_snapshot():
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
                        }
                    ],
                }
            },
            {
                "change": {
                    "created": "2025-06-03T15:15:56.083",
                    "details": [
                        {
                            "action": "Added",
                            "type": "CWE",
                            "newValue": "CWE-79",
                        }
                    ],
                }
            },
        ]
    }

    result = reconstruct_relationships(
        "CVE-2024-21732",
        history,
        date(2024, 2, 1),
    )

    assert result.cwe_ids == ("CWE-79",)
    assert result.evidence_events == 1


def test_relationship_removed_before_snapshot_is_not_included():
    history = {
        "cveChanges": [
            {
                "change": {
                    "created": "2024-01-08T10:00:00.000",
                    "details": [
                        {
                            "action": "Added",
                            "type": "CWE",
                            "newValue": "CWE-79",
                        }
                    ],
                }
            },
            {
                "change": {
                    "created": "2024-01-20T10:00:00.000",
                    "details": [
                        {
                            "action": "Removed",
                            "type": "CWE",
                            "oldValue": "CWE-79",
                        }
                    ],
                }
            },
        ]
    }

    result = reconstruct_relationships(
        "CVE-2024-21732",
        history,
        date(2024, 2, 1),
    )

    assert result.cwe_ids == ()
    
def test_cpe_configuration_change_replaces_old_relationship():
    history = {
        "cveChanges": [
            {
                "change": {
                    "created": "2024-01-08T10:00:00.000",
                    "details": [
                        {
                            "action": "Added",
                            "type": "CPE Configuration",
                            "newValue": (
                                "cpe:2.3:a:old_vendor:old_product:"
                                "*:*:*:*:*:*:*:*"
                            ),
                        }
                    ],
                }
            },
            {
                "change": {
                    "created": "2024-01-20T10:00:00.000",
                    "details": [
                        {
                            "action": "Changed",
                            "type": "CPE Configuration",
                            "oldValue": (
                                "cpe:2.3:a:old_vendor:old_product:"
                                "*:*:*:*:*:*:*:*"
                            ),
                            "newValue": (
                                "cpe:2.3:a:new_vendor:new_product:"
                                "*:*:*:*:*:*:*:*"
                            ),
                        }
                    ],
                }
            },
        ]
    }

    result = reconstruct_relationships(
        "CVE-2024-21732",
        history,
        date(2024, 2, 1),
    )

    assert result.affected == (("new_vendor", "new_product"),)

