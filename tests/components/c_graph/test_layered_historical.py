"""Regression tests for offline, source-separated historical graph analysis."""

from datetime import UTC, datetime

import pandas as pd

from vesper.components.c_graph.historical import reconstruct_relationships
from vesper.components.c_graph.layered_historical import (
    analyze_layer,
    reconstruct_relationship_layers,
)

CUTOFF = datetime(2026, 10, 14, 23, 59, 59, tzinfo=UTC)
CVE_ID = "CVE-2024-12345"
CPE = "cpe:2.3:a:vendor:product:*:*:*:*:*:*:*:*"


def make_history(details_by_time):
    changes = []
    for index, (created, details) in enumerate(details_by_time):
        changes.append(
            {
                "change": {
                    "cveId": CVE_ID,
                    "cveChangeId": f"event-{index}",
                    "created": created,
                    "details": details,
                }
            }
        )
    return {
        "resultsPerPage": len(changes),
        "startIndex": 0,
        "totalResults": len(changes),
        "format": "NVD_CVEHistory",
        "version": "2.0",
        "timestamp": "2026-10-15T00:00:00.000",
        "cveChanges": changes,
    }


def cpe_added():
    return {"action": "Added", "type": "CPE Configuration", "newValue": CPE}


def cwe_added():
    return {"action": "Added", "type": "CWE", "newValue": "CWE-79"}


def test_unsupported_affected_does_not_suppress_independent_layers():
    history = make_history(
        [
            ("2024-01-01T00:00:00Z", [cpe_added(), cwe_added()]),
            (
                "2026-09-01T00:00:00Z",
                [
                    {
                        "action": "Added",
                        "type": "Affected",
                        "newValue": 'New affected value received. <a href="https://github.com/CVEProject/cvelistV5/example">CVE</a>',
                    }
                ],
            ),
        ]
    )

    combined = reconstruct_relationships(history, CUTOFF, CVE_ID)
    layers = reconstruct_relationship_layers(history, CUTOFF, CVE_ID)

    assert combined.feature_eligible is False
    assert layers["cpe"].eligible is True
    assert layers["cpe"].relationships == (("vendor", "product"),)
    assert layers["cwe"].eligible is True
    assert layers["cwe"].relationships == ("CWE-79",)


def test_uncertain_initial_state_only_blocks_its_own_layer():
    history = make_history(
        [
            (
                "2024-01-01T00:00:00Z",
                [
                    {
                        "action": "Removed",
                        "type": "CPE Configuration",
                        "oldValue": CPE,
                    },
                    cwe_added(),
                ],
            )
        ]
    )

    layers = reconstruct_relationship_layers(history, CUTOFF, CVE_ID)

    assert layers["cpe"].eligible is False
    assert "uncertain_initial_cpe_state" in layers["cpe"].exclusion_reasons
    assert layers["cwe"].eligible is True


def test_unsupported_cpe_change_does_not_invalidate_cwe_layer():
    history = make_history(
        [
            ("2024-01-01T00:00:00Z", [cpe_added(), cwe_added()]),
            (
                "2025-01-01T00:00:00Z",
                [{"action": "Changed", "type": "CPE Configuration"}],
            ),
        ]
    )

    layers = reconstruct_relationship_layers(history, CUTOFF, CVE_ID)

    assert layers["cpe"].eligible is False
    assert "unsupported_cpe_configuration_change" in layers["cpe"].exclusion_reasons
    assert layers["cwe"].eligible is True


def test_unsupported_cwe_change_does_not_invalidate_cpe_layer():
    history = make_history(
        [
            ("2024-01-01T00:00:00Z", [cpe_added(), cwe_added()]),
            ("2025-01-01T00:00:00Z", [{"action": "Changed", "type": "CWE"}]),
        ]
    )

    layers = reconstruct_relationship_layers(history, CUTOFF, CVE_ID)

    assert layers["cwe"].eligible is False
    assert "unsupported_cwe_change" in layers["cwe"].exclusion_reasons
    assert layers["cpe"].eligible is True


def test_unavailable_layer_features_are_missing_not_zero():
    supported_history = make_history([("2024-01-01T00:00:00Z", [cpe_added()])])
    missing_history = make_history([("2024-01-01T00:00:00Z", [cwe_added()])])
    supported = reconstruct_relationship_layers(supported_history, CUTOFF, CVE_ID)["cpe"]
    other_id = "CVE-2024-54321"
    missing_history["cveChanges"][0]["change"]["cveId"] = other_id
    missing = reconstruct_relationship_layers(missing_history, CUTOFF, other_id)["cpe"]
    _, outcomes, _ = analyze_layer([supported, missing])

    unavailable = outcomes.loc[outcomes["cve_id"] == other_id].iloc[0]
    assert unavailable["feature_status"] == "unavailable"
    assert "no_interpretable_cpe_events_by_cutoff" in unavailable["reason"]
    assert pd.isna(unavailable["product_degree"])
    assert pd.isna(unavailable["pagerank"])


def test_fixed_layer_graph_produces_deterministic_features():
    records = []
    for cve_id, product in (("CVE-2024-12345", "product"), ("CVE-2024-54321", "product")):
        history = make_history(
            [
                (
                    "2024-01-01T00:00:00Z",
                    [
                        {
                            "action": "Added",
                            "type": "CPE Configuration",
                            "newValue": f"cpe:2.3:a:vendor:{product}:*:*:*:*:*:*:*:*",
                        }
                    ],
                )
            ]
        )
        history["cveChanges"][0]["change"]["cveId"] = cve_id
        records.append(reconstruct_relationship_layers(history, CUTOFF, cve_id)["cpe"])

    first_features, first_outcomes, _ = analyze_layer(records)
    second_features, second_outcomes, _ = analyze_layer(records)

    pd.testing.assert_frame_equal(first_features, second_features)
    pd.testing.assert_frame_equal(first_outcomes, second_outcomes)
