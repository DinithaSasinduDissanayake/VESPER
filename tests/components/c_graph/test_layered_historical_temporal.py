"""Temporal regression tests for layered historical graph outputs."""

import copy
import csv
import json
from datetime import UTC, datetime

import pandas as pd
import pytest

from vesper.components.c_graph.layered_historical import (
    analyze_layer,
    reconstruct_relationship_layers,
    run_layer_comparison,
)

CVE_ID = "CVE-2024-12345"
FUTURE_CVE_ID = "CVE-2025-54321"
OLD_CPE = "cpe:2.3:a:vendor:old_product:*:*:*:*:*:*:*:*"
NEW_CPE = "cpe:2.3:a:vendor:new_product:*:*:*:*:*:*:*:*"


def make_history(cve_id, events):
    changes = [
        {
            "change": {
                "cveId": cve_id,
                "cveChangeId": f"event-{index}",
                "created": created,
                "details": details,
            }
        }
        for index, (created, details) in enumerate(events)
    ]
    return {
        "resultsPerPage": len(changes),
        "startIndex": 0,
        "totalResults": len(changes),
        "format": "NVD_CVEHistory",
        "version": "2.0",
        "timestamp": "2026-10-15T00:00:00.000Z",
        "cveChanges": changes,
    }


def initial_relationships():
    return [
        {"action": "Added", "type": "CPE Configuration", "newValue": OLD_CPE},
        {"action": "Added", "type": "CWE", "newValue": "CWE-79"},
    ]


def changed_relationships():
    return [
        {
            "action": "Changed",
            "type": "CPE Configuration",
            "oldValue": OLD_CPE,
            "newValue": NEW_CPE,
        },
        {"action": "Changed", "type": "CWE", "oldValue": "CWE-79", "newValue": "CWE-89"},
    ]


def test_post_cutoff_events_do_not_change_layer_outputs_when_pruned():
    cutoff = datetime(2024, 6, 1, tzinfo=UTC)
    history = make_history(
        CVE_ID,
        [
            ("2024-01-01T00:00:00Z", initial_relationships()),
            ("2024-06-02T00:00:00Z", changed_relationships()),
        ],
    )
    pruned = copy.deepcopy(history)
    pruned["cveChanges"] = [
        item
        for item in pruned["cveChanges"]
        if datetime.fromisoformat(item["change"]["created"].replace("Z", "+00:00")) <= cutoff
    ]
    pruned["resultsPerPage"] = len(pruned["cveChanges"])
    pruned["totalResults"] = len(pruned["cveChanges"])

    full_layers = reconstruct_relationship_layers(history, cutoff, CVE_ID)
    pruned_layers = reconstruct_relationship_layers(pruned, cutoff, CVE_ID)
    assert full_layers == pruned_layers
    assert full_layers["cpe"].relationships == (("vendor", "old_product"),)
    assert full_layers["cwe"].relationships == ("CWE-79",)

    for layer in ("cpe", "cwe"):
        full_features, full_outcomes, full_metadata = analyze_layer([full_layers[layer]])
        pruned_features, pruned_outcomes, pruned_metadata = analyze_layer([pruned_layers[layer]])
        pd.testing.assert_frame_equal(full_features, pruned_features)
        pd.testing.assert_frame_equal(full_outcomes, pruned_outcomes)
        assert full_metadata == pruned_metadata

    later_layers = reconstruct_relationship_layers(
        history, datetime(2024, 6, 3, tzinfo=UTC), CVE_ID
    )
    assert later_layers["cpe"].relationships == (("vendor", "new_product"),)
    assert later_layers["cwe"].relationships == ("CWE-89",)


def test_layer_runner_excludes_cves_published_after_cutoff(tmp_path):
    history_dir = tmp_path / "histories"
    history_dir.mkdir()
    for cve_id in (CVE_ID, FUTURE_CVE_ID):
        history = make_history(cve_id, [("2024-01-01T00:00:00Z", initial_relationships())])
        (history_dir / f"{cve_id}.json").write_text(json.dumps(history), encoding="utf-8")

    frame_path = tmp_path / "sample_frame.csv"
    with frame_path.open("w", encoding="utf-8", newline="") as file:
        writer = csv.writer(file)
        writer.writerow(["cve_id", "published"])
        writer.writerow([CVE_ID, "2024-01-01T00:00:00+00:00"])
        writer.writerow([FUTURE_CVE_ID, "2025-01-01T00:00:00+00:00"])

    output_dir = tmp_path / "layer_outputs"
    results = run_layer_comparison(
        history_dir,
        frame_path,
        output_dir,
        datetime(2024, 6, 1, tzinfo=UTC),
    )

    for layer, metadata in results.items():
        outcomes = pd.read_csv(output_dir / layer / "outcomes.csv")
        features = pd.read_csv(output_dir / layer / "features.csv")
        future = outcomes.loc[outcomes["cve_id"] == FUTURE_CVE_ID].iloc[0]
        assert future["feature_status"] == "unavailable"
        assert future["reason"] == "not_published_at_cutoff"
        assert FUTURE_CVE_ID not in set(features["cve_id"])
        assert metadata["graph_nodes_by_type"]["cve"] == 1
        assert metadata["graph_edges"] == (2 if layer == "cpe" else 1)


def test_known_empty_layer_relationships_remain_missing_features():
    history = make_history(
        CVE_ID,
        [
            ("2024-01-01T00:00:00Z", initial_relationships()),
            (
                "2024-02-01T00:00:00Z",
                [
                    {"action": "Removed", "type": "CPE Configuration", "oldValue": OLD_CPE},
                    {"action": "Removed", "type": "CWE", "oldValue": "CWE-79"},
                ],
            ),
        ],
    )
    layers = reconstruct_relationship_layers(history, datetime(2024, 6, 1, tzinfo=UTC), CVE_ID)

    for layer in ("cpe", "cwe"):
        features, outcomes, metadata = analyze_layer([layers[layer]])
        outcome = outcomes.iloc[0]
        assert layers[layer].eligible is True
        assert layers[layer].relationships == ()
        assert features.empty
        assert outcome["feature_status"] == "known_no_active_relationships"
        assert pd.isna(outcome["pagerank"])
        assert metadata["known_no_active_relationships"] == 1
        assert metadata["graph_nodes_by_type"]["cve"] == 0


@pytest.mark.parametrize(
    ("cutoff_text", "future_published"),
    [
        ("2024-01-01T00:00:00+00:00", "2024-01-02T00:00:00+00:00"),
        ("2026-06-18T00:00:00+00:00", "2026-06-19T00:00:00+00:00"),
        ("2026-10-14T23:59:59.999999+00:00", "2026-10-15T00:00:00+00:00"),
    ],
    ids=["early", "middle", "window-end"],
)
def test_cutoff_metadata_separates_publication_evidence_and_feature_states(
    tmp_path, cutoff_text, future_published
):
    active_id = "CVE-2024-10001"
    ineligible_id = "CVE-2024-10002"
    known_empty_id = "CVE-2024-10003"
    future_id = "CVE-2024-10004"
    history_dir = tmp_path / "histories"
    history_dir.mkdir()
    histories = {
        active_id: make_history(active_id, [("2023-12-01T00:00:00Z", initial_relationships())]),
        ineligible_id: make_history(
            ineligible_id,
            [
                (
                    "2023-12-01T00:00:00Z",
                    [
                        {"action": "Removed", "type": "CPE Configuration", "oldValue": OLD_CPE},
                        {"action": "Removed", "type": "CWE", "oldValue": "CWE-79"},
                    ],
                ),
                (
                    "2023-12-02T00:00:00Z",
                    [
                        {"action": "Changed", "type": "CPE Configuration", "oldValue": OLD_CPE},
                        {"action": "Changed", "type": "CWE", "oldValue": "CWE-79"},
                    ],
                ),
            ],
        ),
        known_empty_id: make_history(
            known_empty_id,
            [
                ("2023-12-01T00:00:00Z", initial_relationships()),
                (
                    "2023-12-02T00:00:00Z",
                    [
                        {"action": "Removed", "type": "CPE Configuration", "oldValue": OLD_CPE},
                        {"action": "Removed", "type": "CWE", "oldValue": "CWE-79"},
                    ],
                ),
            ],
        ),
        future_id: make_history(future_id, [("2023-12-01T00:00:00Z", initial_relationships())]),
    }
    for cve_id, history in histories.items():
        (history_dir / f"{cve_id}.json").write_text(json.dumps(history), encoding="utf-8")

    frame_path = tmp_path / "sample_frame.csv"
    with frame_path.open("w", encoding="utf-8", newline="") as file:
        writer = csv.writer(file)
        writer.writerow(["cve_id", "published"])
        for cve_id in (active_id, ineligible_id, known_empty_id):
            writer.writerow([cve_id, "2023-12-01T00:00:00+00:00"])
        writer.writerow([future_id, future_published])

    output_dir = tmp_path / "layer_outputs"
    results = run_layer_comparison(
        history_dir, frame_path, output_dir, datetime.fromisoformat(cutoff_text)
    )

    for layer, metadata in results.items():
        required_v2_fields = {
            "metadata_schema_version",
            "population_cves",
            "published_by_cutoff_cves",
            "not_published_at_cutoff_cves",
            "evidence_eligible_cves",
            "evidence_ineligible_cves",
            "known_empty_relationship_cves",
            "feature_rows",
            "feature_unavailable_published_cves",
            "feature_unavailable_population_cves",
            "feature_status_counts",
            "published_feature_status_counts",
            "evidence_exclusion_reason_counts",
            "publication_exclusion_reason_counts",
            "feature_unavailability_reason_counts",
        }
        assert required_v2_fields <= metadata.keys()
        assert metadata["metadata_schema_version"] == "2.0"
        assert metadata["population_cves"] == 4
        assert metadata["published_by_cutoff_cves"] == 3
        assert metadata["not_published_at_cutoff_cves"] == 1
        assert metadata["evidence_eligible_cves"] == 2
        assert metadata["evidence_ineligible_cves"] == 1
        assert metadata["known_empty_relationship_cves"] == 1
        assert metadata["feature_rows"] == 1
        assert metadata["feature_unavailable_published_cves"] == 2
        assert metadata["feature_unavailable_population_cves"] == 3
        assert metadata["published_by_cutoff_cves"] == (
            metadata["evidence_eligible_cves"] + metadata["evidence_ineligible_cves"]
        )
        assert metadata["population_cves"] == (
            metadata["published_by_cutoff_cves"] + metadata["not_published_at_cutoff_cves"]
        )
        assert metadata["publication_exclusion_reason_counts"] == {"not_published_at_cutoff": 1}
        reasons = metadata["evidence_exclusion_reason_counts"]
        assert "not_published_at_cutoff" not in reasons
        assert sum(reasons.values()) > metadata["evidence_ineligible_cves"]
        assert metadata["reason_counts_are_overlapping"] is True
        assert metadata["count_definitions"]["reason_counts"]
        feature_reasons = metadata["feature_unavailability_reason_counts"]
        assert feature_reasons["no_active_relationships_at_cutoff"] == 1
        assert "not_published_at_cutoff" not in feature_reasons
        assert (
            "known-empty" in metadata["count_definitions"]["feature_unavailability_reason_counts"]
        )
        assert (
            "reported separately"
            in metadata["count_definitions"]["feature_unavailability_reason_counts"]
        )
        assert metadata["known_empty_relationship_cves"] == 1
        assert metadata["published_feature_status_counts"] == {
            "available": 1,
            "known_no_active_relationships": 1,
            "unavailable": 1,
        }
        assert metadata["graph_nodes_by_type"]["cve"] == 1
        assert metadata["graph_edges"] == (2 if layer == "cpe" else 1)
        assert metadata["feature_unavailable_cves"] == 3
        assert metadata["evidence_ineligible_population_legacy_cves"] == 2
