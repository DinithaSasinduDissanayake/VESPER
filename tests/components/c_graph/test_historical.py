"""Tests for historical Component C relationship reconstruction."""

import csv
import json
from datetime import UTC, datetime
from pathlib import Path

import networkx as nx
import pytest

from vesper.components.c_graph.historical import (
    build_historical_graph,
    build_multi_cve_historical_graph,
    parse_affected_events,
    parse_cpe_events,
    parse_cwe_events,
    reconstruct_relationships,
)


def make_history(cve_id="CVE-2018-25095"):
    """Create a history fixture containing a real-style vendor change."""
    changes = [
        {
            "change": {
                "cveId": cve_id,
                "cveChangeId": "weakness-initial",
                "created": "2024-01-10T18:42:09.650",
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
                "cveId": cve_id,
                "cveChangeId": "initial",
                "created": "2024-01-11T18:42:09.650",
                "details": [
                    {
                        "action": "Added",
                        "type": "CPE Configuration",
                        "newValue": (
                            "OR\n *cpe:2.3:a:snapcreek:duplicator:"
                            "*:*:*:*:lite:wordpress:*:* "
                            "versions up to (excluding) 1.3.0"
                        ),
                    }
                ],
            }
        },
        {
            "change": {
                "cveId": cve_id,
                "cveChangeId": "vendor-remap",
                "created": "2026-02-02T15:06:20.273",
                "details": [
                    {
                        "action": "Changed",
                        "type": "CPE Configuration",
                        "oldValue": (
                            "OR\n *cpe:2.3:a:snapcreek:duplicator:"
                            "*:*:*:*:lite:wordpress:*:* "
                            "versions from (excluding) 1.3.0"
                        ),
                        "newValue": (
                            "OR\n *cpe:2.3:a:awesomemotive:duplicator:"
                            "*:*:*:*:lite:wordpress:*:* "
                            "versions from (excluding) 1.3.0"
                        ),
                    }
                ],
            }
        },
    ]
    return make_nvd_history_response(cve_id, changes)


def make_nvd_history_response(cve_id, changes=None):
    """Wrap fixture events in the complete NVD history response envelope."""
    if changes is None:
        changes = make_history(cve_id)["cveChanges"]
    return {
        "resultsPerPage": len(changes),
        "startIndex": 0,
        "totalResults": len(changes),
        "format": "NVD_CVEHistory",
        "version": "2.0",
        "timestamp": "2026-10-15T00:00:00.000",
        "cveChanges": changes,
    }


def write_research_manifest(path, cve_ids):
    rows = ["cve_id,published"]
    rows.extend(f"{cve_id},2024-01-01T00:00:00+00:00" for cve_id in cve_ids)
    path.write_text("\n".join(rows) + "\n", encoding="utf-8")
    return path


def test_parses_cpe_configuration_events():
    events = parse_cpe_events(make_history())

    assert len(events) == 2
    assert events[0].action == "Added"
    assert events[0].new_pairs == (("snapcreek", "duplicator"),)
    assert events[1].action == "Changed"
    assert events[1].old_pairs == (("snapcreek", "duplicator"),)
    assert events[1].new_pairs == (("awesomemotive", "duplicator"),)
    assert events[0].original_new_value == events[0].new_configurations[0]
    assert events[0].event_name == ""


def test_parses_cpe_configuration_removal():
    history = make_history()
    history["cveChanges"].append(
        {
            "change": {
                "cveId": "CVE-2018-25095",
                "cveChangeId": "vendor-removed",
                "created": "2026-03-01T00:00:00Z",
                "details": [
                    {
                        "action": "Removed",
                        "type": "CPE Configuration",
                        "oldValue": "*cpe:2.3:a:awesomemotive:duplicator:*:*:*:*:*:*:*:*",
                    }
                ],
            }
        }
    )
    events = parse_cpe_events(history)
    assert events[-1].action == "Removed"
    assert events[-1].old_pairs == (("awesomemotive", "duplicator"),)


def test_parses_cwe_changed_values_and_preserves_event_provenance():
    history = make_history()
    history["cveChanges"].append(
        {
            "change": {
                "cveId": "CVE-2018-25095",
                "cveChangeId": "cwe-remap",
                "eventName": "CVE Modified",
                "sourceIdentifier": "nvd@nist.gov",
                "created": "2024-02-01T00:00:00Z",
                "details": [
                    {
                        "action": "Changed",
                        "type": "CWE",
                        "oldValue": "NIST CWE-79",
                        "newValue": "NIST CWE-89",
                    }
                ],
            }
        }
    )
    events = parse_cwe_events(history)
    changed = next(event for event in events if event.event_id == "cwe-remap")
    assert changed.old_cwes == ("CWE-79",)
    assert changed.new_cwes == ("CWE-89",)
    assert changed.original_old_value == "NIST CWE-79"
    assert changed.source_identifier == "nvd@nist.gov"
    assert changed.event_name == "CVE Modified"


def test_future_event_does_not_change_earlier_snapshot():
    history = make_history()
    history["cveChanges"].reverse()

    result = reconstruct_relationships(
        history,
        datetime(2025, 1, 1, tzinfo=UTC),
    )

    assert result.affected == (("snapcreek", "duplicator"),)
    assert ("awesomemotive", "duplicator") not in result.affected


def test_reconstructs_vendor_before_remap():
    result = reconstruct_relationships(
        make_history(),
        datetime(2025, 1, 1, tzinfo=UTC),
    )

    assert result.cve_id == "CVE-2018-25095"
    assert result.affected == (("snapcreek", "duplicator"),)
    assert result.history_available is True
    assert result.history_complete is False


def test_reconstructs_vendor_after_remap():
    result = reconstruct_relationships(
        make_history(),
        datetime(2026, 2, 2, 15, 6, 21, tzinfo=UTC),
    )

    assert result.affected == (("awesomemotive", "duplicator"),)
    assert result.history_complete is False


def test_cutoff_before_first_cpe_event_has_no_confirmed_relationships():
    result = reconstruct_relationships(
        make_history(),
        datetime(2024, 1, 1, tzinfo=UTC),
    )

    assert result.affected == ()
    assert result.history_complete is False
    assert result.warnings
    assert result.feature_eligible is False
    assert "no_interpretable_cpe_events_by_cutoff" in result.exclusion_reasons


def test_uncertain_initial_relationship_state_is_not_feature_eligible():
    history = make_history()
    cpe_change = next(
        item["change"]
        for item in history["cveChanges"]
        if any(detail.get("type") == "CPE Configuration" for detail in item["change"]["details"])
    )
    cpe_change["details"] = [
        {
            "action": "Removed",
            "type": "CPE Configuration",
            "oldValue": "OR\\n *cpe:2.3:a:snapcreek:duplicator:*:*:*:*:*:*:*:*",
        }
    ]

    relationships = reconstruct_relationships(
        history,
        datetime(2025, 1, 1, tzinfo=UTC),
    )

    assert relationships.feature_eligible is False
    assert "uncertain_initial_cpe_state" in relationships.exclusion_reasons
    assert build_historical_graph(relationships).number_of_nodes() == 0


def test_reconstructs_cwe_removal_from_real_history():
    history_path = Path("data/raw/nvd/history/CVE-2022-2081.json")
    history = json.loads(history_path.read_text(encoding="utf-8"))

    before = reconstruct_relationships(
        history,
        datetime(2024, 9, 1, tzinfo=UTC),
    )
    after = reconstruct_relationships(
        history,
        datetime(2024, 9, 26, tzinfo=UTC),
    )

    assert before.cwe_ids == ("CWE-120", "CWE-787")
    assert after.cwe_ids == ("CWE-787",)


def test_preserves_original_cpe_version_constraints():
    events = parse_cpe_events(make_history())

    assert "versions up to (excluding) 1.3.0" in events[0].new_configurations[0]
    assert "versions from (excluding) 1.3.0" in events[1].old_configurations[0]
    assert "versions from (excluding) 1.3.0" in events[1].new_configurations[0]


def test_build_historical_graph_contains_reconstructed_relationships():
    relationships = reconstruct_relationships(
        make_history(),
        datetime(2025, 1, 1, tzinfo=UTC),
    )

    graph = build_historical_graph(relationships)

    assert isinstance(graph, nx.DiGraph)
    assert graph.has_edge(
        "vendor:snapcreek",
        "product:snapcreek:duplicator",
    )
    assert graph.has_edge(
        "product:snapcreek:duplicator",
        "cve:CVE-2018-25095",
    )
    assert graph.nodes["cve:CVE-2018-25095"]["history_complete"] is False


def test_historical_pipeline_exports_features_and_metadata(tmp_path):
    from vesper.components.c_graph.historical_pipeline import (
        run_historical_pipeline,
    )

    history_path = tmp_path / "CVE-2018-25095.json"
    history_path.write_text(
        json.dumps(make_history()),
        encoding="utf-8",
    )

    output_path = tmp_path / "outputs" / "historical_features.csv"

    metadata = run_historical_pipeline(
        history_path=history_path,
        output_path=output_path,
        snapshot_at=datetime(2025, 1, 1, tzinfo=UTC),
    )

    assert output_path.exists()
    assert output_path.with_suffix(".metadata.json").exists()
    assert metadata["cve_id"] == "CVE-2018-25095"
    assert metadata["history_complete"] is False
    assert metadata["feature_rows"] == 1

    saved_metadata = json.loads(
        output_path.with_suffix(".metadata.json").read_text(encoding="utf-8")
    )
    assert saved_metadata == metadata


def test_multi_cve_graph_shares_vendor_and_product_nodes():
    cutoff = datetime(2025, 1, 1, tzinfo=UTC)

    first = reconstruct_relationships(make_history(), cutoff)
    second = reconstruct_relationships(
        make_history("CVE-2023-12345"),
        cutoff,
    )

    graph = build_multi_cve_historical_graph([first, second])

    assert graph.has_edge(
        "vendor:snapcreek",
        "product:snapcreek:duplicator",
    )
    assert graph.has_edge(
        "product:snapcreek:duplicator",
        "cve:CVE-2018-25095",
    )
    assert graph.has_edge(
        "product:snapcreek:duplicator",
        "cve:CVE-2023-12345",
    )

    cve_nodes = [node for node, data in graph.nodes(data=True) if data.get("node_type") == "cve"]
    assert len(cve_nodes) == 2

    # Shared vendor/product nodes must not be duplicated.
    assert list(graph.nodes).count("vendor:snapcreek") == 1
    assert list(graph.nodes).count("product:snapcreek:duplicator") == 1


def test_multi_cve_graph_rejects_duplicate_cves():
    relationships = reconstruct_relationships(
        make_history(),
        datetime(2025, 1, 1, tzinfo=UTC),
    )

    with pytest.raises(ValueError, match="Duplicate CVE"):
        build_multi_cve_historical_graph([relationships, relationships])


def test_multi_historical_pipeline_exports_features_and_metadata(tmp_path):
    from vesper.components.c_graph.multi_historical_pipeline import (
        run_multi_historical_pipeline,
    )

    history_dir = tmp_path / "history"
    history_dir.mkdir()

    (history_dir / "CVE-2018-25095.json").write_text(
        json.dumps(make_nvd_history_response("CVE-2018-25095")),
        encoding="utf-8",
    )
    (history_dir / "CVE-2023-12345.json").write_text(
        json.dumps(make_nvd_history_response("CVE-2023-12345")),
        encoding="utf-8",
    )
    manifest_path = write_research_manifest(
        tmp_path / "research_population.csv",
        ["CVE-2018-25095", "CVE-2023-12345", "CVE-2024-99999"],
    )

    output_path = tmp_path / "outputs" / "multi_features.csv"

    metadata = run_multi_historical_pipeline(
        history_dir=history_dir,
        output_path=output_path,
        snapshot_at=datetime(2025, 1, 1, tzinfo=UTC),
        manifest_path=manifest_path,
    )

    assert output_path.exists()
    assert output_path.with_suffix(".metadata.json").exists()
    assert metadata["history_files_reconstructed"] == 2
    assert metadata["history_files_failed"] == 0
    assert metadata["feature_rows"] == 2
    assert metadata["target_population_size"] == 3
    assert metadata["target_cves_missing_local_history"] == 1
    assert metadata["history_files_selected_for_processing"] == 2
    assert "valid_empty_responses" in metadata["coverage_metric_definitions"]
    assert metadata["cves_in_feature_dataset"] == 2
    assert metadata["exclusion_counts"] == {"missing_history": 1}
    assert metadata["history_complete"] is False
    assert output_path.with_suffix(".exclusions.csv").exists()

    saved_metadata = json.loads(
        output_path.with_suffix(".metadata.json").read_text(encoding="utf-8")
    )
    assert saved_metadata == metadata


def test_multi_historical_pipeline_reports_all_missing_histories(tmp_path):
    from vesper.components.c_graph.multi_historical_pipeline import (
        run_multi_historical_pipeline,
    )

    history_dir = tmp_path / "empty_history"
    history_dir.mkdir()
    manifest_path = write_research_manifest(
        tmp_path / "research_population.csv", ["CVE-2024-12345"]
    )

    output_path = tmp_path / "features.csv"
    metadata = run_multi_historical_pipeline(
        history_dir=history_dir,
        output_path=output_path,
        snapshot_at=datetime(2025, 1, 1, tzinfo=UTC),
        manifest_path=manifest_path,
    )

    assert metadata["target_population_size"] == 1
    assert metadata["target_cves_with_local_history_files"] == 0
    assert metadata["valid_history_responses"] == 0
    assert metadata["successfully_reconstructed_cves"] == 0
    assert metadata["feature_rows"] == 0
    assert metadata["exclusion_counts"] == {"missing_history": 1}
    assert output_path.exists()


def test_multi_historical_pipeline_excludes_cves_published_after_cutoff(tmp_path):
    from vesper.components.c_graph.multi_historical_pipeline import (
        run_multi_historical_pipeline,
    )

    history_dir = tmp_path / "history"
    history_dir.mkdir()
    current = "CVE-2024-10001"
    future = "CVE-2025-10002"
    (history_dir / f"{current}.json").write_text(
        json.dumps(make_nvd_history_response(current)), encoding="utf-8"
    )
    (history_dir / f"{future}.json").write_text(
        json.dumps(make_nvd_history_response(future)), encoding="utf-8"
    )
    manifest_path = tmp_path / "research_population.csv"
    manifest_path.write_text(
        "cve_id,published\n"
        f"{current},2024-01-01T00:00:00+00:00\n"
        f"{future},2025-03-01T00:00:00+00:00\n",
        encoding="utf-8",
    )

    output_path = tmp_path / "features.csv"
    metadata = run_multi_historical_pipeline(
        history_dir=history_dir,
        output_path=output_path,
        snapshot_at=datetime(2025, 1, 1, tzinfo=UTC),
        manifest_path=manifest_path,
    )

    with output_path.open(encoding="utf-8", newline="") as file:
        feature_ids = {row["cve_id"] for row in csv.DictReader(file)}
    with output_path.with_suffix(".exclusions.csv").open(encoding="utf-8", newline="") as file:
        exclusions = {row["cve_id"]: row["reason"] for row in csv.DictReader(file)}

    assert feature_ids == {current}
    assert exclusions == {future: "not_yet_published_at_cutoff"}
    assert metadata["target_population_size"] == 2
    assert metadata["eligible_population_size"] == 1
    assert metadata["target_cves_not_yet_published_at_cutoff"] == 1
    assert metadata["feature_eligible_cves"] == 1


def test_multi_historical_pipeline_reconciles_population_coverage(tmp_path, monkeypatch):
    from vesper.components.c_graph import multi_historical_pipeline as pipeline

    history_dir = tmp_path / "history"
    history_dir.mkdir()
    included = "CVE-2024-10001"
    empty = "CVE-2024-10002"
    missing = "CVE-2024-10003"
    invalid_json = "CVE-2024-10004"
    mismatched = "CVE-2024-10005"
    reconstruction_error = "CVE-2024-10006"
    outside = "CVE-2024-10007"
    manifest_ids = [included, empty, missing, invalid_json, mismatched, reconstruction_error]
    manifest_path = write_research_manifest(tmp_path / "research_population.csv", manifest_ids)

    (history_dir / f"{included}.json").write_text(
        json.dumps(make_nvd_history_response(included)), encoding="utf-8"
    )
    (history_dir / f"{empty}.json").write_text(
        json.dumps(make_nvd_history_response(empty, [])), encoding="utf-8"
    )
    (history_dir / f"{invalid_json}.json").write_text("{", encoding="utf-8")
    (history_dir / f"{mismatched}.json").write_text(
        json.dumps(make_nvd_history_response(mismatched, make_history(outside)["cveChanges"])),
        encoding="utf-8",
    )
    (history_dir / f"{reconstruction_error}.json").write_text(
        json.dumps(make_nvd_history_response(reconstruction_error)), encoding="utf-8"
    )
    (history_dir / f"{outside}.json").write_text(
        json.dumps(make_nvd_history_response(outside)), encoding="utf-8"
    )

    original_reconstruct = pipeline.reconstruct_relationships

    def fail_one_reconstruction(history, snapshot_at, cve_id=None):
        if cve_id == reconstruction_error:
            raise ValueError("fixture reconstruction failure")
        return original_reconstruct(history, snapshot_at, cve_id=cve_id)

    monkeypatch.setattr(pipeline, "reconstruct_relationships", fail_one_reconstruction)
    output_path = tmp_path / "features.csv"
    metadata = pipeline.run_multi_historical_pipeline(
        history_dir,
        output_path,
        datetime(2025, 1, 1, tzinfo=UTC),
        manifest_path=manifest_path,
    )

    assert metadata["target_population_size"] == 6
    assert metadata["target_cves_with_local_history_files"] == 5
    assert metadata["target_cves_missing_local_history"] == 1
    assert metadata["valid_history_responses"] == 3
    assert metadata["valid_empty_responses"] == 1
    assert metadata["responses_with_recorded_events"] == 2
    assert metadata["invalid_history_files"] == 2
    assert metadata["reconstruction_failures"] == 1
    assert metadata["successfully_reconstructed_cves"] == 2
    assert metadata["feature_eligible_cves"] == 1
    assert metadata["cves_in_feature_dataset"] == 1
    assert metadata["history_files_outside_population"] == 1
    assert metadata["exclusion_counts"] == {
        "invalid_history_response": 2,
        "missing_history": 1,
        "reconstruction_failed": 1,
        "valid_empty_history_response": 1,
    }

    with output_path.open(encoding="utf-8", newline="") as file:
        feature_rows = list(csv.DictReader(file))
    assert {row["cve_id"] for row in feature_rows} == {included}
    with output_path.with_suffix(".exclusions.csv").open(encoding="utf-8", newline="") as file:
        exclusions = {row["cve_id"]: row["reason"] for row in csv.DictReader(file)}
    assert exclusions == {
        missing: "missing_history",
        invalid_json: "invalid_history_response",
        mismatched: "invalid_history_response",
        reconstruction_error: "reconstruction_failed",
        empty: "valid_empty_history_response",
    }
    assert outside not in exclusions


@pytest.mark.parametrize(
    ("rows", "message"),
    [
        (
            "CVE-2024-12345,2024-01-01T00:00:00Z\nCVE-2024-12345,2024-01-02T00:00:00Z\n",
            "Duplicate CVE",
        ),
        ("CVE-2024-invalid,2024-01-01T00:00:00Z\n", "Invalid CVE ID"),
        ("CVE-2024-12345,2026-10-15T00:00:00Z\n", "outside research interval"),
        ("CVE-2024-12345,not-a-date\n", "Invalid publication timestamp"),
    ],
)
def test_research_manifest_rejects_duplicate_malformed_and_out_of_range_rows(
    tmp_path, rows, message
):
    from vesper.components.c_graph.multi_historical_pipeline import load_research_manifest

    path = tmp_path / "research_population.csv"
    path.write_text("cve_id,published\n" + rows, encoding="utf-8")

    with pytest.raises(ValueError, match=message):
        load_research_manifest(path)


def test_research_manifest_accepts_inclusive_start_boundary(tmp_path):
    from vesper.components.c_graph.multi_historical_pipeline import load_research_manifest

    path = tmp_path / "research_population.csv"
    path.write_text("cve_id,published\nCVE-2024-12345,2016-01-01T00:00:00Z\n", encoding="utf-8")

    population = load_research_manifest(path)

    assert population["CVE-2024-12345"] == datetime(2016, 1, 1, tzinfo=UTC)


def test_empty_history_response_uses_filename_cve_id():
    result = reconstruct_relationships(
        make_nvd_history_response("CVE-2026-90928", []),
        datetime(2026, 10, 14, 23, 59, 59, tzinfo=UTC),
        cve_id="CVE-2026-90928",
    )

    assert result.cve_id == "CVE-2026-90928"
    assert result.affected == ()
    assert result.cwe_ids == ()
    assert result.history_available is True
    assert result.history_complete is False
    assert result.feature_eligible is False
    assert result.exclusion_reasons == ("valid_empty_history_response",)
    assert any("no recorded events" in warning.lower() for warning in result.warnings)


def test_empty_history_response_requires_valid_cve_id():
    with pytest.raises(ValueError, match="valid CVE ID"):
        reconstruct_relationships(
            make_nvd_history_response("CVE-2026-90928", []),
            datetime(2026, 10, 14, 23, 59, 59, tzinfo=UTC),
        )


def test_affected_github_reference_is_not_treated_as_cpe_data():
    history = {
        "cveChanges": [
            {
                "change": {
                    "cveId": "CVE-2026-90928",
                    "cveChangeId": "affected-reference",
                    "created": "2026-09-14T13:19:30.870",
                    "details": [
                        {
                            "action": "Added",
                            "type": "Affected",
                            "newValue": (
                                "New affected value received. "
                                '<a href="https://github.com/CVEProject/'
                                "cvelistV5/blob/main/cves/2026/90xxx/"
                                'CVE-2026-90928.json">CVE-2026-90928</a>'
                            ),
                        }
                    ],
                }
            }
        ]
    }

    history = make_nvd_history_response("CVE-2026-90928", history["cveChanges"])
    result = reconstruct_relationships(
        history,
        datetime(2026, 10, 14, 23, 59, 59, tzinfo=UTC),
    )

    assert result.cve_id == "CVE-2026-90928"
    assert result.affected == ()
    assert result.history_complete is False
    assert any(
        "Affected" in warning and "unsupported" in warning.lower() for warning in result.warnings
    )
    assert "unsupported_affected_relationship_change" in result.exclusion_reasons
    assert "github_reference_unrecoverable" in result.exclusion_reasons
    assert result.feature_eligible is False
    assert build_historical_graph(result).number_of_nodes() == 0


def test_embedded_affected_json_parses_explicit_products_and_provenance():
    payload = json.dumps(
        [
            {
                "vendor": "GitHub",
                "product": "Enterprise Server",
                "defaultStatus": "unaffected",
                "versions": [
                    {
                        "version": "3.18.0",
                        "lessThanOrEqual": "3.18.5",
                        "versionType": "semver",
                        "status": "affected",
                        "changes": [{"at": "3.18.6", "status": "unaffected"}],
                    }
                ],
            }
        ]
    )
    history = make_history()
    history["cveChanges"].append(
        {
            "change": {
                "cveId": "CVE-2018-25095",
                "cveChangeId": "affected-json-added",
                "eventName": "CVE Modified",
                "sourceIdentifier": "github@github.com",
                "created": "2026-06-17T12:00:00Z",
                "details": [{"action": "Added", "type": "Affected", "newValue": payload}],
            }
        }
    )

    event = parse_affected_events(history)[0]
    assert event.evidence_state == "supported_embedded_affected_data"
    assert event.new_pairs == (("github", "enterprise server"),)
    assert event.original_new_value == payload
    assert event.event_id == "affected-json-added"
    assert event.source_identifier == "github@github.com"
    assert event.event_name == "CVE Modified"

    history = make_nvd_history_response("CVE-2018-25095", history["cveChanges"])
    result = reconstruct_relationships(history, datetime(2026, 6, 18, tzinfo=UTC))
    assert ("github", "enterprise server") in result.affected
    assert result.feature_eligible is True
    assert result.history_complete is False


def test_affected_version_statuses_create_only_explicitly_affected_products():
    payload = json.dumps(
        [
            {
                "vendor": "Vendor A",
                "product": "Affected Product",
                "defaultStatus": "unaffected",
                "versions": [
                    {"version": "1.0", "versionType": "semver", "status": "affected"},
                    {"version": "1.1", "versionType": "semver", "status": "unaffected"},
                ],
            },
            {
                "vendor": "Vendor B",
                "product": "Unaffected Product",
                "defaultStatus": "unaffected",
                "versions": [{"version": "2.0", "versionType": "semver", "status": "unaffected"}],
            },
        ]
    )
    change = {
        "cveId": "CVE-2018-25095",
        "cveChangeId": "affected-status-matrix",
        "eventName": "CVE Modified",
        "sourceIdentifier": "nvd@nist.gov",
        "created": "2026-06-17T12:00:00Z",
        "details": [{"action": "Added", "type": "Affected", "newValue": payload}],
    }
    history = make_history()
    history["cveChanges"].append({"change": change})

    event = parse_affected_events(history)[0]
    assert event.evidence_state == "supported_embedded_affected_data"
    assert event.new_pairs == (("vendor a", "affected product"),)
    assert event.original_new_value == payload
    assert event.cve_id == "CVE-2018-25095"
    assert event.created_at == datetime(2026, 6, 17, 12, 0, tzinfo=UTC)
    assert event.action == "Added"
    assert event.event_id == "affected-status-matrix"
    assert event.event_name == "CVE Modified"
    assert event.source_identifier == "nvd@nist.gov"

    result = reconstruct_relationships(
        make_nvd_history_response("CVE-2018-25095", history["cveChanges"]),
        datetime(2026, 6, 18, tzinfo=UTC),
    )
    assert ("vendor a", "affected product") in result.affected
    assert ("vendor b", "unaffected product") not in result.affected
    assert result.feature_eligible is True


def test_affected_add_change_remove_events_update_only_the_affected_source():
    def encoded(vendor, product):
        return json.dumps([{"vendor": vendor, "product": product, "defaultStatus": "affected"}])

    history = make_history()
    history["cveChanges"].extend(
        [
            {
                "change": {
                    "cveId": "CVE-2018-25095",
                    "cveChangeId": "affected-add",
                    "eventName": "CVE Modified",
                    "sourceIdentifier": "nvd@nist.gov",
                    "created": "2026-03-01T00:00:00Z",
                    "details": [
                        {
                            "action": "Added",
                            "type": "Affected",
                            "newValue": encoded("Vendor A", "Product A"),
                        }
                    ],
                }
            },
            {
                "change": {
                    "cveId": "CVE-2018-25095",
                    "cveChangeId": "affected-change",
                    "eventName": "CVE Modified",
                    "sourceIdentifier": "nvd@nist.gov",
                    "created": "2026-03-02T00:00:00Z",
                    "details": [
                        {
                            "action": "Changed",
                            "type": "Affected",
                            "oldValue": encoded("Vendor A", "Product A"),
                            "newValue": encoded("Vendor B", "Product B"),
                        }
                    ],
                }
            },
            {
                "change": {
                    "cveId": "CVE-2018-25095",
                    "cveChangeId": "affected-remove",
                    "eventName": "CVE Modified",
                    "sourceIdentifier": "nvd@nist.gov",
                    "created": "2026-03-03T00:00:00Z",
                    "details": [
                        {
                            "action": "Removed",
                            "type": "Affected",
                            "oldValue": encoded("Vendor B", "Product B"),
                        }
                    ],
                }
            },
        ]
    )
    events = parse_affected_events(history)
    assert [event.action for event in events] == ["Added", "Changed", "Removed"]
    added, changed, removed = events
    assert added.original_new_value == encoded("Vendor A", "Product A")
    assert changed.original_old_value == encoded("Vendor A", "Product A")
    assert changed.original_new_value == encoded("Vendor B", "Product B")
    assert removed.original_old_value == encoded("Vendor B", "Product B")
    assert [event.event_id for event in events] == [
        "affected-add",
        "affected-change",
        "affected-remove",
    ]
    assert [event.cve_id for event in events] == ["CVE-2018-25095"] * 3
    assert [event.event_name for event in events] == ["CVE Modified"] * 3
    assert [event.source_identifier for event in events] == ["nvd@nist.gov"] * 3
    assert [event.created_at for event in events] == [
        datetime(2026, 3, 1, tzinfo=UTC),
        datetime(2026, 3, 2, tzinfo=UTC),
        datetime(2026, 3, 3, tzinfo=UTC),
    ]
    history = make_nvd_history_response("CVE-2018-25095", history["cveChanges"])
    result = reconstruct_relationships(history, datetime(2026, 3, 4, tzinfo=UTC))
    assert ("vendor a", "product a") not in result.affected
    assert ("vendor b", "product b") not in result.affected
    assert ("awesomemotive", "duplicator") in result.affected
    assert result.feature_eligible is True


def test_affected_data_without_explicit_affected_status_is_excluded():
    history = make_history()
    history["cveChanges"].append(
        {
            "change": {
                "cveId": "CVE-2018-25095",
                "cveChangeId": "affected-status-unknown",
                "created": "2026-06-17T12:00:00Z",
                "details": [
                    {
                        "action": "Added",
                        "type": "Affected",
                        "newValue": json.dumps(
                            [
                                {
                                    "vendor": "Vendor C",
                                    "product": "Product C",
                                    "defaultStatus": "unknown",
                                }
                            ]
                        ),
                    }
                ],
            }
        }
    )
    history = make_nvd_history_response("CVE-2018-25095", history["cveChanges"])
    result = reconstruct_relationships(history, datetime(2026, 6, 18, tzinfo=UTC))
    assert result.feature_eligible is False
    assert "affected_status_uncertain" in result.exclusion_reasons
    assert build_historical_graph(result).number_of_nodes() == 0


@pytest.mark.parametrize(
    "record",
    [
        {"vendor": "Vendor D", "product": "Missing Status Product"},
        {
            "vendor": "Vendor D",
            "product": "Ambiguous Status Product",
            "versions": [{"version": "1.0", "status": "unknown"}],
        },
    ],
    ids=["missing-status", "unknown-version-status"],
)
def test_missing_or_ambiguous_affected_status_never_creates_a_product(record):
    payload = json.dumps([record])
    history = make_history()
    history["cveChanges"].append(
        {
            "change": {
                "cveId": "CVE-2018-25095",
                "cveChangeId": "uncertain-affected-status",
                "created": "2026-06-17T12:00:00Z",
                "details": [{"action": "Added", "type": "Affected", "newValue": payload}],
            }
        }
    )

    event = parse_affected_events(history)[0]
    assert event.evidence_state == "affected_status_uncertain"
    assert event.new_pairs == ()
    assert event.original_new_value == payload

    result = reconstruct_relationships(
        make_nvd_history_response("CVE-2018-25095", history["cveChanges"]),
        datetime(2026, 6, 18, tzinfo=UTC),
    )
    assert ("vendor d", record["product"].casefold()) not in result.affected
    assert result.feature_eligible is False
    assert "affected_status_uncertain" in result.exclusion_reasons
    assert build_historical_graph(result).number_of_nodes() == 0
