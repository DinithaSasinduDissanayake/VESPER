
"""Tests for historical Component C relationship reconstruction."""

from datetime import datetime, timezone
import json
from pathlib import Path

import networkx as nx
import pytest

from vesper.components.c_graph.historical import (
    build_historical_graph,
    build_multi_cve_historical_graph,
    parse_cpe_events,
    reconstruct_relationships,
)


def make_history(cve_id="CVE-2018-25095"):
    """Create a history fixture containing a real-style vendor change."""
    return {
        "cveChanges": [
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
    }


def test_parses_cpe_configuration_events():
    events = parse_cpe_events(make_history())

    assert len(events) == 2
    assert events[0].action == "Added"
    assert events[0].new_pairs == (("snapcreek", "duplicator"),)
    assert events[1].action == "Changed"
    assert events[1].old_pairs == (("snapcreek", "duplicator"),)
    assert events[1].new_pairs == (("awesomemotive", "duplicator"),)


def test_future_event_does_not_change_earlier_snapshot():
    history = make_history()
    history["cveChanges"].reverse()

    result = reconstruct_relationships(
        history,
        datetime(2025, 1, 1, tzinfo=timezone.utc),
    )

    assert result.affected == (("snapcreek", "duplicator"),)
    assert ("awesomemotive", "duplicator") not in result.affected


def test_reconstructs_vendor_before_remap():
    result = reconstruct_relationships(
        make_history(),
        datetime(2025, 1, 1, tzinfo=timezone.utc),
    )

    assert result.cve_id == "CVE-2018-25095"
    assert result.affected == (("snapcreek", "duplicator"),)
    assert result.history_available is True
    assert result.history_complete is False


def test_reconstructs_vendor_after_remap():
    result = reconstruct_relationships(
        make_history(),
        datetime(2026, 2, 2, 15, 6, 21, tzinfo=timezone.utc),
    )

    assert result.affected == (("awesomemotive", "duplicator"),)
    assert result.history_complete is False


def test_cutoff_before_first_cpe_event_has_no_confirmed_relationships():
    result = reconstruct_relationships(
        make_history(),
        datetime(2024, 1, 1, tzinfo=timezone.utc),
    )

    assert result.affected == ()
    assert result.history_complete is False
    assert result.warnings


def test_reconstructs_cwe_removal_from_real_history():
    history_path = Path("data/raw/nvd/history/CVE-2022-2081.json")
    history = json.loads(history_path.read_text(encoding="utf-8"))

    before = reconstruct_relationships(
        history,
        datetime(2024, 9, 1, tzinfo=timezone.utc),
    )
    after = reconstruct_relationships(
        history,
        datetime(2024, 9, 26, tzinfo=timezone.utc),
    )

    assert before.cwe_ids == ("CWE-120", "CWE-787")
    assert after.cwe_ids == ("CWE-787",)


def test_preserves_original_cpe_version_constraints():
    events = parse_cpe_events(make_history())

    assert "versions up to (excluding) 1.3.0" in (
        events[0].new_configurations[0]
    )
    assert "versions from (excluding) 1.3.0" in (
        events[1].old_configurations[0]
    )
    assert "versions from (excluding) 1.3.0" in (
        events[1].new_configurations[0]
    )


def test_build_historical_graph_contains_reconstructed_relationships():
    relationships = reconstruct_relationships(
        make_history(),
        datetime(2025, 1, 1, tzinfo=timezone.utc),
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
        snapshot_at=datetime(2025, 1, 1, tzinfo=timezone.utc),
    )

    assert output_path.exists()
    assert output_path.with_suffix(".metadata.json").exists()
    assert metadata["cve_id"] == "CVE-2018-25095"
    assert metadata["history_complete"] is False
    assert metadata["feature_rows"] == 1

    saved_metadata = json.loads(
        output_path.with_suffix(".metadata.json").read_text(
            encoding="utf-8"
        )
    )
    assert saved_metadata == metadata


def test_multi_cve_graph_shares_vendor_and_product_nodes():
    cutoff = datetime(2025, 1, 1, tzinfo=timezone.utc)

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

    cve_nodes = [
        node
        for node, data in graph.nodes(data=True)
        if data.get("node_type") == "cve"
    ]
    assert len(cve_nodes) == 2

    # Shared vendor/product nodes must not be duplicated.
    assert list(graph.nodes).count("vendor:snapcreek") == 1
    assert list(graph.nodes).count("product:snapcreek:duplicator") == 1


def test_multi_cve_graph_rejects_duplicate_cves():
    relationships = reconstruct_relationships(
        make_history(),
        datetime(2025, 1, 1, tzinfo=timezone.utc),
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
        json.dumps(make_history("CVE-2018-25095")),
        encoding="utf-8",
    )
    (history_dir / "CVE-2023-12345.json").write_text(
        json.dumps(make_history("CVE-2023-12345")),
        encoding="utf-8",
    )

    output_path = tmp_path / "outputs" / "multi_features.csv"

    metadata = run_multi_historical_pipeline(
        history_dir=history_dir,
        output_path=output_path,
        snapshot_at=datetime(2025, 1, 1, tzinfo=timezone.utc),
    )

    assert output_path.exists()
    assert output_path.with_suffix(".metadata.json").exists()
    assert metadata["history_files_reconstructed"] == 2
    assert metadata["history_files_failed"] == 0
    assert metadata["feature_rows"] == 2
    assert metadata["history_complete"] is False

    saved_metadata = json.loads(
        output_path.with_suffix(".metadata.json").read_text(
            encoding="utf-8"
        )
    )
    assert saved_metadata == metadata


def test_multi_historical_pipeline_rejects_empty_history_directory(tmp_path):
    from vesper.components.c_graph.multi_historical_pipeline import (
        run_multi_historical_pipeline,
    )

    history_dir = tmp_path / "empty_history"
    history_dir.mkdir()

    with pytest.raises(ValueError, match="No CVE history JSON files"):
        run_multi_historical_pipeline(
            history_dir=history_dir,
            output_path=tmp_path / "features.csv",
            snapshot_at=datetime(2025, 1, 1, tzinfo=timezone.utc),
        )
