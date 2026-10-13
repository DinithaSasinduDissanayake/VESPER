
"""Tests for historical graph export and scoring."""

import gzip
import json
from datetime import date, datetime, timezone

import pytest

from vesper.components.c_graph.export_features import export_features
from vesper.components.c_graph.export_historical_features import (
    export_historical_features,
)
from vesper.components.c_graph.graph import KnowledgeGraph
from vesper.components.c_graph.history_reconstruction import (
    reconstruct_relationships,
)
from vesper.components.c_graph.scoring import calculate_cve_features
from vesper.contracts.vulnerability import Vulnerability


def _write_nvd_input(input_path, cve_id="CVE-2024-21732"):
    """Write a minimal compressed NVD dataset for export tests."""
    data = {
        "vulnerabilities": [
            {
                "cve": {
                    "id": cve_id,
                    "published": "2024-01-01T08:15:36.087Z",
                    "lastModified": "2026-06-17T07:10:02.103Z",
                    "descriptions": [],
                    "metrics": {},
                    "weaknesses": [],
                    "configurations": [],
                }
            }
        ]
    }

    with gzip.open(input_path, "wt", encoding="utf-8") as file:
        json.dump(data, file)


def _valid_history():
    """Return a sample history response with dated CWE and CPE evidence."""
    return {
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
                                "cpe:2.3:a:flycms_project:flycms:"
                                "*:*:*:*:*:*:*:*"
                            ),
                        },
                    ],
                }
            }
        ]
    }


def test_reconstructed_relationships_can_be_scored():
    history = _valid_history()
    snapshot = date(2024, 2, 1)

    historical = reconstruct_relationships(
        "CVE-2024-21732",
        history,
        snapshot,
    )

    timestamp = datetime(2024, 1, 1, tzinfo=timezone.utc)
    vulnerability = Vulnerability(
        cve_id=historical.cve_id,
        published_at=timestamp,
        last_modified_at=timestamp,
        description="Historical relationship integration test",
        cvss_base_score=None,
        cvss_version=None,
        cvss_vector=None,
        cwe_ids=historical.cwe_ids,
        affected=historical.affected,
        nvd_status="Unknown",
        snapshot_date=historical.snapshot_date,
    )

    graph = KnowledgeGraph()
    graph.add_vulnerability(vulnerability)
    features = calculate_cve_features(graph)

    assert ("vendor", "flycms_project") in graph.nodes
    assert ("product", "flycms_project:flycms") in graph.nodes
    assert ("cve", "CVE-2024-21732") in graph.nodes
    assert ("cwe", "CWE-79") in graph.nodes
    assert len(features) == 1
    assert features.iloc[0]["cve_id"] == "CVE-2024-21732"


def test_export_does_not_overwrite_existing_output_on_rejection(tmp_path):
    input_path = tmp_path / "nvd.json.gz"
    output_path = tmp_path / "features.csv"

    output_path.write_text("existing output\n", encoding="utf-8")
    _write_nvd_input(input_path)

    with pytest.raises(ValueError, match="Export stopped"):
        export_features(input_path, output_path, date(2024, 2, 1))

    assert output_path.read_text(encoding="utf-8") == "existing output\n"


def test_historical_export_stops_when_history_file_is_missing(tmp_path):
    input_path = tmp_path / "nvd.json.gz"
    history_dir = tmp_path / "history"
    output_path = tmp_path / "historical_features.csv"

    history_dir.mkdir()
    output_path.write_text("existing output\n", encoding="utf-8")
    _write_nvd_input(input_path)

    with pytest.raises(ValueError, match="Historical export stopped"):
        export_historical_features(
            input_path,
            history_dir,
            output_path,
            date(2024, 2, 1),
        )

    assert output_path.read_text(encoding="utf-8") == "existing output\n"


def test_historical_export_writes_features_when_history_is_available(tmp_path):
    input_path = tmp_path / "nvd.json.gz"
    history_dir = tmp_path / "history"
    output_path = tmp_path / "historical_features.csv"

    history_dir.mkdir()
    _write_nvd_input(input_path)

    (history_dir / "CVE-2024-21732.json").write_text(
        json.dumps(_valid_history()),
        encoding="utf-8",
    )

    export_historical_features(
        input_path,
        history_dir,
        output_path,
        date(2024, 2, 1),
    )

    assert output_path.is_file()

    import pandas as pd

    features = pd.read_csv(output_path)

    assert len(features) == 1
    assert features.iloc[0]["cve_id"] == "CVE-2024-21732"
    assert {
        "in_degree_centrality",
        "out_degree_centrality",
        "pagerank",
    }.issubset(features.columns)


def test_historical_export_preserves_output_when_history_json_is_invalid(
    tmp_path,
):
    input_path = tmp_path / "nvd.json.gz"
    history_dir = tmp_path / "history"
    output_path = tmp_path / "historical_features.csv"

    history_dir.mkdir()
    output_path.write_text("existing output\n", encoding="utf-8")
    _write_nvd_input(input_path)

    (history_dir / "CVE-2024-21732.json").write_text(
        "{invalid json",
        encoding="utf-8",
    )

    with pytest.raises(json.JSONDecodeError):
        export_historical_features(
            input_path,
            history_dir,
            output_path,
            date(2024, 2, 1),
        )

    assert output_path.read_text(encoding="utf-8") == "existing output\n"


def test_historical_export_rejects_history_without_cve_changes(tmp_path):
    input_path = tmp_path / "nvd.json.gz"
    history_dir = tmp_path / "history"
    output_path = tmp_path / "historical_features.csv"

    history_dir.mkdir()
    output_path.write_text("existing output\n", encoding="utf-8")
    _write_nvd_input(input_path)

    (history_dir / "CVE-2024-21732.json").write_text(
        json.dumps({"cveId": "CVE-2024-21732"}),
        encoding="utf-8",
    )

    with pytest.raises(ValueError, match="cveChanges"):
        export_historical_features(
            input_path,
            history_dir,
            output_path,
            date(2024, 2, 1),
        )

    assert output_path.read_text(encoding="utf-8") == "existing output\n"
