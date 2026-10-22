"""Artifact joins, fail-closed API behavior and indexed lookup regression tests."""

import csv
import hashlib
import json
import os
from collections import Counter

import pytest
from fastapi.testclient import TestClient

from vesper.api import c_graph
from vesper.api.main import app

REFERENCE = "2026-10-15T00:00:00+00:00"
IDENTITY = {
    "snapshot_id": "nvd-current-snapshot-2026-10-15",
    "graph_scope_id": "nvd-current-snapshot-2026-10-15-graph-test",
    "reference_timestamp": REFERENCE,
}


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def write_csv(path, rows):
    with path.open("w", encoding="utf-8", newline="") as stream:
        writer = csv.DictWriter(stream, fieldnames=list(rows[0]))
        writer.writeheader()
        writer.writerows(rows)


@pytest.fixture
def artifacts(tmp_path, monkeypatch):
    provider, scores, analysis = [
        tmp_path / name for name in ("provider.csv", "scores.csv", "analysis.csv")
    ]
    provider_rows, score_rows, analysis_rows = [], [], []
    for number, value, status in (
        (1, "0.97", "available"),
        (2, "0", "available"),
        (3, "", "not_eligible"),
    ):
        available = status == "available"
        score = {
            "cve_id": f"CVE-2024-{number:04d}",
            "component": "c_graph",
            "decision_time": REFERENCE,
            "horizon_days": "30",
            "score": value,
            "score_kind": "ranking_score",
            "status": status,
            "reason": "" if available else "record_rejected",
            "model_version": c_graph.ADAPTER_VERSION,
            "trained_through": "",
            "snapshot_date": "2026-10-15",
        }
        raw = "0.0000428" if available else ""
        source = {
            **score,
            **IDENTITY,
            "score": raw,
            "pagerank": raw,
            "model_version": c_graph.PROVIDER_VERSION,
            "feature_schema_version": "1.0.0",
            "in_degree_centrality": "0.01" if available else "",
            "out_degree_centrality": "0.02" if available else "",
            "pagerank_status": status,
            "vendor_product_evidence_json": '[["vendor","product"],["vendor","product"]]'
            if available
            else "",
            "cwe_ids_json": '["CWE-79","CWE-79","CWE-20"]' if available else "",
            "cpe_evidence_status": "supported" if available else "not_evaluated",
            "cpe_evidence_reason": "" if available else "record_not_evaluated",
            "cwe_evidence_status": "supported" if available else "not_evaluated",
            "cwe_evidence_reason": "" if available else "record_not_evaluated",
            "source_record_published_at": "2024-01-01T00:00:00Z",
            "source_record_last_modified_at": REFERENCE,
            "source_nvd_file": "nvd_2024-01.json.gz",
            "feature_provenance": "saved_current_snapshot_graph_and_local_nvd_record",
        }
        provider_rows.append(source)
        score_rows.append(score)
        analysis_rows.append(
            {
                "cve_id": score["cve_id"],
                **IDENTITY,
                "pagerank": raw,
                "degree": "7.0" if available else "",
                "P_pagerank": "0.94" if available else "",
                "P_cvss": "0.76" if available else "",
                "pagerank_cvss_disagreement": "0.18" if available else "",
                "analysis_status": "available" if available else status,
                "analysis_reason": "" if available else "record_rejected",
            }
        )

    def save():
        write_csv(provider, provider_rows)
        write_csv(scores, score_rows)
        write_csv(analysis, analysis_rows)
        counts = dict(Counter(row["status"] for row in provider_rows))
        provider.with_suffix(".metadata.json").write_text(
            json.dumps(
                {
                    **IDENTITY,
                    "historical_reconstruction": "not_performed",
                    "feature_schema_version": "1.0.0",
                    "output_sha256": digest(provider),
                    "counts": {
                        "population_cves": len(provider_rows),
                        "shared_score_status_counts": counts,
                    },
                }
            )
        )
        (tmp_path / "scores.csv.metadata.json").write_text(
            json.dumps(
                {
                    **IDENTITY,
                    "model_version": [c_graph.ADAPTER_VERSION],
                    "output_sha256": digest(scores),
                    "source_provider_sha256": digest(provider),
                    "rows": len(score_rows),
                    "percentile_population": counts.get("available", 0),
                    "status_counts": counts,
                }
            )
        )

    save()
    monkeypatch.setenv("VESPER_C_FEATURE_PROVIDER_CSV", str(provider))
    monkeypatch.setenv("VESPER_C_SCORES_CSV", str(scores))
    monkeypatch.setenv("VESPER_C_DISAGREEMENT_CSV", str(analysis))
    if c_graph._index:
        c_graph._index.directory.cleanup()
    c_graph._index = None
    yield provider_rows, score_rows, analysis_rows, save
    if c_graph._index:
        c_graph._index.directory.cleanup()
    c_graph._index = None


@pytest.fixture
def client():
    with TestClient(app) as client:
        yield client


def test_current_response_preserves_three_distinct_values_and_raw_degree(client, artifacts):
    response = client.get("/api/c-graph/cves/CVE-2024-0001")
    assert response.status_code == 200, response.text
    data = response.json()
    assert data["structural_score"] == 0.97
    assert data["raw_pagerank"] == 0.0000428
    assert data["pagerank_comparison_percentile"] == 0.94
    assert data["cvss_percentile"] == 0.76
    assert data["pagerank_cvss_disagreement"] == 0.18
    assert data["degree"] == 7  # Neither normalized centrality nor inferred relationship count.
    assert data["scoring_population"] == 2
    assert data["comparison_population"] == 2
    assert data["vendor_product_relationships"] == [{"vendor": "vendor", "product": "product"}]
    assert data["cwe_ids"] == ["CWE-20", "CWE-79"]
    assert data["provenance"]["provider_sha256"]


def test_zero_remains_zero(client, artifacts):
    data = client.get("/api/c-graph/cves/CVE-2024-0002").json()
    assert data["structural_score"] == 0
    assert data["score_status"] == "available"


def test_large_validated_relationship_field_is_supported(client, artifacts):
    provider, _, _, save = artifacts
    provider[0]["vendor_product_evidence_json"] = json.dumps(
        [["vendor", f"long_product_identifier_{number}"] for number in range(6000)]
    )
    assert len(provider[0]["vendor_product_evidence_json"]) > 131072
    save()
    response = client.get("/api/c-graph/cves/CVE-2024-0001")
    assert response.status_code == 200, response.text
    assert len(response.json()["vendor_product_relationships"]) == 6000


def test_abstention_keeps_independent_supported_product_evidence(client, artifacts):
    provider, scores, analysis, save = artifacts
    provider[2].update(
        status="abstained",
        pagerank_status="abstained",
        reason="insufficient_graph_evidence",
        cpe_evidence_status="supported",
        cpe_evidence_reason="",
        vendor_product_evidence_json='[["vendor","product"]]',
        cwe_evidence_status="unavailable",
        cwe_evidence_reason="no_supported_cwe",
    )
    scores[2].update(status="abstained", reason="insufficient_graph_evidence")
    analysis[2].update(analysis_status="abstained", analysis_reason="insufficient_graph_evidence")
    save()
    response = client.get("/api/c-graph/cves/CVE-2024-0003")
    assert response.status_code == 200, response.text
    data = response.json()
    assert data["structural_score"] is None
    assert data["vendor_product_relationships"] == [{"vendor": "vendor", "product": "product"}]
    assert data["cwe_ids"] == []
    assert data["cwe_evidence_status"] == "unavailable"


def test_unavailable_is_null_with_reason(client, artifacts):
    data = client.get("/api/c-graph/cves/CVE-2024-0003").json()
    assert data["score_status"] == "not_eligible"
    assert data["structural_score"] is None
    assert data["raw_pagerank"] is None
    assert data["degree"] is None
    assert data["cvss_percentile"] is None
    assert data["score_reason"] == "record_rejected"
    assert data["cwe_evidence_status"] == "not_evaluated"


def test_unknown_cve_and_invalid_identifier(client, artifacts):
    assert client.get("/api/c-graph/cves/CVE-2024-9999").status_code == 404
    assert client.get("/api/c-graph/cves/not-a-cve").status_code == 422


def test_optional_analysis_does_not_fabricate_degree_or_comparison(client, artifacts, monkeypatch):
    monkeypatch.delenv("VESPER_C_DISAGREEMENT_CSV")
    data = client.get("/api/c-graph/cves/CVE-2024-0001").json()
    assert data["structural_score"] == 0.97
    assert data["degree"] is None
    assert data["comparison_population"] is None
    assert data["pagerank_comparison_percentile"] is None
    assert data["comparison_reason"] == "Disagreement analysis is not configured."


def test_missing_configuration_is_explicit_not_a_fixture_fallback(
    client, artifacts, monkeypatch, tmp_path
):
    monkeypatch.setenv("VESPER_C_SCORES_CSV", str(tmp_path / "absent.csv"))
    response = client.get("/api/c-graph/cves/CVE-2024-0001")
    assert response.status_code == 503
    assert "VESPER_C_SCORES_CSV" in response.json()["detail"]


@pytest.mark.parametrize(
    "layer,value", [("cpe", "not-json"), ("cpe", '[["vendor"]]'), ("cwe", '["invented weakness"]')]
)
def test_malformed_relationship_evidence_fails_closed(client, artifacts, layer, value):
    provider, _, _, save = artifacts
    provider[0]["vendor_product_evidence_json" if layer == "cpe" else "cwe_ids_json"] = value
    save()
    assert client.get("/api/c-graph/cves/CVE-2024-0001").status_code == 422


@pytest.mark.parametrize(
    "failure",
    [
        "snapshot",
        "checksum",
        "duplicate",
        "population",
        "comparison",
        "degree",
        "raw",
        "historical",
        "missing_score",
        "nan",
    ],
)
def test_conflicting_artifacts_fail_closed(client, artifacts, failure, monkeypatch):
    provider, scores, analysis, save = artifacts
    if failure == "snapshot":
        analysis[0]["snapshot_id"] = "another-snapshot"
    elif failure == "duplicate":
        analysis.append(dict(analysis[0]))
    elif failure == "population":
        analysis.pop()
    elif failure == "comparison":
        analysis[0]["pagerank_cvss_disagreement"] = "0.5"
    elif failure == "degree":
        analysis[0]["degree"] = "0.12"
    elif failure == "raw":
        analysis[0]["pagerank"] = "0.2"
    elif failure == "historical":
        scores[0]["model_version"] = "c_graph-pagerank-percentile-historical-structural-0.1"
    elif failure == "missing_score":
        scores[0]["score"] = ""
    elif failure == "nan":
        scores[0]["score"] = "NaN"
    save()
    if failure == "checksum":
        with open(os.environ["VESPER_C_SCORES_CSV"], "a") as stream:
            stream.write("\n")
    assert client.get("/api/c-graph/cves/CVE-2024-0001").status_code == 422


def test_warm_lookup_reuses_index_and_metadata_change_invalidates(client, artifacts, monkeypatch):
    assert client.get("/api/c-graph/cves/CVE-2024-0001").status_code == 200
    index = c_graph._index
    original = c_graph._build_index
    monkeypatch.setattr(
        c_graph, "_build_index", lambda *args: pytest.fail("Warm lookup reparsed artifacts")
    )
    assert client.get("/api/c-graph/cves/CVE-2024-0002").status_code == 200
    assert c_graph._index is index
    monkeypatch.setattr(c_graph, "_build_index", original)
    provider, _, _, save = artifacts
    provider[0]["vendor_product_evidence_json"] = '[["vendor","updated_product"]]'
    save()
    response = client.get("/api/c-graph/cves/CVE-2024-0001")
    assert response.status_code == 200
    assert response.json()["vendor_product_relationships"][0]["product"] == "updated_product"
    assert c_graph._index is not index


def test_shared_api_health_remains_registered(client):
    assert client.get("/api/health").json() == {"status": "ok"}
    paths = app.openapi()["paths"]
    assert "/api/d-fusion/ranking" in paths
    assert "/api/d-fusion/knapsack" in paths
