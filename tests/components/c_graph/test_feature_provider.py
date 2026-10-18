"""Contract tests for the current-snapshot Component C feature provider."""

from datetime import UTC, datetime

import pandas as pd
import pytest

from vesper.components.c_graph.feature_provider import (
    FEATURE_PROVIDER_COLUMNS,
    build_feature_provider,
    validate_feature_provider,
)
from vesper.components.c_graph.multi_historical_pipeline import load_research_manifest
from vesper.components.c_graph.score_export import SCORE_COLUMNS
from vesper.components.c_graph.scoring import FEATURE_COLUMNS

AT = datetime(2026, 10, 15, tzinfo=UTC)
IDS = ["CVE-2024-12345", "CVE-2024-23456", "CVE-2024-34567"]


def _scores() -> pd.DataFrame:
    rows = [
        [
            IDS[0],
            "c_graph",
            AT.isoformat(),
            30,
            0.125,
            "ranking_score",
            "available",
            "",
            "c_graph-pagerank-structural-0.1",
            "",
            "2026-10-15",
        ],
        [
            IDS[1],
            "c_graph",
            AT.isoformat(),
            30,
            0.25,
            "ranking_score",
            "available",
            "",
            "c_graph-pagerank-structural-0.1",
            "",
            "2026-10-15",
        ],
        [
            IDS[2],
            "c_graph",
            AT.isoformat(),
            30,
            None,
            "ranking_score",
            "not_eligible",
            "Rejected by NVD",
            "c_graph-pagerank-structural-0.1",
            "",
            "2026-10-15",
        ],
    ]
    return pd.DataFrame(rows, columns=SCORE_COLUMNS)


def _features() -> pd.DataFrame:
    return pd.DataFrame(
        [
            [IDS[0], 0.2, 0.4, 0.125],
            [IDS[1], 0.1, 0.3, 0.25],
        ],
        columns=FEATURE_COLUMNS,
    )


def _evidence() -> dict:
    return {
        IDS[0]: {
            "published_at": "2024-01-10T00:00:00+00:00",
            "last_modified_at": "2024-01-15T00:00:00+00:00",
            "vendor_product_pairs": (("vendor", "product"),),
            "cwe_ids": ("CWE-79",),
            "nvd_status": "analyzed",
            "source_nvd_file": "nvd_2024-01.json.gz",
        },
        IDS[1]: {
            "published_at": "2024-02-10T00:00:00+00:00",
            "last_modified_at": "2024-02-15T00:00:00+00:00",
            "vendor_product_pairs": (("vendor", "product-two"),),
            "cwe_ids": (),
            "nvd_status": "analyzed",
            "source_nvd_file": "nvd_2024-02.json.gz",
        },
        IDS[2]: {
            "published_at": "2024-03-10T00:00:00+00:00",
            "last_modified_at": "2024-03-15T00:00:00+00:00",
            "vendor_product_pairs": (),
            "cwe_ids": (),
            "nvd_status": "rejected",
            "source_nvd_file": "nvd_2024-03.json.gz",
        },
    }


def _provider() -> pd.DataFrame:
    return build_feature_provider(
        _features(),
        _scores(),
        target_cve_ids=IDS,
        evidence_by_id=_evidence(),
        snapshot_at=AT,
        snapshot_id="nvd-current-snapshot-2026-10-15",
        graph_scope_id="nvd-current-snapshot-2026-10-15-graph-test",
    )


def test_provider_has_versioned_superset_of_shared_score_contract():
    frame = _provider()
    assert frame.columns.tolist() == FEATURE_PROVIDER_COLUMNS
    assert frame.columns[: len(SCORE_COLUMNS)].tolist() == SCORE_COLUMNS
    assert frame["cve_id"].is_unique
    assert frame["status"].tolist() == ["available", "available", "not_eligible"]
    validate_feature_provider(frame, reference_timestamp=AT, expected_cve_ids=set(IDS))


def test_partial_evidence_is_distinct_from_unavailable_feature_values():
    frame = _provider().set_index("cve_id")
    partial = frame.loc[IDS[1]]
    assert partial["cpe_evidence_status"] == "supported"
    assert partial["cwe_evidence_status"] == "unavailable"
    assert partial["cwe_ids_json"] == ""
    assert partial["cwe_evidence_reason"]
    # The saved snapshot graph metrics are preserved as calculated; no missing
    # layer evidence is serialized as an empty relationship list or zero score.
    assert partial["score"] == 0.25
    assert partial["pagerank"] == 0.25


def test_ineligible_values_remain_blank_and_evidence_is_not_evaluated():
    row = _provider().set_index("cve_id").loc[IDS[2]]
    assert row["status"] == "not_eligible"
    assert pd.isna(row["score"])
    assert pd.isna(row["pagerank"])
    assert pd.isna(row["in_degree_centrality"])
    assert row["cpe_evidence_status"] == "not_evaluated"
    assert row["cwe_evidence_status"] == "not_evaluated"


def test_provider_generation_is_deterministic():
    first = _provider()
    second = _provider()
    pd.testing.assert_frame_equal(first, second)
    assert first.to_csv(index=False) == second.to_csv(index=False)


@pytest.mark.parametrize(
    "mutate, message",
    [
        (lambda frame: frame.drop(columns="snapshot_id"), "missing required columns"),
        (lambda frame: pd.concat([frame, frame.iloc[[0]]]), "duplicate CVE"),
        (lambda frame: frame.assign(pagerank=float("inf")), "finite and in \\[0, 1\\]"),
        (
            lambda frame: frame.assign(reference_timestamp="2026-10-16T00:00:00+00:00"),
            "inconsistent",
        ),
        (lambda frame: frame.assign(status="not_eligible"), "disagrees with shared Score status"),
    ],
)
def test_provider_validator_rejects_contract_inconsistencies(mutate, message):
    invalid = mutate(_provider())
    with pytest.raises(ValueError, match=message):
        validate_feature_provider(invalid)


def test_provider_validator_rejects_timestamp_inconsistent_with_source_record():
    invalid = _provider()
    invalid.loc[0, "source_record_last_modified_at"] = "2026-10-16T00:00:00+00:00"
    with pytest.raises(ValueError, match="cannot be after the reference timestamp"):
        validate_feature_provider(invalid)


def test_provider_validator_requires_evidence_array_for_supported_status():
    invalid = _provider()
    invalid.loc[0, "vendor_product_evidence_json"] = ""
    with pytest.raises(ValueError, match="Supported CPE evidence requires a non-empty JSON list"):
        validate_feature_provider(invalid)


@pytest.mark.parametrize(
    "column, values, message",
    [
        ("component", ["c_graph", "a_text", "c_graph"], "component must be c_graph"),
        (
            "score_kind",
            ["ranking_score", "validated_probability", "ranking_score"],
            "score_kind must be ranking_score",
        ),
        ("graph_scope_id", ["scope-a", "scope-b", "scope-a"], "inconsistent graph_scope_id"),
        ("horizon_days", [30, 90, 30], "one consistent positive integer horizon_days"),
        ("horizon_days", [0, 30, 30], "one consistent positive integer horizon_days"),
        ("horizon_days", [30, 1.5, 30], "one consistent positive integer horizon_days"),
        ("horizon_days", [30, None, 30], "one consistent positive integer horizon_days"),
    ],
)
def test_provider_validator_rejects_contract_scope_and_horizon_mismatches(column, values, message):
    invalid = _provider()
    invalid[column] = values
    with pytest.raises(ValueError, match=message):
        validate_feature_provider(invalid)


@pytest.mark.parametrize("column", ["snapshot_id", "graph_scope_id"])
@pytest.mark.parametrize("value", [None, "", "   "])
def test_provider_validator_requires_populated_scope_identifiers(column, value):
    invalid = _provider()
    invalid.loc[0, column] = value
    with pytest.raises(ValueError, match=f"{column} must be populated"):
        validate_feature_provider(invalid)


def test_provider_validator_accepts_valid_component_c_rows():
    validate_feature_provider(_provider(), reference_timestamp=AT, expected_cve_ids=set(IDS))


@pytest.mark.parametrize(
    "rows, message",
    [
        (
            "CVE-2024-12345,2024-01-01T00:00:00Z\nCVE-2024-12345,2024-01-02T00:00:00Z\n",
            "Duplicate CVE",
        ),
        ("CVE-2024-123,2024-01-01T00:00:00Z\n", "Invalid CVE ID"),
        (
            "CVE-2026-12345,2026-10-15T00:00:00Z\n",
            "Publication timestamp outside research interval",
        ),
        ("CVE-2024-12345,not-a-timestamp\n", "Invalid publication timestamp"),
    ],
    ids=["duplicate-cve", "malformed-cve", "excluded-upper-boundary", "invalid-timestamp"],
)
def test_research_manifest_rejects_invalid_rows(tmp_path, rows, message):
    manifest = tmp_path / "manifest.csv"
    manifest.write_text("cve_id,published\n" + rows, encoding="utf-8")
    with pytest.raises(ValueError, match=message):
        load_research_manifest(manifest)


def test_research_manifest_accepts_inclusive_start_as_aware_utc(tmp_path):
    manifest = tmp_path / "manifest.csv"
    manifest.write_text("cve_id,published\nCVE-2016-12345,2016-01-01T00:00:00Z\n", encoding="utf-8")
    population = load_research_manifest(manifest)
    assert population == {"CVE-2016-12345": datetime(2016, 1, 1, tzinfo=UTC)}
    assert population["CVE-2016-12345"].tzinfo is UTC
