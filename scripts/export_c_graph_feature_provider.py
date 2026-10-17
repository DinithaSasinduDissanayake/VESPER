"""Export a validated Component C provider table from saved snapshot artifacts."""

from __future__ import annotations

import argparse
import gzip
import hashlib
import json
import os
import tempfile
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import networkx as nx
import pandas as pd

from vesper.components.c_graph.feature_provider import (
    FEATURE_PROVIDER_COLUMNS,
    build_feature_provider,
    normalize_timestamp,
    validate_feature_provider,
)
from vesper.components.c_graph.multi_historical_pipeline import (
    DEFAULT_MANIFEST,
    load_research_manifest,
)
from vesper.components.c_graph.nvd_parser import parse_nvd_record
from vesper.components.c_graph.score_export import SCORE_COLUMNS
from vesper.components.c_graph.scoring import FEATURE_COLUMNS

FEATURE_GENERATION_VERSION = "c_graph_feature_provider-1"
GRAPH_CONSTRUCTION_VERSION = "c_graph-directed-graph-1"
GRAPH_CONFIGURATION = {
    "graph_type": "networkx.DiGraph",
    "directed_edges": [
        {"source": "vendor", "target": "product", "relation": "offers"},
        {"source": "product", "target": "cve", "relation": "affected_by"},
        {"source": "cve", "target": "cwe", "relation": "has_weakness"},
    ],
    "degree_centrality": {
        "functions": ["networkx.in_degree_centrality", "networkx.out_degree_centrality"],
        "normalization": "degree / (number_of_graph_nodes - 1)",
        "fewer_than_two_nodes": 0.0,
        "scope": "full graph before research-population row filtering",
    },
    "pagerank": {
        "function": "networkx.pagerank",
        "alpha": 0.85,
        "max_iter": 100,
        "tol": 1e-6,
        "weight_parameter": "weight",
        "edge_weights": "all unit weight; graph builder does not set a weight attribute",
        "personalization": "uniform default over full graph nodes",
        "dangling": "NetworkX default; follows personalization",
        "normalization_scope": "all nodes in the full graph; total PageRank mass is 1",
    },
}
SOURCE_CODE_PATHS = (
    "src/vesper/components/c_graph/graph.py",
    "src/vesper/components/c_graph/scoring.py",
    "src/vesper/components/c_graph/nvd_parser.py",
    "src/vesper/components/c_graph/feature_provider.py",
    "scripts/export_c_graph_feature_provider.py",
)


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _read_metadata(path: Path) -> dict[str, Any]:
    return json.loads(path.read_text(encoding="utf-8"))


def _write_csv_atomically(frame: pd.DataFrame, path: Path) -> None:
    fd, temporary_name = tempfile.mkstemp(prefix=f".{path.name}.", suffix=".tmp", dir=path.parent)
    try:
        with os.fdopen(fd, "w", encoding="utf-8", newline="") as stream:
            frame.to_csv(stream, index=False)
        os.replace(temporary_name, path)
    except BaseException:
        Path(temporary_name).unlink(missing_ok=True)
        raise


def _write_json_atomically(data: dict[str, Any], path: Path) -> None:
    temporary = path.with_name(f".{path.name}.tmp")
    try:
        temporary.write_text(json.dumps(data, indent=2, sort_keys=True) + "\n", encoding="utf-8")
        os.replace(temporary, path)
    finally:
        temporary.unlink(missing_ok=True)


def _collect_target_records(
    nvd_dir: Path,
    target_ids: set[str],
    cutoff: datetime,
    manifest: dict[str, datetime],
) -> tuple[dict[str, dict[str, Any]], dict[str, str]]:
    records_by_id: dict[str, dict[str, Any]] = {}
    source_files: dict[str, str] = {}
    for path in sorted(nvd_dir.glob("nvd_*.json.gz")):
        source_files[path.name] = _sha256(path)
        with gzip.open(path, "rt", encoding="utf-8") as stream:
            data = json.load(stream)
        vulnerabilities = data.get("vulnerabilities") if isinstance(data, dict) else None
        if not isinstance(vulnerabilities, list):
            raise ValueError(f"Invalid monthly NVD file: {path}")
        for record in vulnerabilities:
            cve = record.get("cve") if isinstance(record, dict) else None
            cve_id = cve.get("id") if isinstance(cve, dict) else None
            if cve_id not in target_ids:
                continue
            if cve_id in records_by_id:
                raise ValueError(f"Duplicate target NVD record: {cve_id}")
            parsed = parse_nvd_record(record, cutoff.date())
            manifest_published = manifest[cve_id]
            if parsed.published_at != manifest_published:
                raise ValueError(
                    f"Manifest and local NVD publication timestamps differ for {cve_id}"
                )
            if parsed.published_at > cutoff or parsed.last_modified_at.date() > cutoff.date():
                raise ValueError(f"Local NVD record is after the snapshot cutoff: {cve_id}")
            records_by_id[cve_id] = {
                "published_at": parsed.published_at,
                "last_modified_at": parsed.last_modified_at,
                "vendor_product_pairs": parsed.affected,
                "cwe_ids": parsed.cwe_ids,
                "nvd_status": parsed.nvd_status.strip().casefold(),
                "source_nvd_file": path.name,
            }
    missing = target_ids - set(records_by_id)
    if missing:
        raise ValueError(
            f"No local NVD record for {len(missing)} manifest CVEs; sample={sorted(missing)[:5]}"
        )
    return records_by_id, source_files


def export_feature_provider(
    *,
    nvd_dir: Path,
    full_graph_features_path: Path,
    population_features_path: Path,
    scores_path: Path,
    manifest_path: Path,
    output_dir: Path,
    snapshot_at: datetime,
) -> dict[str, Any]:
    """Validate and export the manifest-scoped current-snapshot feature table."""
    cutoff = normalize_timestamp(snapshot_at)
    paths = [
        nvd_dir,
        full_graph_features_path,
        population_features_path,
        scores_path,
        manifest_path,
    ]
    if not nvd_dir.is_dir() or any(not path.is_file() for path in paths[1:]):
        raise FileNotFoundError("One or more required local inputs are missing")
    if output_dir.exists() and (not output_dir.is_dir() or any(output_dir.iterdir())):
        raise FileExistsError(f"Refusing to reuse or overwrite output directory: {output_dir}")

    full_metadata_path = full_graph_features_path.with_suffix(".metadata.json")
    population_metadata_path = population_features_path.with_suffix(".metadata.json")
    score_metadata_path = scores_path.with_suffix(scores_path.suffix + ".metadata.json")
    full_metadata = _read_metadata(full_metadata_path)
    population_metadata = _read_metadata(population_metadata_path)
    score_metadata = _read_metadata(score_metadata_path)
    if full_metadata.get("snapshot_date") != cutoff.date().isoformat():
        raise ValueError("Full graph metadata cutoff does not match snapshot_at")
    if population_metadata.get("snapshot_at") != cutoff.isoformat():
        raise ValueError("Population metadata timestamp does not match snapshot_at")
    if full_metadata.get("historical_reconstruction") != "not_performed":
        raise ValueError("Expected the saved current-snapshot graph, not a historical export")
    if population_metadata.get("historical_reconstruction") != "not_performed":
        raise ValueError("Expected current-snapshot population outputs, not historical features")
    if score_metadata.get("decision_time") != cutoff.isoformat():
        raise ValueError("Shared Score metadata timestamp does not match snapshot_at")
    if score_metadata.get("score_kind") != "ranking_score":
        raise ValueError("Component C score metadata must identify a structural ranking score")
    downloaded_max = full_metadata.get("source_downloaded_at_max")
    if downloaded_max and normalize_timestamp(downloaded_max) > cutoff:
        raise ValueError("At least one NVD source file was downloaded after snapshot_at")

    manifest = load_research_manifest(manifest_path)
    target_ids = set(manifest)
    features = pd.read_csv(population_features_path)
    scores = pd.read_csv(scores_path, keep_default_na=True)
    full_features = pd.read_csv(full_graph_features_path)
    if list(features.columns) != FEATURE_COLUMNS or list(full_features.columns) != FEATURE_COLUMNS:
        raise ValueError(f"Graph feature columns must be exactly {FEATURE_COLUMNS!r}")
    if list(scores.columns) != SCORE_COLUMNS:
        raise ValueError(f"Shared Score columns must be exactly {SCORE_COLUMNS!r}")
    if len(full_features) != full_metadata.get("graph_summary", {}).get("cve"):
        raise ValueError("Full graph feature row count disagrees with graph metadata")
    if len(features) != population_metadata.get("target_feature_rows"):
        raise ValueError("Population feature row count disagrees with metadata")
    expected_population_features = (
        full_features.loc[full_features["cve_id"].isin(target_ids), FEATURE_COLUMNS]
        .sort_values("cve_id", kind="stable")
        .reset_index(drop=True)
    )
    actual_population_features = features.sort_values("cve_id", kind="stable").reset_index(
        drop=True
    )
    try:
        pd.testing.assert_frame_equal(
            actual_population_features,
            expected_population_features,
            check_dtype=False,
            check_exact=False,
            rtol=1e-12,
            atol=1e-18,
        )
    except AssertionError as error:
        raise ValueError(
            "Saved population features do not exactly match the supplied full graph output"
        ) from error
    if len(scores) != population_metadata.get("score_records") or len(scores) != len(target_ids):
        raise ValueError("Shared Score row count does not cover the research population")
    if scores["decision_time"].map(normalize_timestamp).ne(cutoff).any():
        raise ValueError("Shared Score rows contain inconsistent decision times")
    if set(scores["cve_id"]) != target_ids:
        raise ValueError("Shared Score CVE IDs do not match the research manifest")

    rejected_ids = set(scores.loc[scores["status"] == "not_eligible", "cve_id"])
    abstained_ids = set(scores.loc[scores["status"] == "abstained", "cve_id"])
    score_available_ids = set(scores.loc[scores["status"] == "available", "cve_id"])
    if set(features["cve_id"]) != score_available_ids:
        raise ValueError("Saved graph rows do not match available Score statuses")
    if len(rejected_ids) != population_metadata.get("target_rejected_not_eligible"):
        raise ValueError("Rejected Score count disagrees with population metadata")
    if len(abstained_ids) != population_metadata.get("target_missing_other_reason"):
        raise ValueError("Abstained Score count disagrees with population metadata")

    evidence_by_id, source_hashes = _collect_target_records(nvd_dir, target_ids, cutoff, manifest)
    if {
        cve_id for cve_id, record in evidence_by_id.items() if record["nvd_status"] == "rejected"
    } != rejected_ids:
        raise ValueError("NVD Rejected records do not match shared Score not_eligible statuses")

    graph_hash = _sha256(full_graph_features_path)
    snapshot_id = f"nvd-current-snapshot-{cutoff.date().isoformat()}"
    graph_scope_id = f"{snapshot_id}-graph-{graph_hash[:12]}"
    provider = build_feature_provider(
        features,
        scores,
        target_cve_ids=sorted(target_ids),
        evidence_by_id=evidence_by_id,
        snapshot_at=cutoff,
        snapshot_id=snapshot_id,
        graph_scope_id=graph_scope_id,
    )

    output_dir.mkdir(parents=True, exist_ok=True)
    output_path = output_dir / "c_graph_feature_provider.csv"
    _write_csv_atomically(provider, output_path)
    validate_feature_provider(
        pd.read_csv(output_path),
        reference_timestamp=cutoff,
        expected_cve_ids=target_ids,
    )
    counts = {
        "population_cves": len(provider),
        "shared_score_status_counts": provider["status"].value_counts().sort_index().to_dict(),
        "cpe_evidence_status_counts": provider["cpe_evidence_status"]
        .value_counts()
        .sort_index()
        .to_dict(),
        "cwe_evidence_status_counts": provider["cwe_evidence_status"]
        .value_counts()
        .sort_index()
        .to_dict(),
        "rows_with_both_evidence_layers": int(
            (
                (provider["cpe_evidence_status"] == "supported")
                & (provider["cwe_evidence_status"] == "supported")
            ).sum()
        ),
        "rows_with_neither_evidence_layer": int(
            (
                (provider["cpe_evidence_status"] == "unavailable")
                & (provider["cwe_evidence_status"] == "unavailable")
            ).sum()
        ),
        "rows_with_partial_evidence": int(
            (provider["cpe_evidence_status"] != provider["cwe_evidence_status"]).sum()
        ),
    }
    metadata = {
        "feature_schema_version": "1.0.0",
        "feature_generation_version": FEATURE_GENERATION_VERSION,
        "graph_construction_version": GRAPH_CONSTRUCTION_VERSION,
        "graph_configuration": GRAPH_CONFIGURATION,
        "networkx_version": nx.__version__,
        "source_code_sha256": {
            relative_path: _sha256(Path(__file__).resolve().parents[1] / relative_path)
            for relative_path in SOURCE_CODE_PATHS
        },
        "snapshot_id": snapshot_id,
        "reference_timestamp": cutoff.isoformat(),
        "snapshot_kind": "current_nvd_record_snapshot_not_historical_reconstruction",
        "graph_scope": population_metadata.get("graph_scope"),
        "graph_scope_id": graph_scope_id,
        "historical_reconstruction": "not_performed",
        "score_semantics": score_metadata.get("score_semantics"),
        "score_contract_columns": SCORE_COLUMNS,
        "feature_provider_columns": FEATURE_PROVIDER_COLUMNS,
        "counts": counts,
        "evidence_semantics": (
            "supported means the existing NVD parser extracted explicit vendor/product or CWE "
            "values. unavailable means no supported relationship was extracted; it does not "
            "mean the relationship set is known-empty. not_evaluated is used for "
            "NVD-rejected records."
        ),
        "source_provenance": {
            "manifest": {"path": str(manifest_path), "sha256": _sha256(manifest_path)},
            "full_graph_features": {
                "path": str(full_graph_features_path),
                "sha256": graph_hash,
                "metadata_path": str(full_metadata_path),
            },
            "population_features": {
                "path": str(population_features_path),
                "sha256": _sha256(population_features_path),
                "metadata_path": str(population_metadata_path),
            },
            "shared_scores": {
                "path": str(scores_path),
                "sha256": _sha256(scores_path),
                "metadata_path": str(score_metadata_path),
            },
            "local_nvd_monthly_files_sha256": dict(sorted(source_hashes.items())),
        },
        "output_csv": str(output_path),
        "output_sha256": _sha256(output_path),
        "generated_at_utc": datetime.now(UTC).isoformat(),
    }
    _write_json_atomically(metadata, output_dir / "c_graph_feature_provider.metadata.json")
    score_status_summary = json.dumps(counts["shared_score_status_counts"], sort_keys=True)
    cpe_status_summary = json.dumps(counts["cpe_evidence_status_counts"], sort_keys=True)
    cwe_status_summary = json.dumps(counts["cwe_evidence_status_counts"], sort_keys=True)
    report = "\n".join(
        [
            "# Component C feature-provider export",
            "",
            "This is a reproducible **current NVD snapshot** handoff table, not a historical "
            "reconstruction or validated predictive result.",
            "",
            f"- Snapshot: `{snapshot_id}` (`{cutoff.isoformat()}`)",
            f"- Population rows: {counts['population_cves']:,}",
            f"- Shared Score statuses: `{score_status_summary}`",
            f"- CPE evidence statuses: `{cpe_status_summary}`",
            f"- CWE evidence statuses: `{cwe_status_summary}`",
            "- Both relationship layers explicitly supported: "
            f"{counts['rows_with_both_evidence_layers']:,}",
            f"- Partial relationship evidence: {counts['rows_with_partial_evidence']:,}",
            "- Neither relationship layer supported: "
            f"{counts['rows_with_neither_evidence_layer']:,}",
            "- Feature table: `c_graph_feature_provider.csv`",
            "- Metadata and SHA-256 provenance: `c_graph_feature_provider.metadata.json`",
            "",
            "The table preserves the shared `Score` columns and appends structural graph features, "
            "explicit layer-evidence states, source timestamps, and snapshot provenance. "
            "`available` "
            "scores are structural PageRank ranking values, not exploitation probabilities. Blank "
            "relationship evidence means the existing parser extracted no supported value; it does "
            "not assert a known-empty relationship set. NVD Rejected rows are `not_eligible` with "
            "blank numeric features. Existing graph, score, pilot, and raw inputs were not "
            "overwritten.",
            "",
            "The graph features were reused from the saved full-snapshot and population exports; "
            "this command did not rebuild the graph.",
            f"- Source download start: `{population_metadata.get('source_downloaded_at_min')}`",
            f"- Source download end: `{population_metadata.get('source_downloaded_at_max')}`",
            "These retrieval timestamps do not prove the relationships were available at an "
            "decision time.",
            "",
        ]
    )
    (output_dir / "COMPONENT_C_FEATURE_PROVIDER_REPORT.md").write_text(report, encoding="utf-8")
    return metadata


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Export a validated Component C provider table from saved snapshot artifacts."
    )
    parser.add_argument("--nvd-dir", type=Path, default=Path("data/raw/nvd"))
    parser.add_argument("--full-graph-features", type=Path, required=True)
    parser.add_argument("--population-features", type=Path, required=True)
    parser.add_argument("--scores", type=Path, required=True)
    parser.add_argument("--manifest", type=Path, default=DEFAULT_MANIFEST)
    parser.add_argument("--snapshot-at", type=normalize_timestamp, required=True)
    parser.add_argument("--output-dir", type=Path, required=True)
    args = parser.parse_args()
    print(
        json.dumps(
            export_feature_provider(
                nvd_dir=args.nvd_dir,
                full_graph_features_path=args.full_graph_features,
                population_features_path=args.population_features,
                scores_path=args.scores,
                manifest_path=args.manifest,
                snapshot_at=args.snapshot_at,
                output_dir=args.output_dir,
            ),
            indent=2,
        )
    )


if __name__ == "__main__":
    main()
