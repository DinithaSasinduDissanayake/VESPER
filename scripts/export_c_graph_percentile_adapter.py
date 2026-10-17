"""Refresh only the D-facing percentile adapter from the frozen local provider."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path

import pandas as pd

from vesper.components.c_graph.structural_disagreement import build_real_scores

PROVIDER = Path("outputs/c_graph_feature_provider_2026-10-17_run2/c_graph_feature_provider.csv")
OUTPUT = Path("outputs/c_graph_structural_scalar_disagreement_2026-10-17_run1")


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as source:
        for block in iter(lambda: source.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def main() -> None:
    """Keep research artifacts immutable; retain adapter provenance and states."""
    target = OUTPUT / "c_graph_scores.csv"
    sidecar = OUTPUT / "c_graph_scores.csv.metadata.json"
    metadata = json.loads(sidecar.read_text(encoding="utf-8"))
    provider_metadata = PROVIDER.with_suffix(".metadata.json")
    protected = {
        path: sha256(path)
        for path in [PROVIDER, provider_metadata, *OUTPUT.rglob("*")]
        if path.is_file() and path not in {target, sidecar}
    }
    if protected[PROVIDER] != metadata["source_provider_sha256"]:
        raise ValueError("Frozen provider checksum disagrees with adapter provenance")
    provider_meta = json.loads(provider_metadata.read_text(encoding="utf-8"))
    for field in ("snapshot_id", "graph_scope_id", "reference_timestamp"):
        if metadata[field] != provider_meta[field]:
            raise ValueError(f"Adapter/provider provenance mismatch: {field}")
    provider = pd.read_csv(PROVIDER)
    scores = build_real_scores(provider, provider_meta)
    available = scores.loc[scores.status.eq("available"), "score"]
    metadata.update(
        model_version=sorted(scores.model_version.unique().tolist()),
        definition="Relative PageRank structural percentile = (average_rank(pagerank)-1)/(N-1)",
        interpretation=(
            "Higher score = greater relative graph structural importance; "
            "NOT exploitation probability"
        ),
        horizon_semantics=(
            "horizon_days=30 is shared interface metadata, "
            "not a validated 30-day Component C prediction target"
        ),
        percentile_population=len(available),
        percentile_population_definition=(
            "All and only frozen provider rows with status=available; "
            "independent of research cohort, CVSS, EPSS, KEV, Degree, A and B"
        ),
        tie_handling="Deterministic ascending average ranks; singleton convention=0.5",
        score_distribution={
            "min": float(available.min()),
            "median": float(available.median()),
            "max": float(available.max()),
        },
        regeneration_command=(
            "uv run --offline --no-sync python scripts/export_c_graph_percentile_adapter.py"
        ),
        research_outputs="Unchanged; research summary/report describe the original analysis run",
    )
    scores.to_csv(target, index=False)
    loaded = pd.read_csv(target)
    pd.testing.assert_frame_equal(loaded, scores, check_dtype=False)
    metadata["output_sha256"] = sha256(target)
    sidecar.write_text(json.dumps(metadata, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    for path, expected in protected.items():
        if sha256(path) != expected:
            raise AssertionError(f"Protected artifact changed: {path}")
    print(
        json.dumps(
            {
                "rows": len(scores),
                "status_counts": scores.status.value_counts().to_dict(),
                "N": len(available),
                "distribution": metadata["score_distribution"],
                "protected_artifacts_unchanged": len(protected),
            },
            indent=2,
        )
    )


if __name__ == "__main__":
    main()
