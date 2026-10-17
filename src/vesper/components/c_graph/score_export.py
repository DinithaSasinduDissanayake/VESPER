"""Export Component C graph features through the shared Score contract."""

from __future__ import annotations

import json
import math
import os
import tempfile
from collections.abc import Iterable
from datetime import UTC, datetime
from pathlib import Path

import pandas as pd

from vesper.components.c_graph.scoring import FEATURE_COLUMNS
from vesper.contracts.score import Component, Score, ScoreKind, ScoreStatus

MODEL_VERSION = "c_graph-pagerank-structural-0.1"
SCORE_COLUMNS = [
    "cve_id",
    "component",
    "decision_time",
    "horizon_days",
    "score",
    "score_kind",
    "status",
    "reason",
    "model_version",
    "trained_through",
    "snapshot_date",
]


def build_graph_scores(
    features: pd.DataFrame,
    target_cve_ids: Iterable[str],
    *,
    snapshot_at: datetime,
    horizon_days: int,
    not_eligible_reasons: dict[str, str] | None = None,
) -> list[Score]:
    """Map PageRank to ranking scores; missing graph rows explicitly abstain."""
    if snapshot_at.tzinfo is None or snapshot_at.utcoffset() is None:
        raise ValueError("snapshot_at must include a time zone")
    if isinstance(horizon_days, bool) or not isinstance(horizon_days, int) or horizon_days <= 0:
        raise ValueError("horizon_days must be a positive integer")
    if list(features.columns) != FEATURE_COLUMNS:
        raise ValueError(f"Feature columns must be exactly {FEATURE_COLUMNS!r}")

    target_ids = list(target_cve_ids)
    if len(target_ids) != len(set(target_ids)):
        raise ValueError("target_cve_ids contains duplicates")
    if features["cve_id"].duplicated().any():
        raise ValueError("Feature table contains duplicate CVE identifiers")
    target_set = set(target_ids)
    extras = set(features["cve_id"]) - target_set
    if extras:
        raise ValueError(
            f"Feature table contains CVEs outside target population: {sorted(extras)[:5]}"
        )

    numeric_columns = FEATURE_COLUMNS[1:]
    for column in numeric_columns:
        values = pd.to_numeric(features[column], errors="coerce")
        if values.isna().any() or not values.map(math.isfinite).all():
            raise ValueError(f"Feature column {column!r} must contain finite numbers")
        if ((values < 0) | (values > 1)).any():
            raise ValueError(f"Feature column {column!r} must be between 0 and 1")

    by_id = features.set_index("cve_id")
    not_eligible_reasons = not_eligible_reasons or {}
    unknown_ineligible_ids = set(not_eligible_reasons) - target_set
    if unknown_ineligible_ids:
        raise ValueError(
            "not_eligible_reasons contains IDs outside target population: "
            f"{sorted(unknown_ineligible_ids)[:5]}"
        )
    overlap = set(not_eligible_reasons).intersection(by_id.index)
    if overlap:
        raise ValueError(f"Not-eligible CVEs must not have feature rows: {sorted(overlap)[:5]}")
    decision_time = snapshot_at.astimezone(UTC)
    snapshot_date = decision_time.date()
    scores = []
    for cve_id in target_ids:
        available = cve_id in by_id.index
        ineligible = cve_id in not_eligible_reasons
        scores.append(
            Score(
                cve_id=cve_id,
                component=Component.C_GRAPH,
                decision_time=decision_time,
                horizon_days=horizon_days,
                score=float(by_id.at[cve_id, "pagerank"]) if available else None,
                score_kind=ScoreKind.RANKING_SCORE,
                status=(
                    ScoreStatus.AVAILABLE
                    if available
                    else ScoreStatus.NOT_ELIGIBLE
                    if ineligible
                    else ScoreStatus.ABSTAINED
                ),
                reason=(
                    None
                    if available
                    else not_eligible_reasons[cve_id]
                    if ineligible
                    else "No valid graph feature row was available for this CVE."
                ),
                model_version=MODEL_VERSION,
                trained_through=None,
                snapshot_date=snapshot_date,
            )
        )
    return scores


def export_graph_scores(
    features: pd.DataFrame,
    target_cve_ids: Iterable[str],
    output_path: str | Path,
    *,
    snapshot_at: datetime,
    horizon_days: int,
    source_features: str | Path | None = None,
    not_eligible_reasons: dict[str, str] | None = None,
    graph_scope: str | None = None,
    source_description: str | None = None,
) -> list[Score]:
    """Build and atomically export shared-contract scores and coverage metadata."""
    records = build_graph_scores(
        features,
        target_cve_ids,
        snapshot_at=snapshot_at,
        horizon_days=horizon_days,
        not_eligible_reasons=not_eligible_reasons,
    )
    output = Path(output_path)
    output.parent.mkdir(parents=True, exist_ok=True)
    rows = []
    for record in records:
        row = {key: getattr(record, key) for key in SCORE_COLUMNS}
        row["component"] = record.component.value
        row["score_kind"] = record.score_kind.value
        row["status"] = record.status.value
        row["decision_time"] = record.decision_time.isoformat()
        row["trained_through"] = (
            record.trained_through.isoformat() if record.trained_through else ""
        )
        row["snapshot_date"] = record.snapshot_date.isoformat()
        rows.append(row)

    fd, temporary_name = tempfile.mkstemp(
        prefix=f".{output.name}.", suffix=".tmp", dir=output.parent
    )
    try:
        with os.fdopen(fd, "w", encoding="utf-8", newline="") as stream:
            pd.DataFrame(rows, columns=SCORE_COLUMNS).to_csv(stream, index=False)
        os.replace(temporary_name, output)
    except BaseException:
        Path(temporary_name).unlink(missing_ok=True)
        raise

    available_count = sum(record.status is ScoreStatus.AVAILABLE for record in records)
    not_eligible_count = sum(record.status is ScoreStatus.NOT_ELIGIBLE for record in records)
    abstained_count = sum(record.status is ScoreStatus.ABSTAINED for record in records)
    metadata = {
        "component": Component.C_GRAPH.value,
        "model_version": MODEL_VERSION,
        "score_kind": ScoreKind.RANKING_SCORE.value,
        "score_semantics": (
            "Raw PageRank over the supplied graph; structural ranking score, not a probability."
        ),
        "graph_scope": graph_scope
        or "Scores reflect only the graph represented by the supplied feature table.",
        "source_description": source_description,
        "source_completeness": (
            "Score availability reflects feature rows in the supplied table; it does not by "
            "itself establish complete NVD history coverage or historical reconstruction."
        ),
        "source_features": str(source_features) if source_features is not None else None,
        "decision_time": records[0].decision_time.isoformat()
        if records
        else snapshot_at.astimezone(UTC).isoformat(),
        "snapshot_date": (
            records[0].snapshot_date if records else snapshot_at.astimezone(UTC).date()
        ).isoformat(),
        "horizon_days": horizon_days,
        "target_count": len(records),
        "available_count": available_count,
        "abstained_count": abstained_count,
        "not_eligible_count": not_eligible_count,
        "coverage": available_count / len(records) if records else 0.0,
        "output_columns": SCORE_COLUMNS,
    }
    metadata_path = output.with_suffix(output.suffix + ".metadata.json")
    temp_meta = metadata_path.with_name(f".{metadata_path.name}.tmp")
    temp_meta.write_text(json.dumps(metadata, indent=2) + "\n", encoding="utf-8")
    os.replace(temp_meta, metadata_path)
    return records
