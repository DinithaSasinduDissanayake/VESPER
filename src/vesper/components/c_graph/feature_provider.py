"""Validated current-snapshot feature-provider export for Component C."""

from __future__ import annotations

import json
import math
from datetime import UTC, date, datetime
from typing import Any

import pandas as pd

from vesper.components.c_graph.score_export import SCORE_COLUMNS
from vesper.components.c_graph.scoring import FEATURE_COLUMNS
from vesper.contracts.score import Component, Score, ScoreKind, ScoreStatus

FEATURE_SCHEMA_VERSION = "1.0.0"
FEATURE_PROVIDER_COLUMNS = [
    *SCORE_COLUMNS,
    "reference_timestamp",
    "snapshot_id",
    "feature_schema_version",
    "graph_scope_id",
    "in_degree_centrality",
    "out_degree_centrality",
    "pagerank",
    "in_degree_status",
    "out_degree_status",
    "pagerank_status",
    "vendor_product_evidence_json",
    "cpe_evidence_status",
    "cpe_evidence_reason",
    "cwe_ids_json",
    "cwe_evidence_status",
    "cwe_evidence_reason",
    "source_record_published_at",
    "source_record_last_modified_at",
    "source_nvd_file",
    "feature_provenance",
]
_NUMERIC_FEATURES = (
    "in_degree_centrality",
    "out_degree_centrality",
    "pagerank",
)
_EVIDENCE_STATUSES = {"supported", "unavailable", "not_evaluated"}


def normalize_timestamp(value: datetime | str) -> datetime:
    """Parse and normalize an ISO timestamp to UTC."""
    if isinstance(value, str):
        normalized = value.strip()
        if normalized.endswith("Z"):
            normalized = normalized[:-1] + "+00:00"
        value = datetime.fromisoformat(normalized)
    if value.tzinfo is None or value.utcoffset() is None:
        raise ValueError("timestamp must include a time zone")
    return value.astimezone(UTC)


def _json_list(value: Any, *, field: str, item_length: int) -> list[Any]:
    try:
        parsed = json.loads(value) if isinstance(value, str) else value
    except (TypeError, json.JSONDecodeError) as error:
        raise ValueError(f"{field} must contain valid JSON") from error
    if not isinstance(parsed, list) or not parsed:
        raise ValueError(f"{field} must be a non-empty JSON list")
    if item_length == 1:
        if any(not isinstance(item, str) or not item.strip() for item in parsed):
            raise ValueError(f"{field} must contain non-empty strings")
    elif any(
        not isinstance(item, list)
        or len(item) != item_length
        or any(not isinstance(part, str) or not part.strip() for part in item)
        for item in parsed
    ):
        raise ValueError(f"{field} items must be lists of {item_length} non-empty strings")
    return parsed


def validate_feature_provider(
    frame: pd.DataFrame,
    *,
    reference_timestamp: datetime | str | None = None,
    expected_cve_ids: set[str] | None = None,
) -> None:
    """Validate keys, schema, timestamps, numerics, evidence and status/value pairs."""
    missing = set(FEATURE_PROVIDER_COLUMNS) - set(frame.columns)
    if missing:
        raise ValueError(f"Feature provider is missing required columns: {sorted(missing)}")
    if frame.empty:
        raise ValueError("Feature provider must contain at least one row")
    if frame["cve_id"].isna().any() or frame["cve_id"].duplicated().any():
        raise ValueError("Feature provider contains a missing or duplicate CVE ID")
    if frame["reference_timestamp"].isna().any():
        raise ValueError("Feature provider contains a missing reference timestamp")

    normalized_reference = frame["reference_timestamp"].map(normalize_timestamp)
    if normalized_reference.nunique() != 1:
        raise ValueError("Feature provider contains inconsistent reference timestamps")
    if reference_timestamp is not None:
        expected_time = normalize_timestamp(reference_timestamp)
        if not normalized_reference.eq(expected_time).all():
            raise ValueError("Feature provider reference timestamp does not match the snapshot")
    if frame["decision_time"].isna().any():
        raise ValueError("Feature provider contains a missing decision_time")
    normalized_decision = frame["decision_time"].map(normalize_timestamp)
    if not normalized_decision.eq(normalized_reference).all():
        raise ValueError("decision_time and reference_timestamp are inconsistent")
    expected_dates = normalized_reference.map(lambda value: value.date().isoformat())
    if not frame["snapshot_date"].astype(str).eq(expected_dates).all():
        raise ValueError("snapshot_date is inconsistent with the UTC reference timestamp")
    if (
        frame["snapshot_id"].isna().any()
        or not frame["snapshot_id"].astype(str).str.strip().ne("").all()
    ):
        raise ValueError("snapshot_id must be populated")
    if frame["snapshot_id"].nunique() != 1:
        raise ValueError("Feature provider contains inconsistent snapshot_id values")
    if (
        frame["graph_scope_id"].isna().any()
        or not frame["graph_scope_id"].astype(str).str.strip().ne("").all()
    ):
        raise ValueError("graph_scope_id must be populated")
    if frame["graph_scope_id"].nunique() != 1:
        raise ValueError("Feature provider contains inconsistent graph_scope_id values")
    if not frame["feature_schema_version"].astype(str).eq(FEATURE_SCHEMA_VERSION).all():
        raise ValueError("Unsupported feature_schema_version")
    if not frame["component"].eq(Component.C_GRAPH.value).all():
        raise ValueError("Feature provider component must be c_graph")
    if not frame["score_kind"].eq(ScoreKind.RANKING_SCORE.value).all():
        raise ValueError("Feature provider score_kind must be ranking_score")
    horizons = pd.to_numeric(frame["horizon_days"], errors="coerce")
    if (
        horizons.isna().any()
        or frame["horizon_days"].map(lambda value: isinstance(value, bool)).any()
        or (horizons <= 0).any()
        or (horizons % 1 != 0).any()
        or horizons.nunique() != 1
    ):
        raise ValueError(
            "Feature provider must have one consistent positive integer horizon_days value"
        )
    for column in ("source_record_published_at", "source_record_last_modified_at"):
        if frame[column].isna().any():
            raise ValueError(f"Feature provider contains a missing {column}")
        parsed_values = frame[column].map(normalize_timestamp)
        if (parsed_values > normalized_reference).any():
            raise ValueError(f"{column} cannot be after the reference timestamp")

    if expected_cve_ids is not None and set(frame["cve_id"]) != expected_cve_ids:
        raise ValueError("Feature provider CVE IDs do not match the expected population")

    allowed_score_statuses = {"available", "not_eligible", "abstained", "already_exploited"}
    if not set(frame["status"].dropna()).issubset(allowed_score_statuses):
        raise ValueError("Feature provider contains an unknown shared Score status")
    for index, row in frame.iterrows():
        available = row["status"] == "available"
        for status_column in ("in_degree_status", "out_degree_status", "pagerank_status"):
            if row[status_column] != row["status"]:
                raise ValueError(
                    f"{status_column} disagrees with shared Score status on row {index}"
                )
        numeric_values: dict[str, float | None] = {}
        for column in _NUMERIC_FEATURES:
            raw_value = row[column]
            if pd.isna(raw_value) or raw_value == "":
                numeric_values[column] = None
                continue
            try:
                value = float(raw_value)
            except (TypeError, ValueError) as error:
                raise ValueError(f"{column} is not numeric on row {index}") from error
            if not math.isfinite(value) or not 0.0 <= value <= 1.0:
                raise ValueError(f"{column} must be finite and in [0, 1] on row {index}")
            numeric_values[column] = value
        score = row["score"]
        score_missing = pd.isna(score) or score == ""
        if available:
            if score_missing or any(value is None for value in numeric_values.values()):
                raise ValueError("Available rows require finite score and graph features")
            if not math.isclose(float(score), numeric_values["pagerank"], rel_tol=1e-12):
                raise ValueError("Shared Score value must equal the exported PageRank")
        elif not score_missing or any(value is not None for value in numeric_values.values()):
            raise ValueError("Unavailable score statuses require blank scores and features")
        elif not isinstance(row["reason"], str) or not row["reason"].strip():
            raise ValueError("Unavailable score statuses require an explicit reason")

        for layer, evidence_column, status_column, reason_column, item_length in (
            (
                "CPE",
                "vendor_product_evidence_json",
                "cpe_evidence_status",
                "cpe_evidence_reason",
                2,
            ),
            ("CWE", "cwe_ids_json", "cwe_evidence_status", "cwe_evidence_reason", 1),
        ):
            evidence_status = row[status_column]
            if evidence_status not in _EVIDENCE_STATUSES:
                raise ValueError(f"Unknown {layer} evidence status on row {index}")
            evidence_value = row[evidence_column]
            evidence_blank = pd.isna(evidence_value) or evidence_value == ""
            if evidence_status == "supported":
                if evidence_blank:
                    raise ValueError(f"Supported {layer} evidence requires a non-empty JSON list")
                _json_list(evidence_value, field=evidence_column, item_length=item_length)
            elif not evidence_blank:
                raise ValueError(f"Unavailable {layer} evidence must remain blank")
            if evidence_status != "supported" and (
                not isinstance(row[reason_column], str) or not row[reason_column].strip()
            ):
                raise ValueError(f"Unavailable {layer} evidence requires an explicit reason")
            if row["status"] == "not_eligible" and evidence_status != "not_evaluated":
                raise ValueError(
                    "Not-eligible records must not claim evaluated relationship evidence"
                )

    # Validate that every row remains constructible as the shared Score contract.
    for row in frame[SCORE_COLUMNS].to_dict(orient="records"):
        normalized = dict(row)
        normalized["decision_time"] = normalize_timestamp(normalized["decision_time"])
        normalized["snapshot_date"] = date.fromisoformat(str(normalized["snapshot_date"]))
        normalized["component"] = Component(normalized["component"])
        normalized["score_kind"] = ScoreKind(normalized["score_kind"])
        normalized["status"] = ScoreStatus(normalized["status"])
        trained_through = normalized["trained_through"]
        normalized["trained_through"] = (
            normalize_timestamp(trained_through)
            if isinstance(trained_through, str) and trained_through.strip()
            else None
        )
        normalized["score"] = None if pd.isna(normalized["score"]) else float(normalized["score"])
        normalized["reason"] = None if pd.isna(normalized["reason"]) else normalized["reason"]
        Score(**normalized)


def build_feature_provider(
    features: pd.DataFrame,
    scores: pd.DataFrame,
    *,
    target_cve_ids: list[str],
    evidence_by_id: dict[str, dict[str, Any]],
    snapshot_at: datetime,
    snapshot_id: str,
    graph_scope_id: str,
) -> pd.DataFrame:
    """Join saved graph rows, shared Score rows, and supported local NVD evidence."""
    if list(features.columns) != FEATURE_COLUMNS:
        raise ValueError(f"Graph feature columns must be exactly {FEATURE_COLUMNS!r}")
    if list(scores.columns) != SCORE_COLUMNS:
        raise ValueError(f"Score columns must be exactly {SCORE_COLUMNS!r}")
    if features["cve_id"].duplicated().any() or scores["cve_id"].duplicated().any():
        raise ValueError("Graph features and scores must have unique CVE IDs")
    if len(target_cve_ids) != len(set(target_cve_ids)):
        raise ValueError("target_cve_ids contains duplicates")
    cutoff = normalize_timestamp(snapshot_at)
    if not snapshot_id.strip() or not graph_scope_id.strip():
        raise ValueError("snapshot_id and graph_scope_id must be populated")

    score_ids = set(scores["cve_id"])
    if score_ids != set(target_cve_ids):
        raise ValueError("Score rows must exactly cover the target population")
    feature_by_id = features.set_index("cve_id")
    score_by_id = scores.set_index("cve_id")
    feature_ids = set(feature_by_id.index)
    available_ids = set(scores.loc[scores["status"] == "available", "cve_id"])
    if feature_ids != available_ids:
        raise ValueError("Available Score IDs must exactly match graph feature IDs")
    if not set(evidence_by_id).issubset(set(target_cve_ids)):
        raise ValueError("Evidence records contain IDs outside the target population")

    rows: list[dict[str, Any]] = []
    for cve_id in sorted(target_cve_ids):
        score = score_by_id.loc[cve_id].to_dict()
        record = evidence_by_id.get(cve_id)
        if record is None:
            raise ValueError(f"No local NVD source record found for {cve_id}")
        published = normalize_timestamp(record["published_at"])
        modified = normalize_timestamp(record["last_modified_at"])
        if published > cutoff or modified.date() > cutoff.date():
            raise ValueError(f"Source record for {cve_id} is after the snapshot cutoff")
        if score["status"] == "not_eligible":
            if record.get("nvd_status", "").casefold() != "rejected":
                raise ValueError(
                    f"Score marks {cve_id} ineligible but source record is not Rejected"
                )
            cpe_status = cwe_status = "not_evaluated"
            cpe_reason = cwe_reason = "record_not_eligible_in_snapshot"
            cpe_pairs: list[list[str]] = []
            cwe_ids: list[str] = []
        else:
            cpe_pairs = [list(pair) for pair in record["vendor_product_pairs"]]
            cwe_ids = list(record["cwe_ids"])
            cpe_status = "supported" if cpe_pairs else "unavailable"
            cwe_status = "supported" if cwe_ids else "unavailable"
            cpe_reason = "" if cpe_pairs else "no_supported_relationship_extracted_from_record"
            cwe_reason = "" if cwe_ids else "no_supported_relationship_extracted_from_record"

        if score["status"] == "available":
            feature = feature_by_id.loc[cve_id]
            graph_values = {column: float(feature[column]) for column in _NUMERIC_FEATURES}
            if not math.isclose(graph_values["pagerank"], float(score["score"]), rel_tol=1e-12):
                raise ValueError(f"PageRank and shared Score disagree for {cve_id}")
            value_status = "available"
        else:
            graph_values = dict.fromkeys(_NUMERIC_FEATURES)
            value_status = score["status"]

        row = {
            "cve_id": cve_id,
            **score,
            "reference_timestamp": cutoff.isoformat(),
            "snapshot_id": snapshot_id,
            "feature_schema_version": FEATURE_SCHEMA_VERSION,
            "graph_scope_id": graph_scope_id,
            **graph_values,
            "in_degree_status": value_status,
            "out_degree_status": value_status,
            "pagerank_status": value_status,
            "vendor_product_evidence_json": json.dumps(cpe_pairs, separators=(",", ":"))
            if cpe_pairs
            else "",
            "cpe_evidence_status": cpe_status,
            "cpe_evidence_reason": cpe_reason,
            "cwe_ids_json": json.dumps(cwe_ids, separators=(",", ":")) if cwe_ids else "",
            "cwe_evidence_status": cwe_status,
            "cwe_evidence_reason": cwe_reason,
            "source_record_published_at": published.isoformat(),
            "source_record_last_modified_at": modified.isoformat(),
            "source_nvd_file": record["source_nvd_file"],
            "feature_provenance": "saved_current_snapshot_graph_and_local_nvd_record",
        }
        rows.append(row)

    frame = pd.DataFrame(rows, columns=FEATURE_PROVIDER_COLUMNS)
    validate_feature_provider(
        frame,
        reference_timestamp=cutoff,
        expected_cve_ids=set(target_cve_ids),
    )
    return frame
