"""Export cutoff-specific, pilot-scoped historical graph features."""

from __future__ import annotations

import hashlib
import json
import time
from datetime import datetime
from pathlib import Path
from typing import Any

import pandas as pd

from vesper.components.c_graph.historical import validate_history_response
from vesper.components.c_graph.layered_historical import (
    LayerRelationships,
    analyze_layer,
    reconstruct_relationship_layers,
)

DEFAULT_CUTOFFS = tuple(f"{year}-01-01T00:00:00+00:00" for year in range(2022, 2027))
OUTPUT_COLUMNS = [
    "cve_id",
    "cutoff_timestamp",
    "published_timestamp",
    "layer",
    "evidence_eligible",
    "feature_status",
    "reason",
    "relationship_count",
    "relationships_json",
    "degree_feature",
    "degree_centrality_feature",
    "pagerank",
    "history_path",
    "history_sha256",
    "history_events_total",
    "history_events_by_cutoff",
    "latest_event_by_cutoff",
    "kev_outcome_status",
    "kev_outcome_label",
    "kev_horizon_days",
]


def _parse_utc(value: str | datetime | pd.Timestamp, *, naive_is_utc: bool = False) -> datetime:
    parsed = pd.Timestamp(value)
    if parsed.tzinfo is None:
        if not naive_is_utc:
            raise ValueError(f"Timestamp must include a timezone: {value!r}")
        parsed = parsed.tz_localize("UTC")
    return parsed.tz_convert("UTC").to_pydatetime()


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as source:
        for block in iter(lambda: source.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def _load_sample(sample_frame_path: Path, manifest_path: Path) -> pd.DataFrame:
    sample = pd.read_csv(sample_frame_path, dtype={"cve_id": "string"})
    manifest = pd.read_csv(manifest_path, dtype={"cve_id": "string"})
    required = {"cve_id", "published"}
    if not required.issubset(sample.columns) or not required.issubset(manifest.columns):
        raise ValueError("Sample frame and manifest must contain cve_id and published")
    for table, name in ((sample, "sample frame"), (manifest, "manifest")):
        table["cve_id"] = table["cve_id"].str.strip().str.upper()
        if table["cve_id"].isna().any() or table["cve_id"].duplicated().any():
            raise ValueError(f"{name} CVE IDs must be present and unique")
        table["published"] = pd.to_datetime(
            table["published"], format="mixed", utc=True, errors="coerce"
        )
        if table["published"].isna().any():
            raise ValueError(f"{name} has invalid publication timestamps")
    lookup = manifest.set_index("cve_id")["published"]
    for row in sample.itertuples(index=False):
        if row.cve_id not in lookup.index or row.published != lookup.at[row.cve_id]:
            raise ValueError(f"Sample frame disagrees with research manifest for {row.cve_id}")
    return sample.sort_values("cve_id").reset_index(drop=True)


def _load_saved_labels(
    labels_path: Path, cve_ids: set[str], cutoffs: set[str]
) -> dict[tuple[str, str], dict[str, Any]]:
    wanted: dict[tuple[str, str], dict[str, Any]] = {}
    columns = ["cve_id", "decision_time", "horizon_days", "outcome_status", "outcome_label"]
    for chunk in pd.read_csv(
        labels_path,
        usecols=columns,
        dtype={"outcome_label": "string"},
        chunksize=200_000,
    ):
        chunk = chunk[chunk["cve_id"].isin(cve_ids) & chunk["decision_time"].isin(cutoffs)]
        for row in chunk.itertuples(index=False):
            label_text = (
                "" if pd.isna(row.outcome_label) else str(row.outcome_label).strip().lower()
            )
            if label_text in {"", "<na>"}:
                label = None
            elif label_text in {"true", "1"}:
                label = True
            elif label_text in {"false", "0"}:
                label = False
            else:
                raise ValueError(f"Invalid saved KEV outcome label: {row.outcome_label!r}")
            key = (row.cve_id, row.decision_time)
            if key in wanted:
                raise ValueError(f"Duplicate saved KEV outcome for {key}")
            wanted[key] = {
                "status": row.outcome_status,
                "label": label,
                "horizon_days": int(row.horizon_days),
            }
    expected = len(cve_ids) * len(cutoffs)
    if len(wanted) != expected:
        raise ValueError(f"Saved KEV labels contain {len(wanted)} of {expected} requested rows")
    return wanted


def _event_times(history: dict[str, Any], cve_id: str) -> list[datetime]:
    result = []
    for envelope in history.get("cveChanges", []):
        change = envelope.get("change", {})
        if change.get("cveId") == cve_id and change.get("created"):
            result.append(_parse_utc(change["created"], naive_is_utc=True))
    return result


def _record_for_layer(
    layer: str,
    cve_id: str,
    cutoff: datetime,
    published: datetime,
    history_path: Path,
    history: dict[str, Any] | None,
    error: str | None,
) -> LayerRelationships:
    if published > cutoff:
        return LayerRelationships(cve_id, cutoff, layer, (), False, ("not_published_at_cutoff",))
    if history is None:
        reason = "missing_history_response" if error is None else error
        return LayerRelationships(cve_id, cutoff, layer, (), False, (reason,))
    return reconstruct_relationship_layers(history, cutoff, cve_id)[layer]


def _relationships_json(record: LayerRelationships) -> str:
    if not record.eligible:
        return ""
    if record.layer == "cpe":
        values = [
            {"vendor": vendor, "product": product} for vendor, product in record.relationships
        ]
    else:
        values = [{"cwe_id": cwe_id} for cwe_id in record.relationships]
    return json.dumps(values, sort_keys=True, separators=(",", ":"))


def run_historical_cutoff_export(
    *,
    history_dir: Path,
    sample_frame_path: Path,
    manifest_path: Path,
    labels_path: Path,
    output_dir: Path,
    selection_metadata_path: Path | None = None,
    cutoffs: tuple[str, ...] = DEFAULT_CUTOFFS,
) -> dict[str, Any]:
    """Build separate CPE/CWE pilot graphs using saved dated NVD events and labels."""
    started = time.perf_counter()
    paths = [Path(p) for p in (history_dir, sample_frame_path, manifest_path, labels_path)]
    history_dir, sample_frame_path, manifest_path, labels_path = paths
    selection_metadata_path = (
        Path(selection_metadata_path) if selection_metadata_path is not None else None
    )
    output_dir = Path(output_dir)
    if output_dir.exists():
        raise FileExistsError(f"Refusing to overwrite output directory: {output_dir}")
    if not history_dir.is_dir():
        raise NotADirectoryError(history_dir)
    normalized_cutoffs = tuple(_parse_utc(value) for value in cutoffs)
    if not normalized_cutoffs or len(set(normalized_cutoffs)) != len(normalized_cutoffs):
        raise ValueError("Cutoffs must be non-empty and unique")
    cutoff_keys = {value.isoformat() for value in normalized_cutoffs}
    sample = _load_sample(sample_frame_path, manifest_path)
    cve_ids = set(sample["cve_id"])
    labels = _load_saved_labels(labels_path, cve_ids, cutoff_keys)
    selection_metadata = None
    if selection_metadata_path is not None:
        selection_metadata = json.loads(selection_metadata_path.read_text(encoding="utf-8"))
        if selection_metadata.get("sample_size") != len(sample):
            raise ValueError("Selection metadata sample_size does not match the sample frame")
        if selection_metadata.get("created_before_collection") is not True:
            raise ValueError("Selection metadata does not attest selection before collection")

    histories: dict[str, dict[str, Any] | None] = {}
    source_info: dict[str, dict[str, Any]] = {}
    history_errors: dict[str, str] = {}
    for cve_id in sorted(cve_ids):
        path = history_dir / f"{cve_id}.json"
        if not path.is_file():
            histories[cve_id] = None
            continue
        source_info[cve_id] = {"path": str(path), "sha256": _sha256(path)}
        try:
            history = json.loads(path.read_text(encoding="utf-8"))
            validate_history_response(history, cve_id)
            histories[cve_id] = history
        except (OSError, json.JSONDecodeError, TypeError, ValueError):
            histories[cve_id] = None
            history_errors[cve_id] = "invalid_history_response"

    output_dir.mkdir(parents=True)
    summary_rows: list[dict[str, Any]] = []
    all_metadata: dict[str, Any] = {}
    for cutoff in normalized_cutoffs:
        cutoff_key = cutoff.isoformat()
        cutoff_dir = output_dir / cutoff.date().isoformat()
        cutoff_dir.mkdir()
        cutoff_meta: dict[str, Any] = {}
        cutoff_records: dict[str, list[LayerRelationships]] = {"cpe": [], "cwe": []}
        row_context: dict[str, dict[str, Any]] = {}
        for row in sample.itertuples(index=False):
            cve_id = row.cve_id
            published = row.published.to_pydatetime()
            history = histories[cve_id]
            error = history_errors.get(cve_id)
            if published > cutoff:
                records = {
                    layer: _record_for_layer(
                        layer,
                        cve_id,
                        cutoff,
                        published,
                        history_dir / f"{cve_id}.json",
                        history,
                        None,
                    )
                    for layer in ("cpe", "cwe")
                }
            elif history is not None:
                try:
                    records = reconstruct_relationship_layers(history, cutoff, cve_id)
                except (KeyError, TypeError, ValueError) as exception:
                    records = {
                        layer: LayerRelationships(
                            cve_id,
                            cutoff,
                            layer,
                            (),
                            False,
                            ("reconstruction_failed",),
                        )
                        for layer in ("cpe", "cwe")
                    }
                    error = f"reconstruction_failed:{type(exception).__name__}"
            else:
                records = {
                    layer: _record_for_layer(
                        layer,
                        cve_id,
                        cutoff,
                        published,
                        history_dir / f"{cve_id}.json",
                        None,
                        error,
                    )
                    for layer in ("cpe", "cwe")
                }
            event_times = _event_times(history, cve_id) if history is not None else []
            visible_times = [stamp for stamp in event_times if stamp <= cutoff]
            row_context[cve_id] = {
                "published": published.isoformat(),
                "events_total": len(event_times),
                "events_by_cutoff": len(visible_times),
                "latest_event": max(visible_times).isoformat() if visible_times else "",
                "history_path": source_info.get(cve_id, {}).get("path", ""),
                "history_sha256": source_info.get(cve_id, {}).get("sha256", ""),
                "history_error": error or "",
            }
            for layer in ("cpe", "cwe"):
                cutoff_records[layer].append(records[layer])

        for layer in ("cpe", "cwe"):
            feature_frame, outcome_frame, metadata = analyze_layer(cutoff_records[layer])
            record_by_id = {record.cve_id: record for record in cutoff_records[layer]}
            feature_by_id = feature_frame.set_index("cve_id").to_dict(orient="index")
            degree_name = metadata["degree_feature"]
            centrality_name = metadata["degree_centrality_feature"]
            rows = []
            for outcome in outcome_frame.to_dict(orient="records"):
                cve_id = outcome["cve_id"]
                record = record_by_id[cve_id]
                context = row_context[cve_id]
                label = labels[(cve_id, cutoff_key)]
                feature_values = feature_by_id.get(cve_id, {})
                rows.append(
                    {
                        "cve_id": cve_id,
                        "cutoff_timestamp": cutoff_key,
                        "published_timestamp": context["published"],
                        "layer": layer,
                        "evidence_eligible": bool(record.eligible),
                        "feature_status": outcome["feature_status"],
                        "reason": outcome["reason"] or "",
                        "relationship_count": len(record.relationships)
                        if record.eligible
                        else pd.NA,
                        "relationships_json": _relationships_json(record),
                        "degree_feature": feature_values.get(degree_name, pd.NA),
                        "degree_centrality_feature": feature_values.get(centrality_name, pd.NA),
                        "pagerank": feature_values.get("pagerank", pd.NA),
                        "history_path": context["history_path"],
                        "history_sha256": context["history_sha256"],
                        "history_events_total": context["events_total"],
                        "history_events_by_cutoff": context["events_by_cutoff"],
                        "latest_event_by_cutoff": context["latest_event"],
                        "kev_outcome_status": label["status"],
                        "kev_outcome_label": label["label"],
                        "kev_horizon_days": label["horizon_days"],
                    }
                )
            per_cve = pd.DataFrame(rows, columns=OUTPUT_COLUMNS).sort_values("cve_id")
            layer_dir = cutoff_dir / layer
            layer_dir.mkdir()
            per_cve.to_csv(layer_dir / "outcomes.csv", index=False)
            per_cve[per_cve["feature_status"] == "available"].to_csv(
                layer_dir / "features.csv", index=False
            )
            metadata.update(
                {
                    "cutoff_timestamp": cutoff_key,
                    "population_scope": "130-CVE stratified probability pilot only",
                    "history_files_present": sum(
                        bool(row_context[cve_id]["history_path"]) for cve_id in cve_ids
                    ),
                    "history_or_reconstruction_errors": sum(
                        bool(row_context[cve_id]["history_error"]) for cve_id in cve_ids
                    ),
                    "history_events_observed_by_cutoff": sum(
                        row_context[cve_id]["events_by_cutoff"] for cve_id in cve_ids
                    ),
                    "event_timestamps_prove_public_availability": False,
                    "relationships_not_reconstructed_from_current_only_snapshots": True,
                    "input_sample_frame": str(sample_frame_path),
                    "input_labels": str(labels_path),
                    "features_file": str(layer_dir / "features.csv"),
                    "outcomes_file": str(layer_dir / "outcomes.csv"),
                }
            )
            (layer_dir / "metadata.json").write_text(
                json.dumps(metadata, indent=2, sort_keys=True) + "\n", encoding="utf-8"
            )
            cutoff_meta[layer] = metadata
            summary_rows.append(
                {
                    "cutoff_timestamp": cutoff_key,
                    "layer": layer,
                    "pilot_population_cves": metadata["population_cves"],
                    "published_by_cutoff_cves": metadata["published_by_cutoff_cves"],
                    "not_published_at_cutoff_cves": metadata["not_published_at_cutoff_cves"],
                    "evidence_eligible_cves": metadata["evidence_eligible_cves"],
                    "evidence_ineligible_cves": metadata["evidence_ineligible_cves"],
                    "known_empty_relationship_cves": metadata["known_empty_relationship_cves"],
                    "feature_rows": metadata["feature_rows"],
                    "graph_nodes_by_type": json.dumps(
                        metadata["graph_nodes_by_type"], sort_keys=True
                    ),
                    "graph_edges": metadata["graph_edges"],
                    "kev_positive_in_sample": sum(
                        label["label"] is True
                        for (sample_id, label_cutoff), label in labels.items()
                        if label_cutoff == cutoff_key
                    ),
                }
            )
        all_metadata[cutoff_key] = cutoff_meta
    summary_frame = pd.DataFrame(summary_rows)
    summary_frame.to_csv(output_dir / "cutoff_summary.csv", index=False)
    metadata = {
        "analysis_type": "exploratory_cutoff_specific_historical_graph_features",
        "cutoffs_utc": [cutoff.isoformat() for cutoff in normalized_cutoffs],
        "pilot_sample_size": len(sample),
        "pilot_selection_method": (
            "Stratified SRS without replacement; existing seed and selection metadata retained."
        ),
        "history_directory": str(history_dir),
        "sample_frame": str(sample_frame_path),
        "sample_frame_sha256": _sha256(sample_frame_path),
        "research_manifest": str(manifest_path),
        "research_manifest_sha256": _sha256(manifest_path),
        "selection_metadata_path": str(selection_metadata_path)
        if selection_metadata_path is not None
        else None,
        "selection_metadata_sha256": _sha256(selection_metadata_path)
        if selection_metadata_path is not None
        else None,
        "sample_selection_seed": selection_metadata.get("seed") if selection_metadata else None,
        "sample_stratum_population_counts": selection_metadata.get("stratum_population_counts")
        if selection_metadata
        else None,
        "sample_inclusion_probabilities": selection_metadata.get("selection_probabilities")
        if selection_metadata
        else None,
        "sample_analysis_weights": selection_metadata.get("analysis_weights")
        if selection_metadata
        else None,
        "saved_kev_labels": str(labels_path),
        "saved_kev_labels_sha256": _sha256(labels_path),
        "history_source_sha256_by_cve": {
            cve_id: info["sha256"] for cve_id, info in sorted(source_info.items())
        },
        "full_population_historical_graph_supported": False,
        "historical_availability_claim": False,
        "production_component_d_integration": False,
        "limits": [
            "Graph centralities are scoped to the evidence-eligible pilot CVEs at each cutoff.",
            (
                "The probability sample is not a complete graph population; PageRank and degree "
                "values are pilot-graph-relative."
            ),
            (
                "Recorded NVD history event timestamps do not prove information was publicly "
                "available at those times."
            ),
            (
                "Current monthly NVD snapshots are not substituted for dated per-CVE "
                "relationship evidence."
            ),
            (
                "Layer-specific features remain exploratory and are not silently mapped to the "
                "shared production Score contract."
            ),
        ],
        "cutoff_results": all_metadata,
        "runtime_seconds": round(time.perf_counter() - started, 6),
    }
    (output_dir / "run_metadata.json").write_text(
        json.dumps(metadata, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    report = [
        "# Component C historical cutoff feature pilot",
        "",
        (
            "Exploratory, cutoff-specific CPE and CWE graphs reconstructed from the saved "
            "130-CVE probability sample."
        ),
        "This is not a population-wide historical graph or a validated prediction evaluation.",
        (
            "KEV outcome labels were reused from the saved label-readiness output; no label "
            "data was downloaded or regenerated."
        ),
        (
            "NVD event timestamps support event-time replay, but do not prove public "
            "availability at the event timestamp."
        ),
        "",
        summary_frame.to_string(index=False),
        "",
        (
            "Full-population chronological evaluation remains unsupported: local histories "
            "cover only a small fraction of the manifest, and graph centralities depend on "
            "the included graph population."
        ),
    ]
    (output_dir / "report.md").write_text("\n".join(report) + "\n", encoding="utf-8")
    return metadata
