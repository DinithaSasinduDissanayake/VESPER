"""Replay a bounded set of saved NVD histories at Component C cutoffs."""

from __future__ import annotations

import argparse
import hashlib
import json
import time
from datetime import datetime
from pathlib import Path
from typing import Any

import pandas as pd

from vesper.components.c_graph.historical import validate_history_response
from vesper.components.c_graph.historical_cutoff_export import _load_saved_labels
from vesper.components.c_graph.layered_historical import (
    LayerRelationships,
    analyze_layer,
    reconstruct_relationship_layers,
)

DEFAULT_CUTOFFS = tuple(f"{year}-01-01T00:00:00+00:00" for year in range(2022, 2027))
DETAIL_COLUMNS = [
    "cve_id",
    "cutoff_timestamp",
    "published_timestamp",
    "layer",
    "evidence_eligible",
    "feature_status",
    "reason",
    "relationships_json",
    "history_path",
    "history_sha256",
    "history_events_total",
    "history_events_by_cutoff",
    "history_events_after_cutoff",
    "latest_event_by_cutoff",
    "nvd_response_timestamp",
    "collection_started_at_utc",
    "request_page_count",
    "request_retries",
    "request_started_at_utc",
    "request_ended_at_utc",
    "request_http_statuses",
    "kev_outcome_status",
    "kev_outcome_label",
    "kev_horizon_days",
    "degree_feature",
    "degree_centrality_feature",
    "pagerank",
]
EVENT_COLUMNS = [
    "cve_id",
    "cve_change_id",
    "created_timestamp",
    "event_name",
    "source_identifier",
    "detail_index",
    "detail_type",
    "action",
    "old_value",
    "new_value",
]


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as source:
        for block in iter(lambda: source.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def _utc(value: str | datetime | pd.Timestamp, *, assume_naive_utc: bool = False) -> datetime:
    parsed = pd.Timestamp(value)
    if parsed.tzinfo is None:
        if not assume_naive_utc:
            raise ValueError(f"Timestamp must include a timezone: {value!r}")
        parsed = parsed.tz_localize("UTC")
    return parsed.tz_convert("UTC").to_pydatetime()


def _read_selection(selection_path: Path, manifest_path: Path) -> pd.DataFrame:
    selection = pd.read_csv(selection_path, dtype={"cve_id": "string"})
    manifest = pd.read_csv(manifest_path, dtype={"cve_id": "string"})
    required = {"cve_id", "published"}
    if not required.issubset(selection.columns) or not required.issubset(manifest.columns):
        raise ValueError("Selection and research manifest must contain cve_id and published")
    for frame, name in ((selection, "selection"), (manifest, "manifest")):
        frame["cve_id"] = frame["cve_id"].str.strip().str.upper()
        if frame["cve_id"].isna().any() or frame["cve_id"].duplicated().any():
            raise ValueError(f"{name} CVE IDs must be present and unique")
        frame["published"] = pd.to_datetime(
            frame["published"], format="mixed", utc=True, errors="coerce"
        )
        if frame["published"].isna().any():
            raise ValueError(f"{name} has invalid publication timestamps")
    manifest_dates = manifest.set_index("cve_id")["published"]
    for row in selection.itertuples(index=False):
        if row.cve_id not in manifest_dates.index or row.published != manifest_dates.at[row.cve_id]:
            raise ValueError(f"Selection disagrees with research manifest for {row.cve_id}")
    return selection.sort_values("cve_id").reset_index(drop=True)


def _load_histories(
    history_dir: Path, cve_ids: set[str]
) -> tuple[dict[str, dict[str, Any]], dict[str, str]]:
    histories: dict[str, dict[str, Any]] = {}
    hashes: dict[str, str] = {}
    for cve_id in sorted(cve_ids):
        path = history_dir / f"{cve_id}.json"
        if not path.is_file():
            raise FileNotFoundError(f"Selected history is missing: {path}")
        history = json.loads(path.read_text(encoding="utf-8"))
        validate_history_response(history, cve_id)
        histories[cve_id] = history
        hashes[cve_id] = _sha256(path)
    return histories, hashes


def _events(history: dict[str, Any], cve_id: str) -> list[dict[str, Any]]:
    return [
        envelope["change"]
        for envelope in history.get("cveChanges", [])
        if envelope.get("change", {}).get("cveId") == cve_id
    ]


def _event_detail_rows(history: dict[str, Any], cve_id: str) -> list[dict[str, Any]]:
    rows = []
    for event in _events(history, cve_id):
        details = event.get("details", [])
        if not details:
            rows.append(
                {
                    "cve_id": cve_id,
                    "cve_change_id": event.get("cveChangeId", ""),
                    "created_timestamp": event.get("created", ""),
                    "event_name": event.get("eventName", ""),
                    "source_identifier": event.get("sourceIdentifier", ""),
                    "detail_index": pd.NA,
                    "detail_type": "",
                    "action": "",
                    "old_value": "",
                    "new_value": "",
                }
            )
        for index, detail in enumerate(details):
            rows.append(
                {
                    "cve_id": cve_id,
                    "cve_change_id": event.get("cveChangeId", ""),
                    "created_timestamp": event.get("created", ""),
                    "event_name": event.get("eventName", ""),
                    "source_identifier": event.get("sourceIdentifier", ""),
                    "detail_index": index,
                    "detail_type": detail.get("type", ""),
                    "action": detail.get("action", ""),
                    "old_value": detail.get("oldValue", ""),
                    "new_value": detail.get("newValue", ""),
                }
            )
    return rows


def run_pilot_replay(
    *,
    history_dir: Path,
    selection_path: Path,
    manifest_path: Path,
    labels_path: Path,
    output_dir: Path,
    cutoffs: tuple[str, ...] = DEFAULT_CUTOFFS,
) -> dict[str, Any]:
    """Create deterministic per-cutoff layer outcomes from saved histories."""
    started = time.perf_counter()
    history_dir, selection_path, manifest_path, labels_path = map(
        Path, (history_dir, selection_path, manifest_path, labels_path)
    )
    output_dir = Path(output_dir)
    if output_dir.exists():
        raise FileExistsError(f"Refusing to overwrite pilot replay output: {output_dir}")
    parsed_cutoffs = tuple(_utc(value) for value in cutoffs)
    if not parsed_cutoffs or len(set(parsed_cutoffs)) != len(parsed_cutoffs):
        raise ValueError("Cutoffs must be non-empty and unique")
    cutoff_keys = tuple(value.isoformat() for value in parsed_cutoffs)
    selection = _read_selection(selection_path, manifest_path)
    cve_ids = set(selection["cve_id"])
    histories, history_hashes = _load_histories(history_dir, cve_ids)
    download_report_path = history_dir / "download_report.json"
    download_report = (
        json.loads(download_report_path.read_text(encoding="utf-8"))
        if download_report_path.is_file()
        else {}
    )
    request_by_id = {
        item["cve_id"]: item for item in download_report.get("successful_responses", [])
    }
    request_metadata_dirs = (
        history_dir.parent / "request_metadata",
        history_dir / "request_metadata",
    )
    request_metadata_by_id: dict[str, dict[str, Any]] = {}
    for cve_id in sorted(cve_ids):
        sidecar = next(
            (
                directory / f"{cve_id}.json"
                for directory in request_metadata_dirs
                if (directory / f"{cve_id}.json").is_file()
            ),
            None,
        )
        if sidecar is not None:
            request_metadata_by_id[cve_id] = json.loads(sidecar.read_text(encoding="utf-8"))
    run_started_at = download_report.get("run_started_at_utc", "")
    labels = _load_saved_labels(labels_path, cve_ids, set(cutoff_keys))

    outcome_rows: list[dict[str, Any]] = []
    event_rows = [
        row for cve_id in sorted(cve_ids) for row in _event_detail_rows(histories[cve_id], cve_id)
    ]
    summary_rows: list[dict[str, Any]] = []
    cutoff_metadata: dict[str, Any] = {}
    for cutoff in parsed_cutoffs:
        cutoff_key = cutoff.isoformat()
        records_by_layer: dict[str, list[LayerRelationships]] = {"cpe": [], "cwe": []}
        context_by_id: dict[str, dict[str, Any]] = {}
        for row in selection.itertuples(index=False):
            cve_id = row.cve_id
            published = row.published.to_pydatetime()
            history = histories[cve_id]
            events = _events(history, cve_id)
            event_stamps = [_utc(event["created"], assume_naive_utc=True) for event in events]
            visible = [stamp for stamp in event_stamps if stamp <= cutoff]
            context_by_id[cve_id] = {
                "published": published.isoformat(),
                "history_events_total": len(events),
                "history_events_by_cutoff": len(visible),
                "history_events_after_cutoff": len(event_stamps) - len(visible),
                "latest_event_by_cutoff": max(visible).isoformat() if visible else "",
            }
            if published > cutoff:
                layer_records = {
                    layer: LayerRelationships(
                        cve_id, cutoff, layer, (), False, ("not_published_at_cutoff",)
                    )
                    for layer in ("cpe", "cwe")
                }
            else:
                layer_records = reconstruct_relationship_layers(history, cutoff, cve_id)
            for layer in ("cpe", "cwe"):
                records_by_layer[layer].append(layer_records[layer])

        cutoff_metadata[cutoff_key] = {}
        for layer in ("cpe", "cwe"):
            features, outcomes, layer_metadata = analyze_layer(records_by_layer[layer])
            layer_metadata["analysis_type"] = (
                "exploratory_offline_history_evidence_expansion_layer_analysis"
            )
            record_by_id = {record.cve_id: record for record in records_by_layer[layer]}
            feature_by_id = features.set_index("cve_id").to_dict(orient="index")
            degree_name = layer_metadata["degree_feature"]
            centrality_name = layer_metadata["degree_centrality_feature"]
            for item in outcomes.to_dict(orient="records"):
                cve_id = item["cve_id"]
                record = record_by_id[cve_id]
                context = context_by_id[cve_id]
                label = labels[(cve_id, cutoff_key)]
                values = feature_by_id.get(cve_id, {})
                outcome_rows.append(
                    {
                        "cve_id": cve_id,
                        "cutoff_timestamp": cutoff_key,
                        "published_timestamp": context["published"],
                        "layer": layer,
                        "evidence_eligible": bool(record.eligible),
                        "feature_status": item["feature_status"],
                        "reason": item["reason"] or "",
                        "relationships_json": json.dumps(
                            [
                                {"vendor": vendor, "product": product}
                                for vendor, product in record.relationships
                            ]
                            if layer == "cpe"
                            else [{"cwe_id": value} for value in record.relationships],
                            sort_keys=True,
                            separators=(",", ":"),
                        )
                        if record.eligible
                        else "",
                        "history_path": str(history_dir / f"{cve_id}.json"),
                        "history_sha256": history_hashes[cve_id],
                        "nvd_response_timestamp": histories[cve_id].get("timestamp", ""),
                        "collection_started_at_utc": run_started_at,
                        "request_page_count": request_metadata_by_id.get(cve_id, {}).get(
                            "page_request_count",
                            request_by_id.get(cve_id, {}).get("page_requests", pd.NA),
                        ),
                        "request_retries": request_metadata_by_id.get(cve_id, {}).get(
                            "retry_count", request_by_id.get(cve_id, {}).get("retries", pd.NA)
                        ),
                        "request_started_at_utc": request_metadata_by_id.get(cve_id, {}).get(
                            "request_started_at_utc", ""
                        ),
                        "request_ended_at_utc": request_metadata_by_id.get(cve_id, {}).get(
                            "request_ended_at_utc", ""
                        ),
                        "request_http_statuses": json.dumps(
                            request_metadata_by_id.get(cve_id, {}).get("http_statuses", [])
                        ),
                        **context,
                        "kev_outcome_status": label["status"],
                        "kev_outcome_label": label["label"],
                        "kev_horizon_days": label["horizon_days"],
                        "degree_feature": values.get(degree_name, pd.NA),
                        "degree_centrality_feature": values.get(centrality_name, pd.NA),
                        "pagerank": values.get("pagerank", pd.NA),
                    }
                )
            published_count = layer_metadata["published_by_cutoff_cves"]
            published_ids = {
                cve_id
                for cve_id, context in context_by_id.items()
                if _utc(context["published"]) <= cutoff
            }
            summary = {
                "cutoff_timestamp": cutoff_key,
                "layer": layer,
                "pilot_cves": layer_metadata["population_cves"],
                "published_by_cutoff_cves": published_count,
                "not_published_at_cutoff_cves": layer_metadata["not_published_at_cutoff_cves"],
                "evidence_eligible_cves": layer_metadata["evidence_eligible_cves"],
                "evidence_ineligible_cves": layer_metadata["evidence_ineligible_cves"],
                "known_empty_relationship_cves": layer_metadata["known_empty_relationship_cves"],
                "feature_rows": layer_metadata["feature_rows"],
                "graph_nodes_by_type": json.dumps(
                    layer_metadata["graph_nodes_by_type"], sort_keys=True
                ),
                "graph_edges": layer_metadata["graph_edges"],
                "kev_positive_labels_in_sample": sum(
                    value["label"] is True
                    for (sample_id, label_cutoff), value in labels.items()
                    if label_cutoff == cutoff_key and sample_id in published_ids
                ),
            }
            summary_rows.append(summary)
            cutoff_metadata[cutoff_key][layer] = layer_metadata

    output_dir.mkdir(parents=True)
    outcome_frame = pd.DataFrame(outcome_rows, columns=DETAIL_COLUMNS).sort_values(
        ["cutoff_timestamp", "layer", "cve_id"]
    )
    summary_frame = pd.DataFrame(summary_rows).sort_values(["cutoff_timestamp", "layer"])
    event_frame = pd.DataFrame(event_rows, columns=EVENT_COLUMNS).sort_values(
        ["cve_id", "created_timestamp", "cve_change_id", "detail_index"], na_position="last"
    )
    outcome_frame.to_csv(output_dir / "cutoff_layer_outcomes.csv", index=False)
    outcome_frame[outcome_frame["feature_status"] == "available"].to_csv(
        output_dir / "cutoff_features.csv", index=False
    )
    summary_frame.to_csv(output_dir / "cutoff_summary.csv", index=False)
    event_frame.to_csv(output_dir / "event_details.csv", index=False)

    metadata = {
        "analysis_type": "exploratory_bounded_historical_evidence_expansion_pilot",
        "population_scope": (
            "Six deterministically selected CVEs absent from the three prior local history corpora"
        ),
        "selection_manifest": str(selection_path),
        "selection_manifest_sha256": _sha256(selection_path),
        "research_population_manifest": str(manifest_path),
        "research_population_manifest_sha256": _sha256(manifest_path),
        "saved_kev_labels": str(labels_path),
        "saved_kev_labels_sha256": _sha256(labels_path),
        "history_directory": str(history_dir),
        "history_sha256_by_cve": dict(sorted(history_hashes.items())),
        "source_endpoint": "https://services.nvd.nist.gov/rest/json/cvehistory/2.0",
        "download_report": str(download_report_path) if download_report else "",
        "download_report_sha256": (
            _sha256(download_report_path) if download_report_path.is_file() else ""
        ),
        "collection_run_started_at_utc": run_started_at,
        "collection_request_counts": {
            key: download_report.get(key)
            for key in (
                "page_requests",
                "max_page_requests",
                "retries",
                "new_responses_saved",
                "failed_this_run",
                "elapsed_seconds",
            )
            if key in download_report
        },
        "nvd_response_timestamp_by_cve": {
            cve_id: histories[cve_id].get("timestamp", "") for cve_id in sorted(cve_ids)
        },
        "request_timestamp_limitation": (
            "Per-attempt client start/end timestamps are available when the separate request "
            "metadata sidecar exists; older collections without sidecars retain only run-level "
            "or response timestamps."
        ),
        "event_timestamp_timezone_policy": (
            "Original timestamp strings remain in event_details.csv and raw response bodies. "
            "Replay treats naive values as UTC. NVD documentation does not guarantee a timezone "
            "for naive event strings, so this normalization is a project assumption."
        ),
        "cutoffs_utc": list(cutoff_keys),
        "event_timestamps_prove_public_availability": False,
        "current_monthly_snapshots_used_as_historical_states": False,
        "api_key_value_recorded": False,
        "cutoff_results": cutoff_metadata,
        "limits": [
            (
                "This is a small deterministic diagnostic sample, not a probability sample "
                "or coverage estimator."
            ),
            (
                "NVD change events support event-time replay only and do not prove information "
                "was publicly available at the event timestamp."
            ),
            (
                "CPE output is the supported vendor/product abstraction; version ranges and "
                "logical applicability are not represented in graph edges."
            ),
            (
                "Unsupported Affected links are not followed; independently supported legacy "
                "CPE and CWE streams are evaluated by their own layer policy."
            ),
            (
                "KEV labels are reused for comparison context only; no predictive evaluation "
                "or baseline comparison is performed."
            ),
        ],
        "runtime_seconds": round(time.perf_counter() - started, 6),
    }
    (output_dir / "run_metadata.json").write_text(
        json.dumps(metadata, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    report_lines = [
        "# Component C bounded historical evidence expansion pilot",
        "",
        (
            "Six manifest CVEs absent from all three prior history corpora were selected by "
            "fixed publication-year strata and SHA-256 order."
        ),
        (
            "Their validated NVD history responses were replayed independently at the five "
            "existing UTC cutoffs."
        ),
        (
            "This is exploratory evidence coverage, not a representative population estimate "
            "or predictive evaluation."
        ),
        (
            "NVD event timestamps do not prove public availability to a decision-maker at "
            "that timestamp."
        ),
        "",
        summary_frame.to_string(index=False),
        "",
        (
            "Per-CVE states, reasons, relationships, event counts, labels, and provenance "
            "are in `cutoff_layer_outcomes.csv`; source detail values are in `event_details.csv`."
        ),
        "Unavailable and future-published states remain explicit, with blank numeric features.",
    ]
    (output_dir / "pilot_report.md").write_text("\n".join(report_lines) + "\n", encoding="utf-8")
    return metadata


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--history-dir", type=Path, required=True)
    parser.add_argument("--selection", type=Path, required=True)
    parser.add_argument(
        "--manifest", type=Path, default=Path("data/processed/c_graph/research_population.csv")
    )
    parser.add_argument(
        "--labels",
        type=Path,
        default=Path(
            "outputs/c_graph_kev_label_readiness_2026-10-16_run2/kev_outcomes_by_cutoff.csv"
        ),
    )
    parser.add_argument("--output-dir", type=Path, required=True)
    parser.add_argument("--cutoff", action="append", dest="cutoffs")
    args = parser.parse_args()
    result = run_pilot_replay(
        history_dir=args.history_dir,
        selection_path=args.selection,
        manifest_path=args.manifest,
        labels_path=args.labels,
        output_dir=args.output_dir,
        cutoffs=tuple(args.cutoffs) if args.cutoffs else DEFAULT_CUTOFFS,
    )
    print(
        f"Replayed {len(result['history_sha256_by_cve'])} histories across "
        f"{len(result['cutoffs_utc'])} cutoffs."
    )
    print(f"Output: {args.output_dir}")


if __name__ == "__main__":
    main()
