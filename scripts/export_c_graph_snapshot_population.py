"""Create manifest-scoped feature and Score files from a full NVD snapshot graph."""

from __future__ import annotations

import argparse
import gzip
import json
import os
import tempfile
from datetime import UTC, date, datetime
from pathlib import Path
from typing import Any

import pandas as pd

from vesper.components.c_graph.multi_historical_pipeline import (
    DEFAULT_MANIFEST,
    load_research_manifest,
)
from vesper.components.c_graph.score_export import export_graph_scores
from vesper.components.c_graph.scoring import FEATURE_COLUMNS


def _parse_time(value: str) -> datetime:
    normalized = value.strip()
    if normalized.endswith("Z"):
        normalized = normalized[:-1] + "+00:00"
    parsed = datetime.fromisoformat(normalized)
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=UTC)
    return parsed.astimezone(UTC)


def _record_date(value: Any) -> date | None:
    if not isinstance(value, str) or not value.strip():
        return None
    try:
        return _parse_time(value).date()
    except ValueError:
        return None


def _write_csv_atomically(frame: pd.DataFrame, path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, temp_name = tempfile.mkstemp(prefix=f".{path.name}.", suffix=".tmp", dir=path.parent)
    try:
        with os.fdopen(fd, "w", encoding="utf-8", newline="") as stream:
            frame.to_csv(stream, index=False)
        os.replace(temp_name, path)
    except BaseException:
        Path(temp_name).unlink(missing_ok=True)
        raise


def _write_json_atomically(data: dict[str, Any], path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_suffix(path.suffix + ".tmp")
    try:
        temporary.write_text(json.dumps(data, indent=2) + "\n", encoding="utf-8")
        os.replace(temporary, path)
    finally:
        temporary.unlink(missing_ok=True)


def collect_rejected_target_ids(
    nvd_dir: Path,
    target_ids: set[str],
    snapshot_date: date,
) -> tuple[dict[str, str], list[str]]:
    """Find target CVEs rejected by NVD at the requested cutoff."""
    rejected: dict[str, str] = {}
    download_times = []
    for path in sorted(nvd_dir.glob("nvd_*.json.gz")):
        with gzip.open(path, "rt", encoding="utf-8") as stream:
            data = json.load(stream)
        downloaded_at = data.get("downloaded_at")
        if isinstance(downloaded_at, str):
            download_times.append(downloaded_at)
        for record in data.get("vulnerabilities", []):
            cve = record.get("cve", {}) if isinstance(record, dict) else {}
            cve_id = cve.get("id") if isinstance(cve, dict) else None
            if cve_id not in target_ids:
                continue
            if (
                _record_date(cve.get("published")) is None
                or _record_date(cve.get("published")) > snapshot_date
                or _record_date(cve.get("lastModified")) is None
                or _record_date(cve.get("lastModified")) > snapshot_date
            ):
                continue
            if str(cve.get("vulnStatus", "")).strip().casefold() == "rejected":
                rejected[cve_id] = "NVD marks this CVE as Rejected at the snapshot cutoff."
    return rejected, download_times


def export_snapshot_population(
    *,
    nvd_dir: Path,
    full_graph_features_path: Path,
    manifest_path: Path,
    output_dir: Path,
    snapshot_at: datetime,
    horizon_days: int,
) -> dict[str, Any]:
    """Filter whole-NVD graph features to the research population and score all targets."""
    if snapshot_at.tzinfo is None or snapshot_at.utcoffset() is None:
        raise ValueError("snapshot_at must include a time zone")
    cutoff = snapshot_at.astimezone(UTC)
    population = load_research_manifest(manifest_path)
    target_ids = set(population)

    graph_features = pd.read_csv(full_graph_features_path)
    if list(graph_features.columns) != FEATURE_COLUMNS:
        raise ValueError(f"Feature columns must be exactly {FEATURE_COLUMNS!r}")
    if graph_features["cve_id"].duplicated().any():
        raise ValueError("Full graph feature table contains duplicate CVE IDs")

    source_metadata_path = full_graph_features_path.with_suffix(".metadata.json")
    source_metadata = json.loads(source_metadata_path.read_text(encoding="utf-8"))
    if source_metadata.get("snapshot_date") != cutoff.date().isoformat():
        raise ValueError("Graph feature snapshot date must match snapshot_at")
    if source_metadata.get("historical_reconstruction") != "not_performed":
        raise ValueError("This exporter expects features from the NVD snapshot pipeline")

    target_features = graph_features[graph_features["cve_id"].isin(target_ids)].copy()
    target_features = target_features.sort_values("cve_id", kind="stable").reset_index(drop=True)
    feature_ids = set(target_features["cve_id"])
    missing_ids = target_ids - feature_ids
    rejected_reasons, download_times = collect_rejected_target_ids(
        nvd_dir, target_ids, cutoff.date()
    )
    rejected_reasons = {
        cve_id: reason for cve_id, reason in rejected_reasons.items() if cve_id in missing_ids
    }
    if not download_times:
        raise ValueError("No downloaded_at timestamps found in local NVD monthly files")
    earliest_download, latest_download = min(download_times), max(download_times)
    if _parse_time(latest_download) > cutoff:
        raise ValueError("At least one NVD source file was downloaded after snapshot_at")

    output_dir.mkdir(parents=True, exist_ok=True)
    target_features_path = output_dir / "research_population_features.csv"
    _write_csv_atomically(target_features, target_features_path)

    exclusions = []
    for cve_id in sorted(missing_ids):
        exclusions.append(
            {
                "cve_id": cve_id,
                "reason": "not_eligible_rejected"
                if cve_id in rejected_reasons
                else "no_feature_row_in_snapshot_graph",
                "detail": rejected_reasons.get(
                    cve_id,
                    "No valid feature row was produced from the supplied NVD snapshot graph.",
                ),
            }
        )
    exclusions_path = output_dir / "research_population_features.exclusions.csv"
    _write_csv_atomically(
        pd.DataFrame(exclusions, columns=["cve_id", "reason", "detail"]), exclusions_path
    )

    graph_scope = (
        "Graph statistics were calculated over all non-Rejected CVEs in the local NVD monthly "
        "records eligible at the cutoff, including CVEs published before the research interval. "
        "The feature CSV is filtered to the research manifest after global graph statistics "
        "are computed."
    )
    source_description = (
        "Latest local NVD CVE records partitioned by publication month; source files were "
        f"downloaded between {earliest_download} and {latest_download}. "
        f"The snapshot cutoff is {cutoff.isoformat()}. "
        "Per-CVE change histories were not used to reconstruct earlier relationship states."
    )
    scores_path = output_dir / "c_graph_scores.csv"
    records = export_graph_scores(
        target_features,
        population.keys(),
        scores_path,
        snapshot_at=cutoff,
        horizon_days=horizon_days,
        source_features=target_features_path,
        not_eligible_reasons=rejected_reasons,
        graph_scope=graph_scope,
        source_description=source_description,
    )

    metadata = {
        "research_start_utc": "2016-01-01T00:00:00+00:00",
        "research_end_exclusive_utc": "2026-10-15T00:00:00+00:00",
        "snapshot_at": cutoff.isoformat(),
        "source_downloaded_at_min": earliest_download,
        "source_downloaded_at_max": latest_download,
        "research_population_count": len(target_ids),
        "target_feature_rows": len(target_features),
        "target_ids_without_feature_rows": len(missing_ids),
        "target_rejected_not_eligible": len(rejected_reasons),
        "target_missing_other_reason": len(missing_ids - set(rejected_reasons)),
        "out_of_population_graph_feature_rows": len(set(graph_features["cve_id"]) - target_ids),
        "graph_scope": graph_scope,
        "historical_reconstruction": "not_performed",
        "source_description": source_description,
        "features_csv": str(target_features_path),
        "exclusions_csv": str(exclusions_path),
        "scores_csv": str(scores_path),
        "score_records": len(records),
        "score_status_counts": pd.Series([record.status.value for record in records])
        .value_counts()
        .to_dict(),
    }
    _write_json_atomically(metadata, output_dir / "research_population_features.metadata.json")
    return metadata


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Export manifest-scoped Component C features and Score records."
    )
    parser.add_argument("--nvd-dir", type=Path, default=Path("data/raw/nvd"))
    parser.add_argument("--full-graph-features", type=Path, required=True)
    parser.add_argument("--manifest", type=Path, default=DEFAULT_MANIFEST)
    parser.add_argument("--output-dir", type=Path, required=True)
    parser.add_argument("--snapshot-at", type=_parse_time, required=True)
    parser.add_argument("--horizon-days", type=int, required=True)
    args = parser.parse_args()
    print(
        json.dumps(
            export_snapshot_population(
                nvd_dir=args.nvd_dir,
                full_graph_features_path=args.full_graph_features,
                manifest_path=args.manifest,
                output_dir=args.output_dir,
                snapshot_at=args.snapshot_at,
                horizon_days=args.horizon_days,
            ),
            indent=2,
        )
    )


if __name__ == "__main__":
    main()
