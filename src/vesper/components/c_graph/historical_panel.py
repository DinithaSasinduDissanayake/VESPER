"""Stream an explicitly abstaining historical C panel without computing graph scores."""

from __future__ import annotations

import csv
import hashlib
import json
import re
from collections import Counter, defaultdict
from dataclasses import dataclass, fields
from datetime import UTC, date, datetime, time
from pathlib import Path
from typing import Any

from vesper.components.c_graph.historical import (
    HistoricalRelationships,
    reconstruct_relationships,
    validate_history_response,
)
from vesper.components.c_graph.multi_historical_pipeline import load_research_manifest
from vesper.contracts.score import Score

MODEL_VERSION = "c_graph-pagerank-percentile-historical-structural-0.1"
SCORE_COLUMNS = [field.name for field in fields(Score)]
START = date(2023, 1, 1)
END = date(2026, 9, 1)
EXCLUDED = date(2024, 12, 1)
CVE_PATTERN = re.compile(r"CVE-\d{4}-\d{4,}$")
PUBLIC_REASON = "historical_public_availability_unverified"
CONTEXT_REASON = "historical_graph_context_insufficient"
REASON_ORDER = (
    "cve_not_published_at_decision_time",
    "historical_relationship_history_missing",
    "invalid_history_response",
    "historical_source_state_conflict",
    "reconstruction_failed",
    "github_reference_unrecoverable",
    "unsupported_affected_relationship_change",
    "unsupported_cpe_configuration_change",
    "unsupported_cwe_change",
    "uncertain_initial_cpe_state",
    "uncertain_initial_cwe_state",
    "uncertain_initial_affected_state",
    "incomplete_cpe_change_values",
    "incomplete_cwe_change_values",
    "no_interpretable_cpe_events_by_cutoff",
    "no_interpretable_cwe_events_by_cutoff",
    "valid_empty_history_response",
    PUBLIC_REASON,
    CONTEXT_REASON,
)


def sha256(path: Path) -> str:
    """Hash a file in bounded memory."""
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def decision_grid(
    start: date = START,
    end: date = END,
    exclude_date: date = EXCLUDED,
    cutoff_time: str = "00:00:00Z",
) -> tuple[datetime, ...]:
    """Validate the confirmed release grid; alternate grids require a new contract."""
    if (start, end, exclude_date, cutoff_time) != (START, END, EXCLUDED, "00:00:00Z"):
        raise ValueError("This release requires the confirmed 44-date grid at 00:00:00Z")
    grid = tuple(
        datetime.combine(date(year, month, 1), time(tzinfo=UTC))
        for year in range(start.year, end.year + 1)
        for month in range(1, 13)
        if start <= date(year, month, 1) <= end and date(year, month, 1) != exclude_date
    )
    if len(grid) != 44 or len(set(grid)) != len(grid):
        raise ValueError("Historical grid must contain 44 unique decisions")
    return grid


def ordered_reasons(reasons: Any) -> tuple[str, ...]:
    """Choose specific stable diagnoses before general scientific limitations."""
    priority = {reason: index for index, reason in enumerate(REASON_ORDER)}
    return tuple(sorted(set(reasons), key=lambda reason: (priority.get(reason, 20), reason)))


def scientific_reasons(
    *, public_availability_verified: bool = False, graph_context_sufficient: bool = False
) -> tuple[str, ...]:
    """Describe evidence gates; export deliberately never certifies either gate."""
    return tuple(
        reason
        for reason, satisfied in (
            (PUBLIC_REASON, public_availability_verified),
            (CONTEXT_REASON, graph_context_sufficient),
        )
        if not satisfied
    )


@dataclass
class HistorySource:
    """One immutable input copy, decoded once and retained for cutoff replay."""

    path: Path
    digest: str
    history: dict[str, Any] | None
    error: str | None


def discover_histories(
    history_dirs: list[Path],
) -> tuple[dict[str, list[HistorySource]], dict[str, Any]]:
    """Read each distinct file once; retain duplicates for state comparison."""
    directories = sorted({Path(directory).resolve() for directory in history_dirs})
    if not directories:
        raise ValueError("At least one history directory is required")
    for directory in directories:
        if not directory.is_dir():
            raise NotADirectoryError(directory)
    paths = sorted(
        {path.resolve() for directory in directories for path in directory.glob("CVE-*.json")}
    )
    sources: dict[str, list[HistorySource]] = defaultdict(list)
    inventory = []
    for path in paths:
        if not CVE_PATTERN.fullmatch(path.stem):
            raise ValueError(f"Invalid history filename: {path}")
        raw = path.read_bytes()
        digest = hashlib.sha256(raw).hexdigest()
        history = None
        error = None
        try:
            decoded = json.loads(raw)
            validate_history_response(decoded, path.stem)
            history = decoded
        except (ValueError, TypeError) as exc:
            error = str(exc)
        sources[path.stem].append(HistorySource(path, digest, history, error))
        inventory.append({"path": str(path), "sha256": digest, "validation_error": error})
    return dict(sources), {
        "directories": [str(directory) for directory in directories],
        "directory_file_counts": {
            str(directory): len(list(directory.glob("CVE-*.json"))) for directory in directories
        },
        "file_count": len(paths),
        "unique_historical_cve_count": len(sources),
        "valid_unique_historical_cve_count": sum(
            any(source.history is not None for source in copies) for copies in sources.values()
        ),
        "duplicate_extra_copies": len(paths) - len(sources),
        "duplicate_cves": sorted(cve_id for cve_id, copies in sources.items() if len(copies) > 1),
        "duplicate_resolution_policy": (
            "Distinct paths sorted lexically; identical bytes replayed once. Every valid copy "
            "is compared at each cutoff. Any invalid copy fails closed; differing relationship "
            "state, eligibility or exclusion reasons abstain as source-state conflict."
        ),
        "files": inventory,
    }


def assess_history(copies: list[HistorySource], cutoff: datetime, cve_id: str) -> dict[str, Any]:
    """Diagnose a CVE at one cutoff without constructing a graph."""
    reasons = []
    errors = []
    results: list[HistoricalRelationships] = []
    if any(source.error is not None for source in copies):
        reasons.append("invalid_history_response")
        errors.extend(source.error for source in copies if source.error is not None)
    distinct = {source.digest: source for source in copies if source.history is not None}
    for source in distinct.values():
        try:
            result = reconstruct_relationships(source.history, cutoff, cve_id=cve_id)
        except (ValueError, TypeError, KeyError) as exc:
            reasons.append("reconstruction_failed")
            errors.append(f"{source.path}: {exc}")
        else:
            results.append(result)
            reasons.extend(result.exclusion_reasons)
    signatures = {
        (
            result.affected,
            result.cwe_ids,
            result.feature_eligible,
            tuple(sorted(result.exclusion_reasons)),
        )
        for result in results
    }
    if len(signatures) > 1:
        reasons.append("historical_source_state_conflict")
    eligible = bool(results) and not reasons and all(result.feature_eligible for result in results)
    return {
        "reconstruction_succeeded": bool(results),
        "feature_eligible": eligible,
        "reasons": list(ordered_reasons([*reasons, *scientific_reasons()])),
        "reconstruction_warnings": sorted(
            {warning for result in results for warning in result.warnings}
        ),
        "errors": errors,
        "source_copies": [str(source.path) for source in copies],
    }


def validate_panel(path: Path, population: dict[str, datetime], grid: tuple[datetime, ...]) -> int:
    """Read back in bounded memory and check every expected key and constant."""
    ids = sorted(population)
    count = 0
    with path.open(encoding="utf-8", newline="") as stream:
        reader = csv.DictReader(stream)
        if reader.fieldnames != SCORE_COLUMNS:
            raise ValueError("Historical panel schema differs from shared Score")
        for cutoff in grid:
            for cve_id in ids:
                row = next(reader, None)
                if row is None:
                    raise ValueError("Historical panel is missing rows")
                expected = {
                    "cve_id": cve_id,
                    "component": "c_graph",
                    "decision_time": cutoff.isoformat(),
                    "horizon_days": "30",
                    "score": "",
                    "score_kind": "ranking_score",
                    "status": "abstained",
                    "model_version": MODEL_VERSION,
                    "trained_through": "",
                    "snapshot_date": cutoff.date().isoformat(),
                }
                if any(row.get(key) != value for key, value in expected.items()):
                    raise ValueError(f"Invalid historical row or composite key at row {count + 1}")
                if not row.get("reason") or None in row:
                    raise ValueError("Historical row requires one specific reason and exact schema")
                if population[cve_id] > cutoff and row["reason"] != REASON_ORDER[0]:
                    raise ValueError("Future-publication row has the wrong reason")
                count += 1
        if next(reader, None) is not None:
            raise ValueError("Historical panel has extra rows")
    return count


def export_historical_panel(
    *,
    manifest: Path,
    history_dirs: list[Path],
    output_dir: Path,
    start: date = START,
    end: date = END,
    exclude_date: date = EXCLUDED,
    cutoff_time: str = "00:00:00Z",
    horizon_days: int = 30,
    mode: str = "abstention-only",
) -> dict[str, Any]:
    """Write a new directory containing a streamed panel and evidence metadata.

    No option enables numerical scores. Existing destinations are never overwritten.
    """
    if mode != "abstention-only" or type(horizon_days) is not int or horizon_days != 30:
        raise ValueError("This release requires mode=abstention-only and horizon_days=30")
    grid = decision_grid(start, end, exclude_date, cutoff_time)
    manifest = Path(manifest).resolve()
    output_dir = Path(output_dir).resolve()
    if output_dir.exists():
        raise FileExistsError(f"Refusing existing output directory: {output_dir}")
    for directory in history_dirs:
        source_dir = Path(directory).resolve()
        if output_dir == source_dir or source_dir in output_dir.parents:
            raise ValueError("Output directory must be outside history source directories")
    manifest_hash = sha256(manifest)
    population = load_research_manifest(manifest)
    sources, source_metadata = discover_histories(history_dirs)
    source_metadata["outside_manifest_cves"] = sorted(set(sources) - set(population))
    expected = len(population) * len(grid)
    metadata: dict[str, Any] = {
        "schema_version": "1.0.0",
        "model_version": MODEL_VERSION,
        "component": "c_graph",
        "mode": mode,
        "score_kind": "ranking_score",
        "score_semantics": "Structural ranking interface; no numerical scores released.",
        "intentional_missingness": (
            "No numerical historical Component C score in this release should be interpreted "
            "as missing accidentally. Scores are intentionally absent because the available "
            "evidence does not support certified point-in-time graph scoring."
        ),
        "requested_start": start.isoformat(),
        "requested_end": end.isoformat(),
        "excluded_dates": [exclude_date.isoformat()],
        "decision_times": [cutoff.isoformat() for cutoff in grid],
        "decision_date_count": len(grid),
        "cutoff_convention": "00:00:00 UTC; publication and event timestamps <= cutoff",
        "horizon_days": horizon_days,
        "horizon_interpretation": (
            "Shared downstream evaluation metadata; not a trained 30-day exploitation target."
        ),
        "manifest": {
            "path": str(manifest),
            "row_count": len(population),
            "sha256": manifest_hash,
            "publication_min": min(population.values()).isoformat(),
            "publication_max": max(population.values()).isoformat(),
        },
        "expected_panel_row_count": expected,
        "sources": source_metadata,
        "primary_reason_precedence": list(REASON_ORDER),
        "scientifically_supported_dates": [],
        "partially_supported_dates": [],
        "unsupported_dates": [],
        "support_definitions": {
            "SUPPORTED": "Certified temporal evidence and sufficient agreed graph context.",
            "PARTIALLY_SUPPORTED": "Some strict replay eligibility; scientific gates unverified.",
            "UNSUPPORTED": "No feature-eligible CVEs under strict combined replay.",
        },
        "history_complete": False,
        "public_availability_verified": False,
        "graph_context_sufficient": False,
        "public_availability_limitation": (
            "Recorded event times do not prove historical public access."
        ),
        "graph_context_limitation": (
            "Available local histories do not establish representative context."
        ),
        "graph_computation": "not_performed",
        "score_computation": "not_performed",
        "graph_node_count": None,
        "graph_edge_count": None,
        "pagerank_population": 0,
        "percentile_population": 0,
        "pagerank_settings": {"applied": False, "reason": "No graph or PageRank computed"},
        "trained_through_semantics": (
            "Null: structural PageRank has no supervised training dataset."
        ),
        "limitations": [
            "All scores intentionally blank; replay eligibility is not scientific certification.",
            "Timezone-naive NVD history timestamps are assumed UTC by the retained parser.",
            "Initial states, historical completeness and public availability remain unverified.",
            "Mutable Affected references are not followed or repaired with later records.",
            "Master publication metadata is not independent evidence of historical public access.",
        ],
        "source_code_sha256": {
            name: sha256(Path(__file__).with_name(name))
            for name in ("historical_panel.py", "historical.py", "multi_historical_pipeline.py")
        },
        "output_columns": SCORE_COLUMNS,
        "per_cutoff": [],
    }
    ids = sorted(population)
    output_dir.mkdir(parents=True, exist_ok=False)
    csv_path = output_dir / "c_graph_historical_scores.csv"
    temporary = output_dir / ".c_graph_historical_scores.csv.tmp"
    sidecar = output_dir / "c_graph_historical_scores.csv.metadata.json"
    total_primary: Counter[str] = Counter()
    count = 0
    try:
        with temporary.open("x", encoding="utf-8", newline="") as stream:
            writer = csv.writer(stream)
            writer.writerow(SCORE_COLUMNS)
            for cutoff in grid:
                decision_time = cutoff.isoformat()
                snapshot_date = cutoff.date().isoformat()
                missing_reasons = ("historical_relationship_history_missing", *scientific_reasons())
                diagnostics = {
                    cve_id: assess_history(copies, cutoff, cve_id)
                    for cve_id, copies in sorted(sources.items())
                    if cve_id in population and population[cve_id] <= cutoff
                }
                primary: Counter[str] = Counter()
                all_reasons: Counter[str] = Counter()
                published = 0
                for cve_id in ids:
                    if population[cve_id] > cutoff:
                        reasons = (REASON_ORDER[0],)
                    else:
                        published += 1
                        reasons = (
                            diagnostics[cve_id]["reasons"]
                            if cve_id in diagnostics
                            else missing_reasons
                        )
                    reason = reasons[0]
                    primary[reason] += 1
                    all_reasons.update(reasons)
                    writer.writerow(
                        (
                            cve_id,
                            "c_graph",
                            decision_time,
                            horizon_days,
                            "",
                            "ranking_score",
                            "abstained",
                            reason,
                            MODEL_VERSION,
                            "",
                            snapshot_date,
                        )
                    )
                    count += 1
                eligible = sum(item["feature_eligible"] for item in diagnostics.values())
                classification = "PARTIALLY_SUPPORTED" if eligible else "UNSUPPORTED"
                date_key = "partially_supported_dates" if eligible else "unsupported_dates"
                metadata[date_key].append(cutoff.isoformat())
                total_primary.update(primary)
                metadata["per_cutoff"].append(
                    {
                        "decision_time": cutoff.isoformat(),
                        "published_cve_count": published,
                        "not_yet_published_cve_count": len(population) - published,
                        "histories_present_published": len(diagnostics),
                        "histories_missing_published": published - len(diagnostics),
                        "reconstruction_succeeded_count": sum(
                            item["reconstruction_succeeded"] for item in diagnostics.values()
                        ),
                        "feature_eligible_count": eligible,
                        "classification": classification,
                        "scientifically_supported": False,
                        "abstained_count": len(population),
                        "primary_reason_counts": dict(sorted(primary.items())),
                        "complete_reason_counts": dict(sorted(all_reasons.items())),
                        "history_diagnostics_by_cve": diagnostics,
                        "graph_node_count": None,
                        "graph_edge_count": None,
                        "pagerank_population": 0,
                        "percentile_population": 0,
                    }
                )
        actual = validate_panel(temporary, population, grid)
        if count != expected or actual != expected:
            raise ValueError("Historical panel row count mismatch")
        if sha256(manifest) != manifest_hash or any(
            sha256(source.path) != source.digest for copies in sources.values() for source in copies
        ):
            raise ValueError("Source inputs changed during historical export")
        metadata.update(
            {
                "actual_panel_row_count": actual,
                "unique_composite_keys_validated": True,
                "validation_method": (
                    "Streaming readback matches every sorted master CVE at every cutoff."
                ),
                "available_count": 0,
                "abstained_count": actual,
                "abstention_counts_by_reason": dict(sorted(total_primary.items())),
                "output_file": str(csv_path),
                "output_sha256": sha256(temporary),
                "source_integrity_verified_after_export": True,
            }
        )
        sidecar.write_text(json.dumps(metadata, indent=2, sort_keys=True) + "\n", encoding="utf-8")
        temporary.rename(csv_path)
    except BaseException:
        temporary.unlink(missing_ok=True)
        sidecar.unlink(missing_ok=True)
        output_dir.rmdir()
        raise
    return metadata
