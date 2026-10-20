"""Prepare and collect an incremental, stratified Component C history pilot.

The selection is drawn from the complete research manifest. Existing valid
history responses are copied into this isolated output instead of requested
again. All HTTP attempts, including retries, consume durable SQLite reservations.
"""

from __future__ import annotations

import argparse
import csv
import hashlib
import json
import os
import random
import shutil
import sqlite3
import sys
import time
from collections import Counter, defaultdict
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

PROJECT_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PROJECT_ROOT / "scripts"))

import download_nvd_history as downloader  # noqa: E402

from vesper.components.c_graph.multi_historical_pipeline import load_research_manifest  # noqa: E402

DEFAULT_OUTPUT = PROJECT_ROOT / "outputs/c_graph_history_expansion_pilot_2026-10-16"
DEFAULT_MANIFEST = PROJECT_ROOT / "data/processed/c_graph/research_population.csv"
DEFAULT_HISTORY_DIRS = (
    PROJECT_ROOT / "data/raw/nvd/history",
    PROJECT_ROOT / "outputs/c_graph_probability_pilot_2026-10-16/histories",
)
SEED = 20261016
SAMPLE_PER_STRATUM = 5
MAX_REQUESTS = 260
STRATA = [str(year) for year in range(2016, 2026)] + [
    "2026_pre_2026-06-17",
    "2026_2026-06-17_to_2026-08-25",
    "2026_from_2026-08-26",
]


def _stratum(published: datetime) -> str:
    if published.year < 2026:
        return str(published.year)
    if published < datetime(2026, 6, 17, tzinfo=UTC):
        return STRATA[10]
    if published < datetime(2026, 8, 26, tzinfo=UTC):
        return STRATA[11]
    return STRATA[12]


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as source:
        for block in iter(lambda: source.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def _write_request_sidecar(
    output_dir: Path,
    cve_id: str,
    disposition: str,
    history: dict[str, Any] | None = None,
) -> None:
    """Persist per-CVE retrieval provenance apart from NVD response JSON."""
    request_ledger = output_dir / "request_ledger.jsonl"
    attempts = downloader.request_attempts_from_ledger(request_ledger, cve_id)
    events = (history or {}).get("cveChanges", [])
    timestamps = [
        item.get("change", {}).get("created")
        for item in events
        if isinstance(item, dict) and isinstance(item.get("change"), dict)
    ]
    provenance_complete = (
        disposition == "valid_response"
        and history is not None
        and downloader.has_complete_raw_provenance(history, cve_id, attempts)
    )
    sidecar = {
        "cve_id": cve_id,
        "retrieval_disposition": (
            "incomplete_provenance"
            if disposition == "valid_response" and not provenance_complete
            else disposition
        ),
        "provenance_status": "complete" if provenance_complete else "incomplete",
        "source_endpoint": downloader.NVD_HISTORY_URL,
        "request_attempts": attempts,
        "page_request_count": len({item.get("start_index") for item in attempts}),
        "http_request_attempt_count": len(attempts),
        "retry_count": sum(bool(item.get("is_retry")) for item in attempts),
        "request_started_at_utc": min(
            (item.get("request_started_at_utc", "") for item in attempts), default=""
        ),
        "request_ended_at_utc": max(
            (item.get("request_ended_at_utc", "") for item in attempts), default=""
        ),
        "http_statuses": [item.get("http_status") for item in attempts],
        "event_timestamp_timezone_policy": {
            "original_strings_preserved_in_raw_response": provenance_complete,
            "naive_event_timestamp_count": sum(
                downloader.timestamp_timezone_status(value) == "naive_assumed_utc"
                for value in timestamps
            ),
            "explicit_offset_event_timestamp_count": sum(
                downloader.timestamp_timezone_status(value) == "explicit_offset"
                for value in timestamps
            ),
            "normalization": "Naive event timestamps are interpreted as UTC by project code.",
            "documentation_status": (
                "No explicit NVD timezone guarantee found for naive history-event timestamps; "
                "UTC normalization is an unverified project assumption."
            ),
        },
    }
    metadata_dir = output_dir / "request_metadata"
    metadata_dir.mkdir(parents=True, exist_ok=True)
    destination = metadata_dir / f"{cve_id}.json"
    temporary = destination.with_suffix(".json.tmp")
    temporary.write_text(json.dumps(sidecar, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    os.replace(temporary, destination)


def select_records(
    manifest_path: Path, seed: int = SEED
) -> tuple[list[dict[str, Any]], dict[str, int]]:
    """Draw five CVEs per publication stratum from the unchanged full manifest."""
    population = load_research_manifest(manifest_path)
    grouped: dict[str, list[tuple[str, datetime]]] = defaultdict(list)
    for cve_id, published in population.items():
        grouped[_stratum(published)].append((cve_id, published))

    rng = random.Random(seed)
    selected: list[dict[str, Any]] = []
    counts: dict[str, int] = {}
    for stratum in STRATA:
        members = sorted(grouped[stratum])
        counts[stratum] = len(members)
        if len(members) < SAMPLE_PER_STRATUM:
            raise ValueError(f"Stratum {stratum} has fewer than {SAMPLE_PER_STRATUM} CVEs")
        for cve_id, published in rng.sample(members, SAMPLE_PER_STRATUM):
            probability = SAMPLE_PER_STRATUM / len(members)
            selected.append(
                {
                    "cve_id": cve_id,
                    "published": published.isoformat(),
                    "stratum": stratum,
                    "stratum_population": len(members),
                    "sample_per_stratum": SAMPLE_PER_STRATUM,
                    "inclusion_probability": probability,
                    "analysis_weight": 1 / probability,
                }
            )
    return selected, counts


def prepare_pilot(
    manifest_path: Path = DEFAULT_MANIFEST,
    history_dirs: tuple[Path, ...] = DEFAULT_HISTORY_DIRS,
    output_dir: Path = DEFAULT_OUTPUT,
    seed: int = SEED,
) -> dict[str, Any]:
    """Create immutable sample artifacts before any collection is attempted."""
    if output_dir.exists():
        raise FileExistsError(f"Pilot output already exists: {output_dir}")
    sample, population_counts = select_records(manifest_path, seed)
    output_dir.mkdir(parents=True, exist_ok=False)
    histories = output_dir / "histories"
    histories.mkdir()
    dispositions: Counter[str] = Counter()
    records_to_request: list[dict[str, Any]] = []

    for row in sample:
        cve_id = row["cve_id"]
        valid_source = None
        invalid_found = False
        for source_dir in history_dirs:
            source = source_dir / f"{cve_id}.json"
            if not source.is_file():
                continue
            if downloader.load_saved_history(source) is not None:
                valid_source = source
                break
            invalid_found = True
        if valid_source is not None:
            destination = histories / valid_source.name
            shutil.copy2(valid_source, destination)
            source_sidecar = source_dir / "request_metadata" / f"{cve_id}.json"
            target_sidecar = output_dir / "request_metadata" / f"{cve_id}.json"
            if source_sidecar.is_file():
                target_sidecar.parent.mkdir(parents=True, exist_ok=True)
                shutil.copy2(source_sidecar, target_sidecar)
            else:
                _write_request_sidecar(
                    output_dir,
                    cve_id,
                    "incomplete_provenance",
                    downloader.load_saved_history(destination),
                )
            row["preexisting_history_status"] = "valid_existing_copied"
            row["copied_source"] = str(valid_source)
            row["copied_sha256"] = _sha256(destination)
            dispositions["valid_existing_copied"] += 1
        else:
            row["preexisting_history_status"] = (
                "invalid_existing_preserved" if invalid_found else "absent"
            )
            dispositions[row["preexisting_history_status"]] += 1
            records_to_request.append(row)

    sample_path = output_dir / "sample_frame.csv"
    columns = [
        "cve_id",
        "published",
        "stratum",
        "stratum_population",
        "sample_per_stratum",
        "inclusion_probability",
        "analysis_weight",
        "preexisting_history_status",
        "copied_source",
        "copied_sha256",
    ]
    with sample_path.open("x", encoding="utf-8", newline="") as stream:
        writer = csv.DictWriter(stream, fieldnames=columns)
        writer.writeheader()
        writer.writerows(
            sorted(sample, key=lambda item: (STRATA.index(item["stratum"]), item["cve_id"]))
        )

    metadata = {
        "analysis_type": "incremental_stratified_history_coverage_pilot",
        "collection_started": False,
        "seed": seed,
        "manifest_path": str(manifest_path),
        "manifest_sha256": _sha256(manifest_path),
        "manifest_cves": sum(population_counts.values()),
        "research_start_inclusive_utc": "2016-01-01T00:00:00+00:00",
        "research_end_exclusive_utc": "2026-10-15T00:00:00+00:00",
        "stratum_population_counts": population_counts,
        "stratum_sample_counts": {stratum: SAMPLE_PER_STRATUM for stratum in STRATA},
        "selection_probabilities": {
            stratum: SAMPLE_PER_STRATUM / population_counts[stratum] for stratum in STRATA
        },
        "analysis_weights": {
            stratum: population_counts[stratum] / SAMPLE_PER_STRATUM for stratum in STRATA
        },
        "sample_size": len(sample),
        "preexisting_history_dispositions": dict(dispositions),
        "new_cve_requests_planned": len(records_to_request),
        "request_budget_maximum_including_pages_and_retries": MAX_REQUESTS,
        "request_budget_ledger": "request_reservations.sqlite3",
        "history_sources_checked": [str(path) for path in history_dirs],
        "sample_frame": sample_path.name,
        "historical_event_timestamps_prove_public_availability": False,
        "independent_historical_cpe_validation": False,
        "cpe_applicability_scope": (
            "Vendor/product relationships only; not full CPE configuration semantics."
        ),
    }
    (output_dir / "selection_metadata.json").write_text(
        json.dumps(metadata, indent=2) + "\n", encoding="utf-8"
    )
    with (output_dir / "request_queue.csv").open("x", encoding="utf-8", newline="") as stream:
        writer = csv.DictWriter(stream, fieldnames=["cve_id", "stratum", "published"])
        writer.writeheader()
        writer.writerows(
            {key: row[key] for key in ("cve_id", "stratum", "published")}
            for row in records_to_request
        )
    return metadata


class DurableRequestBudget:
    """Persist every request reservation before the HTTP call that consumes it."""

    def __init__(self, ledger_path: Path, maximum: int | None = MAX_REQUESTS):
        if maximum is not None and maximum < 1:
            raise ValueError("request ceiling must be positive")
        self.ledger_path = ledger_path
        self.context = "unknown"
        self.connection = sqlite3.connect(ledger_path, timeout=30)
        self.connection.execute("PRAGMA synchronous=FULL")
        self.connection.execute(
            "CREATE TABLE IF NOT EXISTS reservations ("
            "request_id INTEGER PRIMARY KEY AUTOINCREMENT, reserved_at_utc TEXT NOT NULL, "
            "context TEXT NOT NULL)"
        )
        self.connection.execute(
            "CREATE TABLE IF NOT EXISTS config (key TEXT PRIMARY KEY, value TEXT NOT NULL)"
        )
        existing = self.connection.execute(
            "SELECT value FROM config WHERE key='maximum'"
        ).fetchone()
        if maximum is None:
            maximum = int(existing[0]) if existing is not None else MAX_REQUESTS
        self.maximum = maximum
        if existing is not None and int(existing[0]) != maximum:
            self.connection.close()
            raise ValueError("request ceiling cannot change when resuming the pilot")
        self.connection.execute(
            "INSERT OR IGNORE INTO config(key, value) VALUES('maximum', ?)", (str(maximum),)
        )
        self.connection.commit()

    @property
    def used(self) -> int:
        return int(self.connection.execute("SELECT COUNT(*) FROM reservations").fetchone()[0])

    def reserve(self) -> None:
        self.connection.execute("BEGIN IMMEDIATE")
        used = int(self.connection.execute("SELECT COUNT(*) FROM reservations").fetchone()[0])
        if used >= self.maximum:
            self.connection.rollback()
            raise downloader.RequestBudgetExceeded(
                f"Durable request ceiling reached ({self.maximum})"
            )
        self.connection.execute(
            "INSERT INTO reservations(reserved_at_utc, context) VALUES(?, ?)",
            (datetime.now(UTC).isoformat(), self.context),
        )
        self.connection.commit()

    def close(self) -> None:
        self.connection.close()


def _collect_pilot_locked(
    output_dir: Path = DEFAULT_OUTPUT,
    env_path: Path | None = None,
    request_ceiling: int | None = None,
) -> dict[str, Any]:
    """Resume the prepared collection, never replacing a saved response."""
    downloader.read_request_ledger(output_dir / "request_ledger.jsonl")
    metadata_path = output_dir / "selection_metadata.json"
    metadata = json.loads(metadata_path.read_text(encoding="utf-8"))
    budget = DurableRequestBudget(
        output_dir / "request_reservations.sqlite3", maximum=request_ceiling
    )
    metadata["request_budget_maximum_including_pages_and_retries"] = budget.maximum
    metadata["collection_started"] = True
    metadata["collection_started_at_utc"] = datetime.now(UTC).isoformat()
    metadata_path.write_text(json.dumps(metadata, indent=2) + "\n", encoding="utf-8")
    queue_path = output_dir / "request_queue.csv"
    with queue_path.open(encoding="utf-8", newline="") as stream:
        queue = list(csv.DictReader(stream))
    histories = output_dir / "histories"
    for path in histories.glob("CVE-*.json"):
        if downloader.load_saved_history(path) is None:
            raise ValueError(f"Existing pilot history is invalid and will be preserved: {path}")
        sidecar_path = output_dir / "request_metadata" / f"{path.stem}.json"
        if not sidecar_path.exists():
            downloader.reconcile_saved_history(
                path, sidecar_path, output_dir / "request_ledger.jsonl", path.stem
            )

    if env_path is not None:
        downloader.load_env_file(env_path)
    api_key = __import__("os").environ.get("NVD_API_KEY")
    limiter = downloader._shared_limiter(api_key)
    outcomes_path = output_dir / "retrieval_outcomes.jsonl"
    raw_response_dir = output_dir / "raw_responses"
    request_ledger_path = output_dir / "request_ledger.jsonl"
    started = time.monotonic()
    try:
        for row in queue:
            cve_id = row["cve_id"]
            destination = histories / f"{cve_id}.json"
            if downloader.load_saved_history(destination) is not None:
                sidecar_path = output_dir / "request_metadata" / f"{cve_id}.json"
                if not sidecar_path.exists():
                    downloader.reconcile_saved_history(
                        destination, sidecar_path, request_ledger_path, cve_id
                    )
                continue
            if destination.exists():
                raise FileExistsError(f"Invalid existing pilot file is preserved: {destination}")
            metrics: dict[str, int] = {}
            budget.context = cve_id
            try:
                history = downloader.fetch_history(
                    cve_id,
                    api_key,
                    metrics=metrics,
                    limiter=limiter,
                    request_budget=budget,
                    raw_response_dir=raw_response_dir,
                    request_ledger_path=request_ledger_path,
                )
                downloader.save_history(destination, history)
                _write_request_sidecar(output_dir, cve_id, "valid_response", history)
                complete = _pilot_sidecar_is_complete(output_dir, cve_id)
                disposition = (
                    ("valid_empty" if not history["cveChanges"] else "valid_with_events")
                    if complete
                    else "incomplete_provenance"
                )
                item = {
                    "cve_id": cve_id,
                    "disposition": disposition,
                    "event_count": len(history["cveChanges"]),
                    "page_requests": metrics.get("page_requests", 0),
                    "retries": metrics.get("retries", 0),
                    "sha256": _sha256(destination),
                    "source_url": f"{downloader.NVD_HISTORY_URL}?cveId={cve_id}",
                    "retrieved_at_utc": datetime.now(UTC).isoformat(),
                }
                if not complete:
                    item["error"] = "saved history has incomplete or unverifiable provenance"
            except downloader.RequestBudgetExceeded as error:
                _write_request_sidecar(output_dir, cve_id, "request_budget_exhausted")
                item = {"cve_id": cve_id, "disposition": "budget_exhausted", "error": str(error)}
                _append_jsonl(outcomes_path, item)
                break
            except (RuntimeError, OSError, ValueError) as error:
                _write_request_sidecar(output_dir, cve_id, "failed_response")
                item = {
                    "cve_id": cve_id,
                    "disposition": "failed",
                    "error": f"{type(error).__name__}: {error}",
                    "page_requests": metrics.get("page_requests", 0),
                    "retries": metrics.get("retries", 0),
                }
            _append_jsonl(outcomes_path, item)
    finally:
        used = budget.used
        budget.close()

    elapsed = round(time.monotonic() - started, 2)
    outcomes = (
        [json.loads(line) for line in outcomes_path.read_text(encoding="utf-8").splitlines()]
        if outcomes_path.exists()
        else []
    )
    summary = {
        "analysis_type": metadata["analysis_type"],
        "sample_size": metadata["sample_size"],
        "unique_history_files_present": sum(
            downloader.load_saved_history(path) is not None
            and _pilot_sidecar_is_complete(output_dir, path.stem)
            for path in histories.glob("CVE-*.json")
        ),
        "valid_empty_responses": sum(
            item.get("disposition") == "valid_empty"
            and _pilot_sidecar_is_complete(output_dir, item["cve_id"])
            for item in outcomes
        ),
        "valid_responses_with_events": sum(
            item.get("disposition") == "valid_with_events"
            and _pilot_sidecar_is_complete(output_dir, item["cve_id"])
            for item in outcomes
        ),
        "failed_ids": sum(item.get("disposition") == "failed" for item in outcomes),
        "incomplete_provenance_ids": sum(
            not _pilot_sidecar_is_complete(output_dir, row["cve_id"])
            for row in queue
            if downloader.load_saved_history(histories / f"{row['cve_id']}.json") is not None
        ),
        "reserved_http_requests_including_retries": used,
        "hard_request_ceiling": budget.maximum,
        "elapsed_seconds_this_invocation": elapsed,
        "event_timestamps_prove_public_availability": False,
        "production_or_population_wide_output": False,
    }
    (output_dir / "retrieval_summary.json").write_text(
        json.dumps(summary, indent=2) + "\n", encoding="utf-8"
    )
    return summary


def collect_pilot(
    output_dir: Path = DEFAULT_OUTPUT,
    env_path: Path | None = None,
    request_ceiling: int | None = None,
) -> dict[str, Any]:
    """Collect under the same cross-process lock used by the standard runner."""
    with downloader.RunDirectoryLock(output_dir):
        return _collect_pilot_locked(output_dir, env_path, request_ceiling)


def _pilot_sidecar_is_complete(output_dir: Path, cve_id: str) -> bool:
    sidecar = output_dir / "request_metadata" / f"{cve_id}.json"
    try:
        data = json.loads(sidecar.read_text(encoding="utf-8"))
        history = downloader.load_saved_history(output_dir / "histories" / f"{cve_id}.json")
    except (OSError, json.JSONDecodeError):
        return False
    if not isinstance(data, dict):
        return False
    return (
        data.get("retrieval_disposition") == "valid_response"
        and data.get("provenance_status") in {None, "complete", "reconciled"}
        and history is not None
        and downloader.has_complete_raw_provenance(
            history, cve_id, data.get("request_attempts", [])
        )
    )


def _append_jsonl(path: Path, value: dict[str, Any]) -> None:
    with path.open("a", encoding="utf-8", newline="\n") as stream:
        stream.write(json.dumps(value, ensure_ascii=False) + "\n")
        stream.flush()


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output-dir", type=Path, default=DEFAULT_OUTPUT)
    parser.add_argument("--manifest", type=Path, default=DEFAULT_MANIFEST)
    parser.add_argument("--prepare", action="store_true", help="Create selection artifacts only")
    parser.add_argument("--collect", action="store_true", help="Collect/resume the prepared sample")
    parser.add_argument(
        "--request-ceiling",
        type=int,
        default=None,
        help=(
            f"Maximum HTTP attempts including retries and pages (default: {MAX_REQUESTS}; "
            "persisted on first collection)"
        ),
    )
    parser.add_argument("--env-file", type=Path, default=PROJECT_ROOT / ".env")
    args = parser.parse_args()
    if args.prepare == args.collect:
        parser.error("choose exactly one of --prepare or --collect")
    if args.prepare:
        print(json.dumps(prepare_pilot(args.manifest, output_dir=args.output_dir), indent=2))
    else:
        print(
            json.dumps(
                collect_pilot(args.output_dir, args.env_file, args.request_ceiling), indent=2
            )
        )


if __name__ == "__main__":
    main()
