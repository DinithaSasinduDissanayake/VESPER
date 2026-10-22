"""Historical Component B score snapshots, for training and evaluating Component D."""

import argparse
import hashlib
import json
import os
import shutil
import subprocess
import time
from concurrent.futures import ProcessPoolExecutor
from datetime import date, timedelta
from pathlib import Path

from vesper.components.b_survival.score_export import (
    HORIZON_DAYS,
    SCORE_COLUMNS,
    build_timing_scores,
    fit_scoring_model,
    percentile_scores,
    scores_to_frame,
    start_of_day,
)
from vesper.components.b_survival.split_data import load_survival_table
from vesper.components.b_survival.study_design import PROCESSED_SUBFOLDER, SNAPSHOT_DATE
from vesper.components.b_survival.survival_table import OUTPUT_FILE_NAME
from vesper.config import load_settings
from vesper.contracts.score import ScoreStatus

HISTORY_SUBFOLDER = "history"
FILE_PREFIX = "b_exploit_timing_history"
RAW_FILE_PREFIX = "b_exploit_timing_probability_history"
METADATA_FILE = "history.metadata.json"

# One decision time takes about 20 s and 0.8 GB of memory (2026-09-01, 196,000
# train rows), so a few workers at a time keep a laptop responsive
MAX_WORKERS = 3


def monthly_grid(first, last):
    """The 1st of every month from `first` to `last` (both included)."""
    days, day = [], date(first.year, first.month, 1)
    while day <= last:
        days.append(day)
        day = date(day.year + day.month // 12, day.month % 12 + 1, 1)
    return tuple(days)


# The decision grid: 00:00 UTC on the 1st of each month, 2024-07-01 to 2026-09-01 (27 dates)
DECISION_DATES = monthly_grid(date(2024, 7, 1), date(2026, 9, 1))

LIMITS = [
    "Retrospective replay, not a point-in-time record: NVD fields (CVSS, CWE) come from the "
    "current NVD snapshot, so CVSS scores added or changed after a decision time leak in.",
    "KEV dates and Exploit-DB publication dates are used as dated; deleted or backdated "
    "entries cannot be detected.",
    "The Cox baseline is a step function: where no train CVE was listed in the 30 days after "
    "a CVE's age, the raw estimate is exactly 0 (zero_raw_estimates per decision time).",
    "CVEs without a CVSS 3.x score at the current snapshot abstain at every decision time.",
    "Labels are not included: Component D adds kev_within_horizon itself.",
]


def check_grid(decision_dates, snapshot_date=SNAPSHOT_DATE, horizon_days=HORIZON_DAYS):
    """Refuse a grid whose label window would reach the snapshot, or with repeats."""
    if not decision_dates:
        raise ValueError("The decision grid is empty")
    if len(set(decision_dates)) != len(decision_dates):
        raise ValueError("The decision grid has repeated dates")
    latest = snapshot_date - timedelta(days=horizon_days)
    late = [day.isoformat() for day in decision_dates if day > latest]
    if late:
        raise ValueError(
            f"Decision dates after {latest} (snapshot - {horizon_days} days) have an "
            f"unfinished label window: {late}"
        )
    return tuple(sorted(decision_dates))


def file_names(day):
    return f"{FILE_PREFIX}_{day.isoformat()}.csv", f"{RAW_FILE_PREFIX}_{day.isoformat()}.csv"


def sha256(path):
    digest = hashlib.sha256()
    with Path(path).open("rb") as source:
        for block in iter(lambda: source.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def code_version():
    """The git commit of the code, with "-dirty" if src/ has uncommitted or new files."""
    try:
        commit = subprocess.run(
            ["git", "rev-parse", "HEAD"], capture_output=True, text=True, check=True
        ).stdout.strip()
        dirty = subprocess.run(
            ["git", "status", "--porcelain", "--", "src"],
            capture_output=True,
            text=True,
            check=True,
        ).stdout.strip()
    except (OSError, subprocess.CalledProcessError):
        return "unknown"
    return commit + ("-dirty" if dirty else "")


def score_one_time(table, day, snapshot_date=SNAPSHOT_DATE):
    """Fit and score at one decision time. Returns (percentile frame, raw frame, info)."""
    decision_time = start_of_day(day)
    model = fit_scoring_model(table, decision_time)
    raw = build_timing_scores(
        table,
        model,
        decision_time=decision_time,
        trained_through=decision_time,
        snapshot_date=snapshot_date,
    )
    ranked = percentile_scores(raw, decision_time)
    raw_frame = scores_to_frame(raw).sort_values("cve_id", ignore_index=True)
    ranked_frame = scores_to_frame(ranked).sort_values("cve_id", ignore_index=True)

    available = raw_frame["status"] == ScoreStatus.AVAILABLE.value
    info = {
        "decision_time": decision_time.isoformat(),
        "model_version": ranked[0].model_version if ranked else None,
        "source_model_version": raw[0].model_version if raw else None,
        "train_rows": model.train_rows,
        "train_events": model.train_events,
        "train_max_follow_up_days": model.train_max_follow_up,
        "rows": len(raw_frame),
        "status_counts": {
            state.value: int((raw_frame["status"] == state.value).sum()) for state in ScoreStatus
        },
        "zero_raw_estimates": int((raw_frame.loc[available, "score"] == 0).sum()),
        "min_raw_estimate": float(raw_frame.loc[available, "score"].min())
        if available.any()
        else None,
    }
    return ranked_frame, raw_frame, info


def run_one_time(table_path, day, folder):
    """Worker: score one decision time and write its two files. Returns its metadata."""
    started = time.perf_counter()
    table = load_survival_table(table_path)
    ranked, raw, info = score_one_time(table, day)
    name, raw_name = file_names(day)
    ranked.to_csv(folder / name, index=False)
    raw.to_csv(folder / raw_name, index=False)
    info["files"] = {
        "percentile": {"name": name, "sha256": sha256(folder / name)},
        "raw": {"name": raw_name, "sha256": sha256(folder / raw_name)},
    }
    info["seconds"] = round(time.perf_counter() - started, 1)
    return info


def next_run_folder(history_dir):
    """history/run-NNN with the next free number. Existing runs are never reused."""
    numbers = [
        int(path.name.removeprefix("run-"))
        for path in history_dir.glob("run-*")
        if path.name.removeprefix("run-").isdigit()
    ]
    return history_dir / f"run-{max(numbers, default=0) + 1:03d}"


def print_summary(infos):
    print()
    header = f"{'decision':<12}{'train rows':>11}{'events':>8}{'rows':>9}{'available':>11}"
    print(header + f"{'abstained':>11}{'in KEV':>8}{'not elig.':>11}{'zeros':>8}{'s':>7}")
    for info in infos:
        counts = info["status_counts"]
        print(
            f"{info['decision_time'][:10]:<12}{info['train_rows']:>11}{info['train_events']:>8}"
            f"{info['rows']:>9}{counts['available']:>11}{counts['abstained']:>11}"
            f"{counts['already_exploited']:>8}{counts['not_eligible']:>11}"
            f"{info['zero_raw_estimates']:>8}{info['seconds']:>7}"
        )


def check_one_time(table_path, day):
    """Worker: fit and score one decision time, write nothing. Returns its counts."""
    _, _, info = score_one_time(load_survival_table(table_path), day)
    return info


def check_zeros(settings=None, decision_dates=DECISION_DATES, workers=None):
    """Count raw estimates of exactly 0 per decision time. Writes no files."""
    settings = settings or load_settings()
    decision_dates = check_grid(decision_dates)
    table_path = settings.data_processed / PROCESSED_SUBFOLDER / OUTPUT_FILE_NAME
    workers = workers or min(len(decision_dates), os.cpu_count() or 1, MAX_WORKERS)
    jobs = [(table_path, day) for day in decision_dates]
    if workers == 1:
        infos = [check_one_time(*job) for job in jobs]
    else:
        with ProcessPoolExecutor(max_workers=workers) as pool:
            infos = list(pool.map(check_one_time, *zip(*jobs, strict=True)))
    print()
    print(f"{'decision':<12}{'available':>11}{'raw = 0':>9}{'min raw':>12}  model_version")
    for info in infos:
        print(
            f"{info['decision_time'][:10]:<12}{info['status_counts']['available']:>11}"
            f"{info['zero_raw_estimates']:>9}{info['min_raw_estimate']:>12.2e}  "
            f"{info['model_version']}"
        )
    return infos


def main(settings=None, decision_dates=DECISION_DATES, workers=None):
    """Score every decision time and write a new history run folder. Returns its path."""
    started = time.perf_counter()
    # Folders come from vesper.config
    settings = settings or load_settings()
    decision_dates = check_grid(decision_dates)
    table_path = settings.data_processed / PROCESSED_SUBFOLDER / OUTPUT_FILE_NAME
    history_dir = settings.outputs / PROCESSED_SUBFOLDER / HISTORY_SUBFOLDER
    history_dir.mkdir(parents=True, exist_ok=True)
    run_folder = next_run_folder(history_dir)
    # Work in a temporary folder; it becomes run-NNN only when every date succeeded
    work_folder = history_dir / f".{run_folder.name}.partial-{os.getpid()}"
    work_folder.mkdir()

    try:
        workers = workers or min(len(decision_dates), os.cpu_count() or 1, MAX_WORKERS)
        jobs = [(table_path, day, work_folder) for day in decision_dates]
        if workers == 1:
            infos = [run_one_time(*job) for job in jobs]
        else:
            with ProcessPoolExecutor(max_workers=workers) as pool:
                infos = list(pool.map(run_one_time, *zip(*jobs, strict=True)))

        metadata = {
            "component": "b_survival",
            "description": (
                "Historical B scores: one file per decision time, replayed with only the "
                "data dated before that time (see limits)."
            ),
            "decision_grid": [day.isoformat() for day in decision_dates],
            "horizon_days": HORIZON_DAYS,
            "snapshot_date": SNAPSHOT_DATE.isoformat(),
            "score_kind": "ranking_score",
            "percentile_definition": (
                "rank / N among the CVEs available at the same decision time, "
                "average ranks for ties, in (0, 1]"
            ),
            "raw_definition": "1 - S(age + 30 | x) / S(age | x), Cox model trained through T",
            "output_columns": SCORE_COLUMNS,
            "labels": "Not included; Component D adds kev_within_horizon.",
            "limits": LIMITS,
            "source_files": {OUTPUT_FILE_NAME: {"sha256": sha256(table_path)}},
            "code_version": code_version(),
            "decision_times": infos,
        }
        (work_folder / METADATA_FILE).write_text(json.dumps(metadata, indent=2), encoding="utf-8")
        if run_folder.exists():
            raise FileExistsError(f"{run_folder} appeared during the run; not overwritten")
        work_folder.rename(run_folder)
    except BaseException:
        shutil.rmtree(work_folder, ignore_errors=True)
        raise

    print_summary(infos)
    print()
    print(f"Saved {2 * len(infos)} files and {METADATA_FILE} to: {run_folder}")
    print(f"Total run time: {time.perf_counter() - started:.0f} s with {workers} worker(s)")
    return run_folder


def parse_dates(text):
    return tuple(date.fromisoformat(part.strip()) for part in text.split(",") if part.strip())


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0].strip())
    parser.add_argument(
        "--decision-times",
        type=parse_dates,
        default=DECISION_DATES,
        help="comma-separated dates (00:00 UTC), for example 2025-01-01,2025-07-01",
    )
    parser.add_argument("--workers", type=int, default=None)
    parser.add_argument(
        "--check-zeros",
        action="store_true",
        help="only count raw estimates of exactly 0 per decision time; write nothing",
    )
    arguments = parser.parse_args()
    run = check_zeros if arguments.check_zeros else main
    run(decision_dates=arguments.decision_times, workers=arguments.workers)
