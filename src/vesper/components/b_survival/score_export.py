"""
Export Component B exploit-timing scores for Component D, as shared Score records.

One row per CVE in the survival table published before the decision time. The
status of each CVE is decided in this order:

  already_exploited  listed in KEV before the decision day; empty score
  not_eligible       outside the modelling cohort (post_kev: published before
                     KEV_START_DATE); empty score
  abstained          a model input is missing (no CVSS 3.x score), or the
                     horizon reaches past the longest train follow-up, so the
                     estimate would be extrapolated; empty score, with a reason
  available          scored (see the two files below)

Two files are written, with the same CVEs, statuses and reasons:

  b_exploit_timing_probability.csv   the raw estimate: the Cox model's "listed
      in KEV within the next HORIZON_DAYS days", given that the CVE is still
      unlisted at the decision time:
          raw = 1 - S(age + HORIZON_DAYS | x) / S(age | x)
      where age = days from publication to the decision day. A CVE published
      today gets 1 - S(HORIZON_DAYS | x). It has the form of a probability, but
      its calibration has not been checked on held-out data, so its score_kind
      is still ranking_score (CONTRIBUTING.md).

  b_exploit_timing_scores.csv        the file Component D reads: the percentile
      rank of the raw estimate among the AVAILABLE CVEs only, rank / N with tied
      CVEs sharing the average rank, so it is in (0, 1]. The raw values are
      about 1e-4, so on their own they would pull D's mean of 0-1 scores down;
      the percentile puts B on the same scale as Component C's percentile.

The model is fitted with the same rules as the evaluation: post_kev CVEs
published before `trained_through`, re-censored at that day (split_data), CVEs
without CVSS left out. By default trained_through = decision time = the start
(00:00 UTC) of SNAPSHOT_DATE, the deployment setting. An earlier
trained_through gives the model of an evaluation cut-off. trained_through is
never after the decision time (the Score contract checks this).

Output:  outputs/b_survival/b_exploit_timing_probability.csv (+ .metadata.json)
         outputs/b_survival/b_exploit_timing_scores.csv      (+ .metadata.json)

Run from anywhere (run survival_table first):
    uv run python -m vesper.components.b_survival.score_export
"""

import dataclasses
import json
import os
import tempfile
import warnings
from datetime import UTC, datetime, time
from pathlib import Path

import numpy as np
import pandas as pd

from vesper.components.b_survival.cox_model import fit_cox
from vesper.components.b_survival.features import NUMERIC_COLUMN, drop_missing_cvss
from vesper.components.b_survival.split_data import load_survival_table, split_at_cutoff
from vesper.components.b_survival.study_design import (
    KEV_START_DATE,
    PROCESSED_SUBFOLDER,
    SNAPSHOT_DATE,
)
from vesper.components.b_survival.survival_table import OUTPUT_FILE_NAME, filter_cohort
from vesper.config import load_settings
from vesper.contracts.score import Component, Score, ScoreKind, ScoreStatus

# The look-ahead window, in days. Component D's fusion uses 30.
HORIZON_DAYS = 30
COHORT = "post_kev"
MODEL_VERSION_SUFFIX = "0.1"
RAW_OUTPUT_FILE = "b_exploit_timing_probability.csv"
OUTPUT_FILE = "b_exploit_timing_scores.csv"
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

REASON_ALREADY_EXPLOITED = "Listed in CISA KEV before the decision time."
REASON_NOT_ELIGIBLE = (
    f"Published before the KEV catalogue started ({KEV_START_DATE.isoformat()}); "
    "outside the post_kev modelling cohort."
)
REASON_NO_CVSS = "No CVSS 3.x score: a model input is missing."
REASON_EXTRAPOLATED = "The horizon reaches past the longest train follow-up; not extrapolated."


def start_of_day(day):
    """00:00 UTC of a date, as a timezone-aware datetime."""
    return datetime.combine(day, time(0, 0), tzinfo=UTC)


def model_version(trained_through, kind="cox"):
    return f"b_survival-{kind}-{trained_through.date().isoformat()}-{MODEL_VERSION_SUFFIX}"


def fit_scoring_model(table, trained_through, cohort=COHORT):
    """Fit the Cox model on the cohort's CVEs published before trained_through."""
    train, _, _ = split_at_cutoff(filter_cohort(table, cohort), trained_through.date())
    train, _ = drop_missing_cvss(train)
    return fit_cox(train)


def build_timing_scores(
    table,
    model,
    *,
    decision_time,
    trained_through,
    snapshot_date=SNAPSHOT_DATE,
    horizon_days=HORIZON_DAYS,
    cohort=COHORT,
):
    """Raw estimates for every CVE of the survival table published before decision_time.

    Returns one Score per CVE, in the order of the table.
    """
    if decision_time.tzinfo is None or trained_through.tzinfo is None:
        raise ValueError("decision_time and trained_through must include a time zone")
    if trained_through > decision_time:
        raise ValueError("trained_through must not be after decision_time")
    if isinstance(horizon_days, bool) or not isinstance(horizon_days, int) or horizon_days <= 0:
        raise ValueError("horizon_days must be a positive integer")
    if table["cve_id"].duplicated().any():
        raise ValueError("The survival table has duplicate CVE IDs")

    decision = pd.Timestamp(decision_time).tz_convert("UTC")
    decision_day = decision.normalize()
    rows = table[table["published_at"] < decision].reset_index(drop=True)
    published_day = rows["published_at"].dt.normalize()
    age_days = (decision_day - published_day).dt.days.to_numpy()

    # The KEV day is only rebuilt here to decide the status, never used as an input
    kev_day = published_day + pd.to_timedelta(rows["duration_days"], unit="D")
    listed_before = ((rows["event"] == 1) & (kev_day < decision_day)).to_numpy()
    in_cohort = rows["cve_id"].isin(set(filter_cohort(rows, cohort)["cve_id"])).to_numpy()
    has_cvss = rows[NUMERIC_COLUMN].notna().to_numpy()
    too_far = age_days + horizon_days > model.train_max_follow_up

    status = np.select(
        [listed_before, ~in_cohort, ~has_cvss, too_far],
        [
            ScoreStatus.ALREADY_EXPLOITED,
            ScoreStatus.NOT_ELIGIBLE,
            ScoreStatus.ABSTAINED,
            ScoreStatus.ABSTAINED,
        ],
        default=ScoreStatus.AVAILABLE,
    )
    reason = np.select(
        [listed_before, ~in_cohort, ~has_cvss, too_far],
        [REASON_ALREADY_EXPLOITED, REASON_NOT_ELIGIBLE, REASON_NO_CVSS, REASON_EXTRAPOLATED],
        default="",
    )

    score = np.full(len(rows), np.nan)
    available = status == ScoreStatus.AVAILABLE
    if available.any():
        score[available] = model.listed_within_next(
            rows[available], age_days[available], horizon_days
        )

    version = model_version(trained_through)
    return [
        Score(
            cve_id=cve_id,
            component=Component.B_SURVIVAL,
            decision_time=decision_time,
            horizon_days=horizon_days,
            score=float(value) if state == ScoreStatus.AVAILABLE else None,
            score_kind=ScoreKind.RANKING_SCORE,
            status=ScoreStatus(state),
            reason=text or None,
            model_version=version,
            trained_through=trained_through,
            snapshot_date=snapshot_date,
        )
        for cve_id, state, text, value in zip(rows["cve_id"], status, reason, score, strict=True)
    ]


def percentile_ranks(values):
    """rank / N with average ranks for ties: in (0, 1], the highest value gets 1."""
    values = pd.Series(values, dtype=float)
    if not np.isfinite(values).all():
        raise ValueError("Percentiles need finite values")
    return (values.rank(method="average") / len(values)).to_numpy()


def percentile_scores(records, trained_through):
    """The same records with each available score replaced by its percentile rank
    among the available records. Statuses, reasons and times are unchanged."""
    available = [i for i, record in enumerate(records) if record.status is ScoreStatus.AVAILABLE]
    ranks = percentile_ranks([records[i].score for i in available])
    new_score = dict(zip(available, ranks, strict=True))
    version = model_version(trained_through, kind="cox-percentile")
    return [
        dataclasses.replace(
            record,
            score=float(new_score[i]) if i in new_score else None,
            model_version=version,
        )
        for i, record in enumerate(records)
    ]


def scores_to_frame(records):
    """Score records as a table with exactly SCORE_COLUMNS, dates as ISO text."""
    rows = []
    for record in records:
        row = {key: getattr(record, key) for key in SCORE_COLUMNS}
        row["component"] = record.component.value
        row["score_kind"] = record.score_kind.value
        row["status"] = record.status.value
        row["decision_time"] = record.decision_time.isoformat()
        row["trained_through"] = record.trained_through.isoformat()
        row["snapshot_date"] = record.snapshot_date.isoformat()
        rows.append(row)
    return pd.DataFrame(rows, columns=SCORE_COLUMNS)


def write_atomically(path, write):
    """Write to a temporary file next to `path`, then replace `path` with it."""
    fd, temporary = tempfile.mkstemp(prefix=f".{path.name}.", suffix=".tmp", dir=path.parent)
    try:
        with os.fdopen(fd, "w", encoding="utf-8", newline="") as stream:
            write(stream)
        os.replace(temporary, path)
    except BaseException:
        Path(temporary).unlink(missing_ok=True)
        raise


def export_scores(records, output_path, model, score_semantics, extra=None):
    """Write one scores CSV and a metadata JSON next to it. Returns the counts per status."""
    output_path = Path(output_path)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    frame = scores_to_frame(records)
    write_atomically(output_path, lambda stream: frame.to_csv(stream, index=False))

    counts = {state.value: int((frame["status"] == state.value).sum()) for state in ScoreStatus}
    available = frame.loc[frame["status"] == ScoreStatus.AVAILABLE.value, "score"]
    first = records[0] if records else None
    metadata = {
        "component": Component.B_SURVIVAL.value,
        "model_version": first.model_version if first else None,
        "score_kind": ScoreKind.RANKING_SCORE.value,
        "score_semantics": score_semantics,
        "cohort": COHORT,
        "decision_time": first.decision_time.isoformat() if first else None,
        "trained_through": first.trained_through.isoformat() if first else None,
        "snapshot_date": first.snapshot_date.isoformat() if first else None,
        "horizon_days": first.horizon_days if first else None,
        "train_rows": model.train_rows,
        "train_events": model.train_events,
        "train_max_follow_up_days": model.train_max_follow_up,
        "target_count": len(records),
        "status_counts": counts,
        "score_distribution": {
            "min": float(available.min()) if len(available) else None,
            "median": float(available.median()) if len(available) else None,
            "max": float(available.max()) if len(available) else None,
        },
        "output_columns": SCORE_COLUMNS,
        **(extra or {}),
    }
    metadata_path = output_path.with_suffix(output_path.suffix + ".metadata.json")
    write_atomically(metadata_path, lambda stream: stream.write(json.dumps(metadata, indent=2)))
    return counts


RAW_SEMANTICS = (
    "Cox model estimate of 'listed in CISA KEV within the next horizon_days days', given "
    "the CVE is still unlisted at the decision time: 1 - S(age + h | x) / S(age | x). "
    "A ranking score: its calibration has not been checked on held-out data, so it is "
    "not a probability."
)
PERCENTILE_SEMANTICS = (
    "Percentile rank of the raw 30-day estimate among the available CVEs: rank / N, "
    "ties share the average rank, in (0, 1]. Higher = listed in KEV sooner relative to "
    "the other CVEs. A relative ranking, not an exploitation probability."
)


def print_summary(raw, counts, model):
    print()
    print(f"Model: {raw[0].model_version if raw else '-'}")
    print(f"  train rows {model.train_rows}, events {model.train_events}")
    print("Rows per status (the same in both files):")
    for state, count in counts.items():
        print(f"  {state:<18}{count:>9}")
    scores = pd.Series([r.score for r in raw if r.score is not None], dtype=float)
    if len(scores):
        quantiles = scores.quantile([0, 0.5, 0.9, 0.99, 1])
        print("Raw estimates: " + ", ".join(f"q{q:g}={v:.5f}" for q, v in quantiles.items()))
        print(f"  mean {scores.mean():.5f}")


def main(settings=None, decision_time=None, snapshot_date=SNAPSHOT_DATE, trained_through=None):
    """Fit the scoring model, score every CVE, and write both files and their metadata.

    decision_time and trained_through are timezone-aware datetimes. By default the
    decision time is 00:00 UTC on SNAPSHOT_DATE and trained_through is the start
    of the decision day (never later than the snapshot).
    """
    # Folders come from vesper.config
    settings = settings or load_settings()
    table = load_survival_table(settings.data_processed / PROCESSED_SUBFOLDER / OUTPUT_FILE_NAME)
    decision_time = decision_time or start_of_day(SNAPSHOT_DATE)
    if decision_time.tzinfo is None:
        raise ValueError("decision_time must include a time zone")
    decision_day = decision_time.astimezone(UTC).date()
    if decision_day > SNAPSHOT_DATE:
        warnings.warn(
            f"The decision day {decision_day} is after the data snapshot {SNAPSHOT_DATE}: "
            "KEV listings and CVEs after the snapshot are not known",
            stacklevel=2,
        )
    trained_through = trained_through or start_of_day(min(decision_day, SNAPSHOT_DATE))

    model = fit_scoring_model(table, trained_through)
    raw = build_timing_scores(
        table,
        model,
        decision_time=decision_time,
        trained_through=trained_through,
        snapshot_date=snapshot_date,
    )
    ranked = percentile_scores(raw, trained_through)

    output_dir = settings.outputs / PROCESSED_SUBFOLDER
    raw_path, output_path = output_dir / RAW_OUTPUT_FILE, output_dir / OUTPUT_FILE
    counts = export_scores(raw, raw_path, model, RAW_SEMANTICS)
    export_scores(
        ranked,
        output_path,
        model,
        PERCENTILE_SEMANTICS,
        extra={
            "source_file": RAW_OUTPUT_FILE,
            "source_model_version": raw[0].model_version if raw else None,
            "percentile_population": counts[ScoreStatus.AVAILABLE.value],
            "percentile_definition": "rank / N, average ranks for ties, in (0, 1]",
        },
    )
    print_summary(raw, counts, model)
    print()
    print("Saved:", raw_path)
    print("Saved:", output_path)
    return output_path


if __name__ == "__main__":
    main()
