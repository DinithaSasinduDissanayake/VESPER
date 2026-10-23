"""Fit the Component A text model at a cut-off date and save it with its metadata."""

import argparse
import time
from datetime import UTC, date, datetime
from pathlib import Path

import joblib
import pandas as pd
import sklearn

from vesper.components.a_text.labels import DECISION_DAYS, HORIZON_DAYS, build_training_cohort
from vesper.components.a_text.model import fit_text_model, held_out_log_odds, ranking_reference
from vesper.components.a_text.sanitise import rules_digest
from vesper.config import load_settings

COLUMNS = ["published_date", "description", "kev_date_added"]  # read from the CVE table
OUTPUT_SUBFOLDER = "a_text"  # trained models go in outputs/a_text/models/


def train(data: Path, cutoff: date, out: Path) -> dict:
    """Read the CVE table, fit the model at `cutoff`, save {model, metadata} to `out`."""
    frame = pd.read_parquet(data, columns=COLUMNS)
    frame["published_date"] = pd.to_datetime(frame.published_date, utc=True)
    frame["kev_date_added"] = pd.to_datetime(frame.kev_date_added, utc=True)
    cohort = build_training_cohort(frame, cutoff)
    model = fit_text_model(cohort)
    # Three more fits, each without one third of the rows, give unseen scores to set the
    # centre and spread of the ranking score.
    reference = ranking_reference(held_out_log_odds(cohort))
    metadata = {
        "cutoff": cutoff.isoformat(),
        "horizon_days": HORIZON_DAYS,
        "decision_days": DECISION_DAYS,
        "n_train": len(cohort),
        "n_positives": int(cohort.label.sum()),
        "best_c": model.best_c,
        "offset": model.offset,
        **reference,
        "sanitiser_digest": rules_digest(),  # load_model refuses the file if the rules change
        "sklearn_version": sklearn.__version__,
        "trained_at": datetime.now(UTC).isoformat(timespec="seconds"),
    }
    out.parent.mkdir(parents=True, exist_ok=True)
    joblib.dump({"model": model, "metadata": metadata}, out)
    return metadata


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--data", type=Path, required=True, help="parquet with " + ", ".join(COLUMNS)
    )
    parser.add_argument("--cutoff", type=date.fromisoformat, required=True, help="YYYY-MM-DD (UTC)")
    parser.add_argument(
        "--out", type=Path, help="default: outputs/a_text/models/model_<cutoff>.joblib"
    )
    args = parser.parse_args(argv)
    out = args.out or (
        load_settings().outputs / OUTPUT_SUBFOLDER / "models" / f"model_{args.cutoff}.joblib"
    )
    started = time.perf_counter()
    metadata = train(args.data, args.cutoff, out)
    print(metadata)
    print(f"Saved {out} in {time.perf_counter() - started:.0f} s")
    return out


if __name__ == "__main__":
    main()
