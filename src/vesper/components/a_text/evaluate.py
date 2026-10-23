"""Rolling quarterly evaluation of Component A against a CVSS baseline.

For each test quarter: train on every CVE whose 90-day label was settled before the
quarter started, score the CVEs published in the quarter, and count how many of the
top 100 entered KEV within 90 days. The same rows are ranked by CVSS base score.
"""

import argparse
import json
import re
import time
from pathlib import Path

import numpy as np
import pandas as pd
from sklearn.metrics import average_precision_score

from vesper.components.a_text.labels import HORIZON_DAYS, build_training_cohort
from vesper.components.a_text.model import fit_text_model
from vesper.config import load_settings

COLUMNS = ["cve_id", "published_date", "description", "kev_date_added", "vuln_status"]
CVSS_COLUMN = "cvss_base_score"
METHODS = ("A", "CVSS")
FIRST_QUARTER = "2023Q1"
HITS_K = 100  # the review budget: top 100 CVEs of each quarter
RECALL_K = 1000
DRAWS = 1000
SEED = 20261022  # seed of the experiment's paired A - CVSS bootstrap
OUTPUT_SUBFOLDER = "a_text"  # results go in outputs/a_text/evaluation/

# Leak wording the sanitiser does not delete (experiment note 25). "exploited in the
# wild" is deleted by the sanitiser already, so it is removed before two of the checks.
_DELETED = re.compile(r"(actively\s+)?exploited in the wild", re.IGNORECASE)
_ON_RAW_TEXT = [r"aware of (a )?reports? that this issue may have been", r"KEV\)\s*catalog"]
_AFTER_DELETION = [r"\bactively\b", r"\bin the wild\b"]


def has_leak_wording(text) -> bool:
    """True when the raw description still says it was exploited after sanitising."""
    text = "" if pd.isna(text) else str(text)
    rest = _DELETED.sub(" ", text)
    return any(re.search(p, text, re.IGNORECASE) for p in _ON_RAW_TEXT) or any(
        re.search(p, rest, re.IGNORECASE) for p in _AFTER_DELETION
    )


def quarter_start(name: str) -> pd.Timestamp:
    year, quarter = name.upper().split("Q")
    return pd.Timestamp(year=int(year), month=3 * int(quarter) - 2, day=1, tz="UTC")


def quarter_name(start: pd.Timestamp) -> str:
    return f"{start.year}Q{start.quarter}"


def next_quarter(start: pd.Timestamp) -> pd.Timestamp:
    return start + pd.DateOffset(months=3)


def mature_quarters(frame: pd.DataFrame) -> list[pd.Timestamp]:
    """Quarters from 2023Q1 whose every 90-day window closed by the newest date in the data."""
    snapshot = max(frame.published_date.max(), frame.kev_date_added.max())
    starts, start = [], quarter_start(FIRST_QUARTER)
    while next_quarter(start) + pd.Timedelta(days=HORIZON_DAYS) <= snapshot:
        starts.append(start)
        start = next_quarter(start)
    return starts


def test_cohort(frame: pd.DataFrame, start: pd.Timestamp) -> pd.DataFrame:
    """CVEs published in the quarter, labelled by the same rules as the training cohort."""
    end = next_quarter(start)
    # A cut-off 90 days after the quarter ends lets every window in the quarter close.
    cohort = build_training_cohort(
        frame[frame.published_date < end], end + pd.Timedelta(days=HORIZON_DAYS)
    )
    return cohort[cohort.published_date >= start]


def score_quarter(frame: pd.DataFrame, start: pd.Timestamp) -> tuple[pd.DataFrame, dict]:
    """Fit A on labels settled before `start`; score the quarter with A and CVSS."""
    began = time.perf_counter()
    train = build_training_cohort(frame, start)  # published and settled before `start`
    test = test_cohort(frame, start)
    assert not train.cve_id.isin(test.cve_id).any(), "a test CVE is in the training set"
    model = fit_text_model(train)
    rows = pd.DataFrame(
        {
            "quarter": quarter_name(start),
            "cve_id": test.cve_id.to_numpy(),
            "label": test.label.to_numpy(),
            "A": model.log_odds(test.description.tolist()),
            "CVSS": test[CVSS_COLUMN].to_numpy(dtype=float),
            "leak_wording": test.description.map(has_leak_wording).to_numpy(),
        }
    )
    fit = {
        "quarter": quarter_name(start),
        "n_train": len(train),
        "train_positives": int(train.label.sum()),
        "best_c": model.best_c,
        "seconds": round(time.perf_counter() - began, 1),
    }
    return rows, fit


# ---- metrics ----------------------------------------------------------------------


def top(group: pd.DataFrame, method: str, k: int) -> pd.DataFrame:
    """The k highest scores; equal scores keep table order; missing scores are never picked."""
    scored = group[np.isfinite(group[method])]
    return scored.sort_values(method, ascending=False, kind="stable").head(k)


def tie_range(group: pd.DataFrame, method: str, k: int) -> tuple[int, float, int]:
    """Fewest, expected (random order) and most hits@k over orders of the tied k-th scores."""
    scores = group[method].to_numpy(dtype=float)
    labels = group.label.to_numpy()
    finite = np.isfinite(scores)
    scores, labels = scores[finite], labels[finite]
    if len(scores) <= k:
        hits = int(labels.sum())
        return hits, float(hits), hits
    boundary = np.sort(scores)[::-1][k - 1]
    fixed = int(labels[scores > boundary].sum())
    slots = k - int((scores > boundary).sum())
    tied = labels[scores == boundary]
    positives, negatives = int(tied.sum()), len(tied) - int(tied.sum())
    expected = fixed + slots * positives / len(tied)
    return fixed + max(0, slots - negatives), round(expected, 2), fixed + min(slots, positives)


def dense_ranks(scores: np.ndarray) -> np.ndarray:
    """0 for the highest score, equal scores share a rank, -1 for a missing score."""
    ranks = np.full(len(scores), -1, dtype=np.int64)
    finite = np.isfinite(scores)
    distinct = np.unique(scores[finite])
    ranks[finite] = len(distinct) - 1 - np.searchsorted(distinct, scores[finite])
    return ranks


def sampled_hits(labels, ranks, sample, k: int) -> int:
    """hits@k in one bootstrap sample; at a tied boundary the sampled order decides."""
    ranks, labels = ranks[sample], labels[sample]
    scored = ranks >= 0
    ranks, labels = ranks[scored], labels[scored]
    if len(ranks) <= k:
        return int(labels.sum())
    boundary = np.partition(ranks, k - 1)[k - 1]
    above = ranks < boundary
    slots = k - int(above.sum())
    return int(labels[above].sum() + labels[ranks == boundary][:slots].sum())


def interval(estimate: float, draws: list[float]) -> dict:
    return {
        "estimate": float(estimate),
        "lower": float(np.quantile(draws, 0.025)),
        "upper": float(np.quantile(draws, 0.975)),
    }


def paired_bootstrap(pred: pd.DataFrame, draws: int, seed: int) -> list[dict]:
    """Per draw, resample CVEs within each quarter once and score both methods on it."""
    quarters = []
    for _, group in pred.groupby("quarter", sort=True):
        ranks = {m: dense_ranks(group[m].to_numpy(dtype=float)) for m in METHODS}
        quarters.append((group.label.to_numpy(dtype=int), ranks))
    rng = np.random.default_rng(seed)
    results = []
    for _ in range(draws):
        hits = {(m, k): 0 for m in METHODS for k in (HITS_K, RECALL_K)}
        positives = 0
        for labels, ranks in quarters:
            sample = rng.integers(0, len(labels), len(labels))
            positives += int(labels[sample].sum())
            for m in METHODS:
                for k in (HITS_K, RECALL_K):
                    hits[m, k] += sampled_hits(labels, ranks[m], sample, k)
        draw = {}
        for m in METHODS:
            draw[m, "hits"] = hits[m, HITS_K]
            draw[m, "recall"] = hits[m, RECALL_K] / positives if positives else 0.0
        results.append(draw)
    return results


def summarise(pred: pd.DataFrame, draws: int = DRAWS, seed: int = SEED) -> dict:
    """Pooled and per-quarter metrics for A and CVSS, with 95% bootstrap intervals."""
    per_quarter, totals = [], {(m, k): 0 for m in METHODS for k in (HITS_K, RECALL_K)}
    for quarter, group in pred.groupby("quarter", sort=True):
        row = {"quarter": quarter, "eligible": len(group), "positives": int(group.label.sum())}
        for m in METHODS:
            for k in (HITS_K, RECALL_K):
                totals[m, k] += int(top(group, m, k).label.sum())
            row[f"{m}_hits@{HITS_K}"] = int(top(group, m, HITS_K).label.sum())
            fewest, expected, most = tie_range(group, m, HITS_K)
            row |= {f"{m}_ties_min": fewest, f"{m}_ties_expected": expected, f"{m}_ties_max": most}
            row[f"{m}_found@{RECALL_K}"] = int(top(group, m, RECALL_K).label.sum())
        per_quarter.append(row)

    positives = int(pred.label.sum())
    boot = paired_bootstrap(pred, draws, seed)
    methods = {}
    for m in METHODS:
        recall = totals[m, RECALL_K] / positives if positives else 0.0
        # Missing scores rank last, as in the experiment.
        ap_scores = np.where(np.isfinite(pred[m]), pred[m], -1e12)
        methods[m] = {
            f"hits@{HITS_K}": interval(totals[m, HITS_K], [d[m, "hits"] for d in boot]),
            f"recall@{RECALL_K}": interval(recall, [d[m, "recall"] for d in boot]),
            "average_precision": float(average_precision_score(pred.label, ap_scores))
            if positives
            else 0.0,
            # hits@100 if equal scores were ordered at random instead of by table order
            f"hits@{HITS_K}_ties_expected": round(
                sum(q[f"{m}_ties_expected"] for q in per_quarter), 2
            ),
            "scored": int(np.isfinite(pred[m]).sum()),
        }
    a, c = methods["A"], methods["CVSS"]
    difference = {
        f"hits@{HITS_K}": interval(
            a[f"hits@{HITS_K}"]["estimate"] - c[f"hits@{HITS_K}"]["estimate"],
            [d["A", "hits"] - d["CVSS", "hits"] for d in boot],
        ),
        f"recall@{RECALL_K}": interval(
            a[f"recall@{RECALL_K}"]["estimate"] - c[f"recall@{RECALL_K}"]["estimate"],
            [d["A", "recall"] - d["CVSS", "recall"] for d in boot],
        ),
    }
    return {
        "quarters": len(per_quarter),
        "eligible": len(pred),
        "positives": positives,
        "methods": methods,
        "A_minus_CVSS": difference,
        "per_quarter": per_quarter,
    }


def evaluate_predictions(pred: pd.DataFrame, draws: int = DRAWS) -> dict:
    """Metrics on every CVE, and again without CVEs whose text still has leak wording."""
    clean = pred[~pred.leak_wording]
    return {
        "all_cves": summarise(pred, draws),
        "without_leak_wording": {
            "removed_cves": int(pred.leak_wording.sum()),
            "removed_positives": int(pred.label[pred.leak_wording].sum()),
            **summarise(clean, draws),
        },
    }


# ---- command line -----------------------------------------------------------------


def load(data: Path) -> pd.DataFrame:
    frame = pd.read_parquet(data, columns=COLUMNS + [CVSS_COLUMN])
    frame["published_date"] = pd.to_datetime(frame.published_date, utc=True)
    frame["kev_date_added"] = pd.to_datetime(frame.kev_date_added, utc=True)
    return frame[frame.vuln_status != "Rejected"].reset_index(drop=True)


def pick_quarters(frame: pd.DataFrame, spec: str | None) -> list[pd.Timestamp]:
    """`None` = every mature quarter; else "2024Q1,2025Q3" or a range "2023Q1-2026Q2"."""
    mature = mature_quarters(frame)
    if spec is None:
        return mature
    if "-" in spec:
        first, last = (quarter_start(s) for s in spec.split("-"))
        wanted = [q for q in mature if first <= q <= last]
    else:
        wanted = [quarter_start(s) for s in spec.split(",")]
    late = [quarter_name(q) for q in wanted if q not in mature]
    if late:
        raise ValueError(f"not mature in this data (90-day windows still open): {late}")
    return wanted


def table(result: dict) -> pd.DataFrame:
    """One row per quarter plus a total row, for both cohorts."""
    rows = []
    for cohort in ("all_cves", "without_leak_wording"):
        part = pd.DataFrame(result[cohort]["per_quarter"])
        total = part.drop(columns="quarter").sum().to_dict() | {"quarter": "total"}
        rows.append(pd.concat([part, pd.DataFrame([total])]).assign(cohort=cohort))
    return pd.concat(rows, ignore_index=True)


def main(argv=None):
    settings = load_settings()
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--data",
        type=Path,
        default=settings.data_processed / OUTPUT_SUBFOLDER / "cves.parquet",
        help="CVE table from vesper.components.a_text.dataset",
    )
    parser.add_argument("--quarters", help='e.g. "2023Q1-2026Q2" or "2024Q1,2025Q2" (default: all)')
    parser.add_argument("--draws", type=int, default=DRAWS, help="bootstrap draws")
    parser.add_argument(
        "--out", type=Path, default=settings.outputs / OUTPUT_SUBFOLDER / "evaluation"
    )
    args = parser.parse_args(argv)

    began = time.perf_counter()
    frame = load(args.data)
    parts, fits = [], []
    for start in pick_quarters(frame, args.quarters):
        rows, fit = score_quarter(frame, start)
        parts.append(rows)
        fits.append(fit)
        print(fit, flush=True)
    pred = pd.concat(parts, ignore_index=True)
    result = {
        "data": str(args.data),
        "snapshot": str(max(frame.published_date.max(), frame.kev_date_added.max())),
        "horizon_days": HORIZON_DAYS,
        "draws": args.draws,
        "seed": SEED,
        **evaluate_predictions(pred, args.draws),
        "fits": fits,
        "seconds": round(time.perf_counter() - began),
    }
    args.out.mkdir(parents=True, exist_ok=True)
    pred.to_parquet(args.out / "predictions.parquet", index=False)
    (args.out / "evaluation.json").write_text(json.dumps(result, indent=2), encoding="utf-8")
    table(result).to_csv(args.out / "quarters.csv", index=False)
    for cohort in ("all_cves", "without_leak_wording"):
        s = result[cohort]
        hits = {m: s["methods"][m][f"hits@{HITS_K}"]["estimate"] for m in METHODS}
        d = s["A_minus_CVSS"][f"hits@{HITS_K}"]
        print(
            f"{cohort}: {s['quarters']} quarters, {s['positives']} positives, hits@{HITS_K} "
            f"A {hits['A']:.0f} vs CVSS {hits['CVSS']:.0f}, "
            f"A - CVSS {d['estimate']:+.0f} [{d['lower']:.0f}, {d['upper']:.0f}]"
        )
    print(f"Saved {args.out} in {result['seconds']} s")
    return result


if __name__ == "__main__":
    main()
