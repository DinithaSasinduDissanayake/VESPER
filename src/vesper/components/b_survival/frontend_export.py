"""Export a demo JSON of the real exploit-timing model for the frontend."""

import gzip
import json
import re
from datetime import UTC, date, datetime

import numpy as np
import pandas as pd
from lifelines import KaplanMeierFitter

from vesper.components.b_survival.cox_model import PENALIZER, fit_cox
from vesper.components.b_survival.evaluate import OUTPUT_SUBFOLDER
from vesper.components.b_survival.features import NUMERIC_COLUMN, drop_missing_cvss
from vesper.components.b_survival.score_export import (
    COHORT,
    HORIZON_DAYS,
    build_timing_scores,
    percentile_scores,
    start_of_day,
)
from vesper.components.b_survival.score_history import code_version
from vesper.components.b_survival.split_data import load_survival_table, split_at_cutoff
from vesper.components.b_survival.study_design import (
    MAIN_CUTOFF,
    PROCESSED_SUBFOLDER,
    SNAPSHOT_DATE,
)
from vesper.components.b_survival.survival_table import OUTPUT_FILE_NAME, filter_cohort
from vesper.config import load_settings
from vesper.contracts.score import ScoreStatus

OUTPUT_PARTS = ("frontend", "public", "demo", "exploit_timing.json")
SAMPLE_QUEUE_PARTS = ("frontend", "src", "queue", "sampleQueue.ts")
EXPLOITDB_FILE = "exploitdb_clean.csv"

CURRENT_DECISION = SNAPSHOT_DATE  # 2026-10-01, the deployment setting
BACKTEST_DECISION = date(2026, 9, 1)  # the last history decision time
TOP_N = 25
TOP_FACTORS = 6
KM_MAX_DAYS = 730
KM_MAX_POINTS = 200
TOP_SHARES = (0.01, 0.05, 0.10)
EXPLOITDB_URL = "https://www.exploit-db.com/exploits/{}"
NVD_URL = "https://nvd.nist.gov/vuln/detail/{}"
# Level by percentile among the scored CVEs: High = top 5%, Medium = next 15%
LEVEL_CUTOFFS = (("High", 0.95), ("Medium", 0.80))
RECENT_KEV_LIMIT = 10
DESCRIPTION_CHARS = 220

RETROSPECTIVE_NOTE = (
    "Retrospective: CVSS and CWE are the current NVD values, not as they were at the "
    "decision time. Model training, KEV outcomes and exploit dates are cut at the "
    "decision time."
)

FEATURE_LABELS = {
    "cvss_score_std": "CVSS base score",
    "exploit_at_publication": "Public exploit on publication day",
}


# ---------------------------------------------------------------------------
# Models and scores at one decision time
# ---------------------------------------------------------------------------


class Scored:
    """The model, train rows and scores at one decision time."""

    def __init__(self, table, day):
        self.day = day
        self.decision_time = start_of_day(day)
        train, _, _ = split_at_cutoff(filter_cohort(table, COHORT), day)
        self.train, _ = drop_missing_cvss(train)
        self.model = fit_cox(self.train)
        raw = build_timing_scores(
            table, self.model, decision_time=self.decision_time, trained_through=self.decision_time
        )
        ranked = percentile_scores(raw, self.decision_time)
        self.frame = pd.DataFrame(
            {
                "cve_id": [r.cve_id for r in raw],
                "status": [r.status.value for r in raw],
                "reason": [r.reason for r in raw],
                "raw": [r.score for r in raw],
                "percentile": [r.score for r in ranked],
                "model_version": [r.model_version for r in ranked],
                "raw_model_version": [r.model_version for r in raw],
            }
        ).set_index("cve_id")
        available = self.frame["status"] == ScoreStatus.AVAILABLE.value
        # Rank shown on screen: 1 = highest raw estimate among the available CVEs;
        # tied CVEs share the same number (1, 2, 2, 4). The back-test summary uses
        # average ranks instead, to be fair to CVSS's many ties.
        self.frame["rank"] = self.frame.loc[available, "raw"].rank(ascending=False, method="min")
        self.available_count = int(available.sum())
        train_features = self.model.features(self.train)
        self.feature_means = train_features.mean()


# ---------------------------------------------------------------------------
# Per-CVE detail
# ---------------------------------------------------------------------------


def day_text(value):
    return None if pd.isna(value) else pd.Timestamp(value).date().isoformat()


def number(value, digits=6):
    return None if value is None or pd.isna(value) else round(float(value), digits)


def factor_label(feature):
    if feature in FEATURE_LABELS:
        return FEATURE_LABELS[feature]
    if feature.startswith("cwe="):
        return feature.removeprefix("cwe=")
    name, _, level = feature.partition("=")
    return f"{name.removeprefix('cvss_').replace('_', ' ').capitalize()}: {level.lower()}"


def top_factors(scored, row):
    """The features that move this CVE's relative risk most, against an average
    train CVE: coef x (value - train mean), with the hazard ratio exp(coef)."""
    features = scored.model.features(row).iloc[0]
    params = scored.model.fitter.params_
    factors = []
    for feature, coef in params.items():
        value = float(features[feature])
        effect = float(coef) * (value - float(scored.feature_means[feature]))
        if feature != "cvss_score_std" and value == 0:
            continue  # a dummy that is off says nothing about this CVE
        factors.append(
            {
                "feature": feature,
                "label": factor_label(feature),
                "value": round(value, 4),
                "hazard_ratio": round(float(np.exp(coef)), 4),
                "log_effect": round(effect, 4),
            }
        )
    factors.sort(key=lambda factor: -abs(factor["log_effect"]))
    return factors[:TOP_FACTORS]


def survival_curve(scored, row, age):
    """S(age + d) / S(age) for d = 0 ... HORIZON_DAYS: the chance of not being
    listed by each day of the next HORIZON_DAYS days."""
    partial = float(scored.model.risk(row)[0])
    days = np.arange(HORIZON_DAYS + 1)
    added = scored.model.cumulative_baseline(age + days) - scored.model.cumulative_baseline(
        np.full(len(days), age)
    )
    return [round(float(value), 8) for value in np.exp(-added * partial)]


def cve_detail(scored, table_row, exploits):
    """Everything the CVE detail card shows for one CVE at one decision time."""
    decision = pd.Timestamp(scored.decision_time)
    cve_id = table_row["cve_id"]
    published = table_row["published_at"]
    age = int((decision.normalize() - published.normalize()).days)
    score = scored.frame.loc[cve_id]
    row = table_row.to_frame().T.infer_objects()

    kev = None
    if table_row["event"] == 1:
        kev_day = published.normalize() + pd.Timedelta(days=int(table_row["duration_days"]))
        kev = {"date": day_text(kev_day), "after_decision": bool(kev_day >= decision.normalize())}

    before = exploits[(exploits["cve_id"] == cve_id) & (exploits["date_published"] < decision)]
    evidence = [{"kind": "published", "date": day_text(published), "label": "Published in NVD"}]
    for exploit in before.sort_values("date_published").itertuples():
        evidence.append(
            {
                "kind": "exploit",
                "date": day_text(exploit.date_published),
                "label": f"Exploit-DB {exploit.exploit_id}",
                "source": "exploitdb",
                "url": EXPLOITDB_URL.format(exploit.exploit_id),
            }
        )

    available = score["status"] == ScoreStatus.AVAILABLE.value
    has_cvss = pd.notna(table_row[NUMERIC_COLUMN])
    return {
        "cve_id": cve_id,
        "decision_time": scored.decision_time.isoformat(),
        "trained_through": scored.decision_time.isoformat(),
        "model_version": score["model_version"],
        "published": day_text(published),
        "age_days": age,
        "cvss": number(table_row[NUMERIC_COLUMN], 1),
        "cwe": [cwe for cwe in str(table_row["cwe_ids"] or "").split(";") if cwe and cwe != "nan"],
        "status": score["status"],
        "reason": score["reason"],
        "raw_30d": number(score["raw"], 8) if available else None,
        "percentile": number(score["percentile"]) if available else None,
        "rank": int(score["rank"]) if available else None,
        "rank_of": scored.available_count,
        "survival": survival_curve(scored, row, age) if available else None,
        "evidence": evidence,
        "kev": kev,
        "factors": top_factors(scored, row) if has_cvss else [],
    }


# ---------------------------------------------------------------------------
# Results from the evaluate outputs
# ---------------------------------------------------------------------------


def evaluate_results(models_dir, current):
    """Results read from the files written by evaluate (nothing recomputed)."""
    metrics = pd.read_csv(models_dir / "metrics.csv")
    differences = pd.read_csv(models_dir / "c_index_differences.csv")
    ratios = pd.read_csv(models_dir / "hazard_ratios.csv")
    main_cutoff = MAIN_CUTOFF.isoformat()

    def metric(cohort, model):
        row = metrics[
            (metrics["cohort"] == cohort)
            & (metrics["cutoff"] == main_cutoff)
            & (metrics["model"] == model)
        ].iloc[0]
        return {
            "c_index": number(row["c_index"], 4),
            "c_index_ci": [number(row["c_index_ci_lower"], 4), number(row["c_index_ci_upper"], 4)],
            "p_at_100": number(row["p_at_100"], 4),
            "p_at_100_ci": [
                number(row["p_at_100_ci_lower"], 4),
                number(row["p_at_100_ci_upper"], 4),
            ],
            "train_events": int(row["train_events"]),
            "test_events": int(row["test_events"]),
        }

    def difference_rows(frame):
        return [
            {
                "cohort": row.cohort,
                "cutoff": row.cutoff,
                "difference": number(row.c_index_difference, 4),
                "ci": [number(row.ci_lower, 4), number(row.ci_upper, 4)],
                "excludes_zero": bool(row.excludes_zero),
                "train_events": int(
                    metrics[
                        (metrics["cohort"] == row.cohort)
                        & (metrics["cutoff"] == row.cutoff)
                        & (metrics["model"] == "cox")
                    ]["train_events"].iloc[0]
                ),
            }
            for row in frame.itertuples()
        ]

    main = {}
    for cohort in ("post_kev", "full"):
        main[cohort] = {
            "cox": metric(cohort, "cox"),
            "cvss": metric(cohort, "cvss_rank"),
            "difference": difference_rows(
                differences[
                    (differences["cohort"] == cohort) & (differences["cutoff"] == main_cutoff)
                ]
            )[0],
        }

    post_kev_ratios = ratios[
        (ratios["cohort"] == "post_kev")
        & (ratios["model"] == "cox")
        & (ratios["cutoff"] == main_cutoff)
    ]
    hazard_rows = []
    for row in post_kev_ratios.itertuples():
        if row.feature == "cvss_score_std":
            continue  # the per-point row is easier to read
        hazard_rows.append(
            {
                "feature": row.feature,
                "label": "CVSS base score (per 1 point)"
                if row.feature.startswith("cvss_base_score")
                else factor_label(row.feature),
                "hazard_ratio": number(row.hazard_ratio, 3),
                "ci": [number(row.ci_lower_95, 3), number(row.ci_upper_95, 3)],
                "p_value": number(row.p_value, 4),
            }
        )
    hazard_rows.sort(key=lambda row: row["p_value"])

    durations = current.train["duration_days"]
    events = current.train["event"] == 1
    starts = current.model.band_starts
    band_index = np.searchsorted(starts, durations[events], side="right") - 1
    counts = np.bincount(band_index, minlength=len(starts))
    bands = [
        {
            "start_day": int(start),
            "end_day": int(starts[i + 1]) if i + 1 < len(starts) else None,
            "train_listings": int(counts[i]),
            "rate_per_day": float(current.model.band_rates[i]),
        }
        for i, start in enumerate(starts)
    ]

    return {
        "main_cutoff": main_cutoff,
        "main": main,
        "differences": difference_rows(differences.sort_values(["cohort", "cutoff"])),
        "hazard_ratios": hazard_rows,
        "bands": bands,
        "bands_model_version": current.frame["raw_model_version"].iloc[0],
    }


def kaplan_meier_points(table):
    """Overall post_kev Kaplan-Meier curve, days 0-KM_MAX_DAYS, at most KM_MAX_POINTS."""
    rows = filter_cohort(table, "post_kev")
    rows = rows[~rows["already_exploited"]]
    fitter = KaplanMeierFitter().fit(rows["duration_days"], rows["event"])
    days = np.unique(np.linspace(0, KM_MAX_DAYS, KM_MAX_POINTS).round().astype(int))
    values = fitter.survival_function_at_times(days).to_numpy()
    return {
        "cohort": "post_kev",
        "rows": len(rows),
        "events": int(rows["event"].sum()),
        "points": [[int(d), round(float(v), 6)] for d, v in zip(days, values, strict=True)],
    }


# ---------------------------------------------------------------------------
# Back-test
# ---------------------------------------------------------------------------


def listed_in_window(table, start, days=HORIZON_DAYS):
    """CVE IDs added to KEV from `start` (inclusive) for `days` days."""
    first = pd.Timestamp(start, tz="UTC")
    last = first + pd.Timedelta(days=days)
    published_day = table["published_at"].dt.normalize()
    kev_day = published_day + pd.to_timedelta(table["duration_days"], unit="D")
    listed = (table["event"] == 1) & (kev_day >= first) & (kev_day < last)
    return table.loc[listed, "cve_id"].tolist()


def backtest_summary(table, scored, listed_ids):
    """Where the CVEs listed after the decision time ranked, by B and by CVSS."""
    frame = scored.frame
    available = frame[frame["status"] == ScoreStatus.AVAILABLE.value]
    n = len(available)
    cvss = table.set_index("cve_id").loc[available.index, NUMERIC_COLUMN].astype(float)
    # Rank 1 = highest. Tied CVEs share the average rank (the expected place in a
    # random order of the tie), as P@100 does in evaluate; CVSS has many ties.
    b_rank = available["raw"].rank(ascending=False, method="average")
    cvss_rank = cvss.rank(ascending=False, method="average")

    statuses = frame.loc[[i for i in listed_ids if i in frame.index], "status"]
    scored_ids = [i for i in listed_ids if i in available.index]
    counts = {}
    for share in TOP_SHARES:
        limit = share * n
        counts[f"top_{round(share * 100)}pct"] = {
            "b": int((b_rank[scored_ids] <= limit).sum()),
            "cvss": int((cvss_rank[scored_ids] <= limit).sum()),
        }
    return {
        "decision_time": scored.decision_time.isoformat(),
        "window_days": HORIZON_DAYS,
        "listed": len(listed_ids),
        "listed_by_status": statuses.value_counts().to_dict(),
        "listed_published_after_decision": len(listed_ids) - len(statuses),
        "scored": len(scored_ids),
        "available_population": n,
        "top_counts": counts,
        "rank_note": "Tied CVEs share the average rank (CVSS has many ties).",
        "per_cve": [
            {
                "cve_id": cve_id,
                "b_rank": round(float(b_rank[cve_id]), 1),
                "cvss_rank": round(float(cvss_rank[cve_id]), 1),
                "cvss": number(cvss[cve_id], 1),
            }
            for cve_id in scored_ids
        ],
    }


# ---------------------------------------------------------------------------
# Main program
# ---------------------------------------------------------------------------


# ---------------------------------------------------------------------------
# Plain-language additions: level, product, reasons, recent KEV additions
# ---------------------------------------------------------------------------


def level_of(percentile):
    """High / Medium / Low from the percentile (None when there is no score)."""
    if percentile is None or pd.isna(percentile):
        return None
    for name, cutoff in LEVEL_CUTOFFS:
        if percentile >= cutoff:
            return name
    return "Low"


def short_text(text, limit=DESCRIPTION_CHARS):
    if len(text) <= limit:
        return text
    return text[: limit - 1].rsplit(" ", 1)[0] + "…"


def known(value):
    """False for an empty vendor or product, or the "n/a" that some NVD records use."""
    return bool(value) and str(value).strip().lower() not in {"n/a", "na", "-", "unknown"}


def load_nvd_info(nvd_dir, table, cve_ids):
    """Vendor, product and a short description per CVE, from the raw NVD files.

    Only the monthly files in which these CVEs were published are read.
    """
    wanted = set(cve_ids)
    months = sorted(
        set(table.loc[table["cve_id"].isin(wanted), "published_at"].dt.strftime("%Y-%m"))
    )
    info = {}
    for month in months:
        path = nvd_dir / f"nvd_{month}.json.gz"
        if not path.exists():
            continue
        with gzip.open(path, "rt", encoding="utf-8") as file:
            records = json.load(file)["vulnerabilities"]
        for record in records:
            cve = record["cve"]
            if cve["id"] not in wanted:
                continue
            english = [d["value"] for d in cve.get("descriptions", []) if d.get("lang") == "en"]
            affected = [
                item
                for block in cve.get("affected", [])
                for item in block.get("affectedData", [])
                if known(item.get("vendor")) or known(item.get("product"))
            ]
            first = affected[0] if affected else {}
            info[cve["id"]] = {
                "vendor": first.get("vendor") if known(first.get("vendor")) else None,
                "product": first.get("product") if known(first.get("product")) else None,
                "description": short_text(english[0]) if english else None,
            }
    return info


def first_month_ratio(bands):
    """Baseline hazard of the first age band against the second."""
    if len(bands) < 2 or bands[1]["rate_per_day"] <= 0:
        return None
    return bands[0]["rate_per_day"] / bands[1]["rate_per_day"]


def plain_reasons(detail, ratio):
    """One to four short sentences that explain the level, by fixed rules."""
    if detail["status"] == ScoreStatus.ALREADY_EXPLOITED.value:
        return [
            "Already in the CISA list of attacked vulnerabilities (KEV) since "
            f"{detail['kev']['date']}. Patch it now."
        ]
    if detail["status"] != ScoreStatus.AVAILABLE.value:
        return [f"No score: {detail['reason']}"]

    top_share = 1 - detail["percentile"]
    share = "top 1%" if top_share < 0.01 else f"top {top_share * 100:.0f}%"
    reasons = [
        f"{detail['level']}: #{round(detail['rank']):,} of {detail['rank_of']:,} vulnerabilities "
        f"not yet attacked ({share})."
    ]
    if detail["age_days"] <= 30:
        days = detail["age_days"]
        reason = f"It is new: published {days} day{'' if days == 1 else 's'} ago."
        if ratio:
            reason += f" In the first 30 days the risk is about {ratio:.0f}× the next two months."
        reasons.append(reason)
    exploits = [item for item in detail["evidence"] if item["kind"] == "exploit"]
    if any(f["feature"] == "exploit_at_publication" for f in detail["factors"]):
        reasons.append("Public exploit code was available on the day it was published.")
    elif exploits:
        reasons.append(f"Public exploit code appeared on {exploits[0]['date']}.")
    cvss = detail["cvss"]
    if cvss is not None and cvss >= 9:
        reasons.append(f"Its severity is critical (CVSS {cvss:.1f}).")
    elif cvss is not None and cvss >= 7:
        reasons.append(f"Its severity is high (CVSS {cvss:.1f}).")
    raising = [
        f for f in detail["factors"] if f["feature"].startswith("cwe=") and f["hazard_ratio"] > 1.1
    ]
    if raising:
        reasons.append(
            f"Its weakness type ({raising[0]['label']}) is attacked more often than average."
        )
    return reasons[:4]


def add_plain_fields(detail, nvd_info, ratio):
    """Add level, NVD link, vendor, product, description and reasons to one CVE."""
    detail["level"] = level_of(detail["percentile"])
    detail["nvd_url"] = NVD_URL.format(detail["cve_id"])
    detail.update(
        nvd_info.get(detail["cve_id"], {"vendor": None, "product": None, "description": None})
    )
    detail["reasons"] = plain_reasons(detail, ratio)
    return detail


def recent_kev(kev_records, decision_time, days=HORIZON_DAYS, limit=RECENT_KEV_LIMIT):
    """CVEs added to KEV in the `days` days before the decision time, newest first."""
    decision_day = pd.Timestamp(decision_time).normalize()
    first = decision_day - pd.Timedelta(days=days)
    items = []
    for record in kev_records:
        added = pd.Timestamp(record["dateAdded"], tz="UTC")
        if first <= added < decision_day:
            items.append(
                {
                    "cve_id": record["cveID"],
                    "date_added": added.date().isoformat(),
                    "vendor": record.get("vendorProject"),
                    "product": record.get("product"),
                    "name": record.get("vulnerabilityName"),
                    "nvd_url": NVD_URL.format(record["cveID"]),
                }
            )
    items.sort(key=lambda item: (item["date_added"], item["cve_id"]), reverse=True)
    return {"window_days": days, "count": len(items), "items": items[:limit]}


def load_kev_records(kev_dir, snapshot_date=SNAPSHOT_DATE):
    """The KEV catalogue file of the snapshot ([] if it is missing)."""
    path = kev_dir / f"kev_{snapshot_date.isoformat()}.json"
    if not path.exists():
        return []
    return json.loads(path.read_text(encoding="utf-8"))["vulnerabilities"]


def sample_queue_ids(path):
    """CVE IDs in the frontend's sample queue file."""
    if not path.exists():
        return []
    return sorted(set(re.findall(r"CVE-\d{4}-\d{4,}", path.read_text(encoding="utf-8"))))


def load_exploits(path):
    exploits = pd.read_csv(path, dtype={"cve_id": "string"})
    exploits["date_published"] = pd.to_datetime(exploits["date_published"], utc=True)
    return exploits


def build_export(table, exploits, models_dir, sample_ids, nvd_dir=None, kev_records=()):
    """The whole JSON document as a dictionary."""
    current = Scored(table, CURRENT_DECISION)
    backtest = Scored(table, BACKTEST_DECISION)
    by_id = table.set_index("cve_id", drop=False)

    available = current.frame[current.frame["status"] == ScoreStatus.AVAILABLE.value]
    top_ids = available.sort_values("raw", ascending=False).head(TOP_N).index.tolist()
    current_ids = [i for i in dict.fromkeys(sample_ids + top_ids) if i in by_id.index]
    listed_ids = listed_in_window(table, BACKTEST_DECISION)
    results = {**evaluate_results(models_dir, current), "kaplan_meier": kaplan_meier_points(table)}
    current_details = {i: cve_detail(current, by_id.loc[i], exploits) for i in current_ids}
    backtest_details = {
        i: cve_detail(backtest, by_id.loc[i], exploits)
        for i in listed_ids
        if i in backtest.frame.index
    }
    nvd_info = (
        load_nvd_info(nvd_dir, table, list(current_details) + list(backtest_details))
        if nvd_dir
        else {}
    )
    ratio = first_month_ratio(results["bands"])
    for details in (current_details, backtest_details):
        for detail in details.values():
            add_plain_fields(detail, nvd_info, ratio)
    levels = current.frame["percentile"].map(level_of)

    return {
        "meta": {
            "model_version": current.frame["model_version"].iloc[0],
            "raw_model_version": current.frame["raw_model_version"].iloc[0],
            "decision_time": current.decision_time.isoformat(),
            "trained_through": current.decision_time.isoformat(),
            "backtest_decision_time": backtest.decision_time.isoformat(),
            "snapshot_date": SNAPSHOT_DATE.isoformat(),
            "horizon_days": HORIZON_DAYS,
            "cohort": COHORT,
            "penalizer": PENALIZER,
            "generated_at": datetime.now(UTC).isoformat(timespec="seconds"),
            "code_version": code_version(),
            "note": RETROSPECTIVE_NOTE,
            "sample_queue_missing": [i for i in sample_ids if i not in by_id.index],
        },
        "results": results,
        "levels": {
            "rule": "High = top 5% of scored vulnerabilities, Medium = next 15%, Low = the rest",
            "cutoffs": dict(LEVEL_CUTOFFS),
            "counts": {name: int((levels == name).sum()) for name in ("High", "Medium", "Low")},
        },
        "top": top_ids,
        "cves": {"current": current_details, "backtest": backtest_details},
        "backtest": backtest_summary(table, backtest, listed_ids),
        "recent_kev": recent_kev(kev_records, current.decision_time),
    }


def main(settings=None):
    """Write frontend/public/demo/exploit_timing.json and print its size."""
    # Folders come from vesper.config
    settings = settings or load_settings()
    processed = settings.data_processed / PROCESSED_SUBFOLDER
    table = load_survival_table(processed / OUTPUT_FILE_NAME)
    exploits = load_exploits(processed / EXPLOITDB_FILE)
    models_dir = settings.outputs / PROCESSED_SUBFOLDER / OUTPUT_SUBFOLDER
    root = settings.project_root
    sample_ids = sample_queue_ids(root.joinpath(*SAMPLE_QUEUE_PARTS))

    document = build_export(
        table,
        exploits,
        models_dir,
        sample_ids,
        nvd_dir=settings.raw_source("nvd"),
        kev_records=load_kev_records(settings.raw_source("kev")),
    )
    output = root.joinpath(*OUTPUT_PARTS)
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(document, indent=1), encoding="utf-8", newline="\n")

    summary = document["backtest"]
    print("Saved:", output, f"({output.stat().st_size / 1e6:.2f} MB)")
    print("CVEs: current", len(document["cves"]["current"]), "back-test", summary["listed"])
    print(
        f"Back-test {summary['decision_time'][:10]}: {summary['listed']} CVEs listed in KEV "
        f"in the next {summary['window_days']} days, {summary['scored']} scored "
        f"(of {summary['available_population']} available)"
    )
    for name, counts in summary["top_counts"].items():
        print(f"  {name}: B {counts['b']}, CVSS {counts['cvss']}")
    print("  by status:", summary["listed_by_status"])
    print("  published after the decision time:", summary["listed_published_after_decision"])
    return output


if __name__ == "__main__":
    main()
