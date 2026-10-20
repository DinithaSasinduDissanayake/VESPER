"""Build cutoff-specific KEV-addition outcome cohorts for Component C review.

This is a label-availability analysis only. It does not train a model or claim
that current-state graph features are valid at historical decision times.
"""

from __future__ import annotations

import argparse
import hashlib
import json
from datetime import datetime
from pathlib import Path
from typing import Any

import pandas as pd

from vesper.components.c_graph.kev_labels import classify_outcome

DEFAULT_CUTOFFS = tuple(f"{year}-01-01T00:00:00Z" for year in range(2022, 2027))
OUTCOME_COLUMNS = [
    "cve_id",
    "published",
    "decision_time",
    "horizon_days",
    "horizon_end",
    "kev_date_added",
    "outcome_status",
    "outcome_label",
]


def _utc(value: str | datetime | pd.Timestamp) -> pd.Timestamp:
    result = pd.Timestamp(value)
    if result.tzinfo is None:
        raise ValueError(f"Timestamp must include a timezone: {value!r}")
    return result.tz_convert("UTC")


def _read_sources(manifest_path: Path, kev_path: Path) -> tuple[pd.DataFrame, dict[str, Any]]:
    manifest = pd.read_csv(manifest_path, dtype={"cve_id": "string"})
    required_manifest = {"cve_id", "published"}
    if not required_manifest.issubset(manifest.columns):
        raise ValueError(f"Manifest requires columns {sorted(required_manifest)}")
    manifest["cve_id"] = manifest["cve_id"].str.strip().str.upper()
    if manifest["cve_id"].isna().any() or manifest["cve_id"].duplicated().any():
        raise ValueError("Manifest CVE IDs must be present and unique")
    manifest["published"] = pd.to_datetime(
        manifest["published"], format="mixed", utc=True, errors="coerce"
    )
    if manifest["published"].isna().any():
        raise ValueError("Manifest contains missing or invalid publication timestamps")

    raw_bytes = kev_path.read_bytes()
    catalog = json.loads(raw_bytes)
    if not isinstance(catalog, dict) or not isinstance(catalog.get("vulnerabilities"), list):
        raise ValueError("KEV source must be an object containing a vulnerabilities list")
    as_of = _utc(catalog["dateReleased"])
    records = []
    for item in catalog["vulnerabilities"]:
        cve_id = str(item.get("cveID", "")).strip().upper()
        added = pd.to_datetime(item.get("dateAdded"), format="%Y-%m-%d", utc=True, errors="coerce")
        if not cve_id or pd.isna(added):
            raise ValueError("KEV record has a missing identity or invalid dateAdded")
        records.append((cve_id, added))
    kev = pd.DataFrame(records, columns=["cve_id", "kev_date_added"])
    if kev["cve_id"].duplicated().any():
        raise ValueError("KEV source contains duplicate CVE IDs; resolve before labeling")
    if kev["kev_date_added"].gt(as_of).any():
        raise ValueError("KEV source contains a dateAdded after dateReleased")
    provenance = {
        "source_url": "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json",
        "catalog_version": catalog.get("catalogVersion"),
        "date_released": as_of.isoformat(),
        "catalog_count_field": catalog.get("count"),
        "vulnerability_rows": len(kev),
        "earliest_date_added": kev["kev_date_added"].min().date().isoformat() if len(kev) else None,
        "latest_date_added": kev["kev_date_added"].max().date().isoformat() if len(kev) else None,
        "sha256": hashlib.sha256(raw_bytes).hexdigest(),
        "source_file": str(kev_path),
    }
    if catalog.get("count") != len(kev):
        raise ValueError("KEV count field does not match vulnerability row count")
    return manifest.merge(kev, on="cve_id", how="left", validate="one_to_one"), provenance


def analyze_labels(
    manifest_and_kev: pd.DataFrame,
    *,
    cutoffs: tuple[str, ...] = DEFAULT_CUTOFFS,
    horizon_days: int = 30,
    catalog_as_of: str | datetime | pd.Timestamp,
) -> tuple[pd.DataFrame, pd.DataFrame]:
    """Return per-CVE cutoff outcomes and denominator-explicit summaries."""
    if not cutoffs:
        raise ValueError("At least one cutoff is required")
    rows: list[dict[str, Any]] = []
    for cutoff_text in cutoffs:
        cutoff = _utc(cutoff_text)
        for item in manifest_and_kev.itertuples(index=False):
            status, label, horizon_end = classify_outcome(
                published=item.published,
                date_added=item.kev_date_added,
                decision_time=cutoff,
                horizon_days=horizon_days,
                catalog_as_of=catalog_as_of,
            )
            rows.append(
                {
                    "cve_id": item.cve_id,
                    "published": item.published.isoformat(),
                    "decision_time": cutoff.isoformat(),
                    "horizon_days": horizon_days,
                    "horizon_end": horizon_end.isoformat(),
                    "kev_date_added": item.kev_date_added.isoformat()
                    if pd.notna(item.kev_date_added)
                    else "",
                    "outcome_status": status,
                    "outcome_label": label,
                }
            )
    outcomes = pd.DataFrame(rows, columns=OUTCOME_COLUMNS)
    summary_rows = []
    for cutoff, group in outcomes.groupby("decision_time", sort=True):
        counts = group["outcome_status"].value_counts().to_dict()
        eligible = int(group["outcome_label"].notna().sum())
        positives = int(group["outcome_label"].eq(True).sum())
        summary_rows.append(
            {
                "decision_time": cutoff,
                "population_cves": len(group),
                "published_before_cutoff_cves": int(
                    group["outcome_status"].ne("not_published_at_cutoff").sum()
                ),
                "labeled_at_risk_cves": eligible,
                "positive_within_horizon_cves": positives,
                "negative_full_horizon_cves": int(group["outcome_label"].eq(False).sum()),
                "unlabeled_cves": len(group) - eligible,
                "status_counts_json": json.dumps(counts, sort_keys=True),
            }
        )
    return outcomes, pd.DataFrame(summary_rows)


def run(
    manifest_path: Path,
    kev_path: Path,
    output_dir: Path,
    *,
    cutoffs: tuple[str, ...] = DEFAULT_CUTOFFS,
    horizon_days: int = 30,
) -> None:
    manifest_path, kev_path, output_dir = map(Path, (manifest_path, kev_path, output_dir))
    targets = [
        output_dir / "kev_outcomes_by_cutoff.csv",
        output_dir / "kev_outcome_coverage.csv",
        output_dir / "kev_label_provenance.json",
        output_dir / "kev_label_readiness_report.md",
    ]
    existing = [str(path) for path in targets if path.exists()]
    if existing:
        raise FileExistsError(f"Refusing to overwrite existing output(s): {existing}")
    joined, provenance = _read_sources(manifest_path, kev_path)
    outcomes, summary = analyze_labels(
        joined,
        cutoffs=cutoffs,
        horizon_days=horizon_days,
        catalog_as_of=provenance["date_released"],
    )
    output_dir.mkdir(parents=True, exist_ok=True)
    outcomes.to_csv(targets[0], index=False)
    summary.to_csv(targets[1], index=False)
    metadata = {
        **provenance,
        "manifest_file": str(manifest_path),
        "manifest_rows": len(joined),
        "cutoffs_utc": [_utc(cutoff).isoformat() for cutoff in cutoffs],
        "horizon_days": horizon_days,
        "target_definition": "CISA KEV catalog addition by dateAdded within the future horizon.",
        "date_only_semantics": (
            "dateAdded is interpreted as 00:00 UTC; an addition at the decision timestamp "
            "is already listed."
        ),
        "not_a_model_evaluation": True,
        "graph_feature_warning": (
            "No cutoff-specific graph feature join is performed; current-snapshot features "
            "are not treated as historical features."
        ),
        "epss_available": False,
        "proposal_definition_verified": False,
        "outcome_rows": len(outcomes),
    }
    targets[2].write_text(json.dumps(metadata, indent=2) + "\n", encoding="utf-8")
    rendered_summary = summary.to_string(index=False)
    report = f"""# Component C KEV Outcome-Label Readiness

This is a label-availability analysis, not a model evaluation or a production target policy.

- Outcome: CISA KEV catalogue addition (dateAdded).
- Catalog version/date released: {provenance["catalog_version"]} / {provenance["date_released"]}.
- Source rows: {provenance["vulnerability_rows"]}; unique CVEs: {joined["cve_id"].nunique()}.
- SHA-256: {provenance["sha256"]}.
- Exploratory horizon: {horizon_days} days.
- Date-only dateAdded is interpreted at 00:00 UTC; an addition at the cutoff is already in KEV.
- A negative requires the entire horizon to be observed by dateReleased.
- CVEs published at or after a cutoff, already in KEV, or right-censored remain unlabeled.
- The catalog began on 2021-11-03; earlier cutoffs are not labelable from this source.

## Cutoff coverage

{rendered_summary}

## Limits

This output does not join Component C graph features. The existing full-snapshot graph
was built from NVD state around 2026-10-15 and cannot serve as historical input for
these earlier cutoffs. Local EPSS is absent. The proposal PDF and exact missed-risk
rule are not available in the workspace. This report establishes label coverage only;
it does not satisfy chronological evaluation, compare baselines, or identify
missed-risk cases.
"""
    targets[3].write_text(report, encoding="utf-8")


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--manifest",
        type=Path,
        default=Path("data/processed/c_graph/research_population.csv"),
    )
    parser.add_argument("--kev", type=Path, required=True)
    parser.add_argument("--output-dir", type=Path, required=True)
    parser.add_argument("--horizon-days", type=int, default=30)
    parser.add_argument("--cutoff", action="append", dest="cutoffs")
    args = parser.parse_args()
    run(
        args.manifest,
        args.kev,
        args.output_dir,
        cutoffs=tuple(args.cutoffs) if args.cutoffs else DEFAULT_CUTOFFS,
        horizon_days=args.horizon_days,
    )


if __name__ == "__main__":
    main()
