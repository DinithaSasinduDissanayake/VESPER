"""Run the daily knapsack plan from a ranked Component D CSV."""

from __future__ import annotations

import argparse
import csv
from pathlib import Path

import pandas as pd

from vesper.components.d_fusion.knapsack import PatchCandidate, build_patch_plan
from vesper.config import load_settings


def main() -> None:
    settings = load_settings()
    parser = argparse.ArgumentParser(
        description=(
            "Create a daily patch plan using a clearly labeled equal-effort "
            "assumption for demonstration"
        )
    )
    parser.add_argument(
        "--ranking",
        type=Path,
        default=settings.outputs / "d_fusion" / "ranked_vulnerabilities.csv",
    )
    parser.add_argument(
        "--output",
        type=Path,
        default=settings.outputs / "d_fusion" / "vesper_daily_patch_plan.csv",
    )
    parser.add_argument("--patchers", type=int, default=3)
    parser.add_argument("--hours-per-patcher", type=float, default=6.0)
    parser.add_argument(
        "--assumed-patch-hours",
        type=float,
        default=1.0,
        help="Equal effort assigned to every CVE for demonstration only",
    )
    parser.add_argument("--business-criticality", type=int, choices=(1, 2, 3), default=1)
    args = parser.parse_args()

    if args.patchers < 1 or args.hours_per_patcher <= 0:
        parser.error("patchers and hours-per-patcher must be positive")
    if args.assumed_patch_hours <= 0:
        parser.error("assumed-patch-hours must be positive")
    if not args.ranking.is_file():
        parser.error(f"Ranking CSV not found: {args.ranking}")

    ranking = pd.read_csv(args.ranking, dtype={"cve_id": "string"}, low_memory=False)
    required = {"cve_id", "risk_score"}
    missing = required.difference(ranking.columns)
    if missing:
        parser.error(f"Ranking CSV is missing columns: {sorted(missing)}")
    if ranking["cve_id"].isna().any() or ranking["cve_id"].duplicated().any():
        parser.error("Ranking CSV must have one non-empty row per CVE ID")
    ranking["risk_score"] = pd.to_numeric(ranking["risk_score"], errors="raise")
    if ranking["risk_score"].isna().any() or not ranking["risk_score"].between(0, 1).all():
        parser.error("Ranking risk_score values must be present and between 0 and 1")
    if "risk_rank" in ranking:
        ranks = pd.to_numeric(ranking["risk_rank"], errors="raise")
    else:
        ranks = pd.Series(range(1, len(ranking) + 1), index=ranking.index)

    candidates = [
        PatchCandidate(
            cve_id=str(row.cve_id),
            risk_score=float(row.risk_score),
            model_rank=int(row.model_rank),
            patch_hours=args.assumed_patch_hours,
            business_criticality=args.business_criticality,
        )
        for row in pd.DataFrame(
            {"cve_id": ranking["cve_id"], "risk_score": ranking["risk_score"], "model_rank": ranks}
        ).itertuples(index=False)
    ]
    plan = build_patch_plan(
        candidates,
        patchers=args.patchers,
        hours_per_patcher=args.hours_per_patcher,
    )
    planned = sorted((*plan.scheduled, *plan.deferred), key=lambda item: item.model_rank)

    args.output.parent.mkdir(parents=True, exist_ok=True)
    with args.output.open("w", newline="", encoding="utf-8") as output_file:
        writer = csv.DictWriter(
            output_file,
            fieldnames=(
                "cve_id",
                "model_rank",
                "risk_score",
                "business_criticality",
                "priority_value",
                "patch_hours_assumed",
                "effort_estimate_type",
                "effort_basis",
                "scheduled_today",
                "status",
            ),
        )
        writer.writeheader()
        for item in planned:
            writer.writerow(
                {
                    "cve_id": item.cve_id,
                    "model_rank": item.model_rank,
                    "risk_score": f"{item.risk_score:.8f}",
                    "business_criticality": item.business_criticality,
                    "priority_value": f"{item.priority_value:.8f}",
                    "patch_hours_assumed": f"{args.assumed_patch_hours:.2f}",
                    "effort_estimate_type": "equal_effort_demo_assumption",
                    "effort_basis": (
                        f"Assumed {args.assumed_patch_hours:.2f} hour(s) per CVE; "
                        "not a measured patch-time estimate"
                    ),
                    "scheduled_today": "yes" if item.selected else "no",
                    "status": item.reason,
                }
            )

    print(f"Saved {len(planned)} planned CVEs to {args.output}")
    print(
        f"Selected {len(plan.scheduled)}; deferred {len(plan.deferred)}; "
        f"used {plan.used_hours:.2f}/{plan.capacity_hours:.2f} team-hours"
    )
    print(
        "Effort assumption: "
        f"{args.assumed_patch_hours:.2f} hours per CVE (demonstration only)"
    )


if __name__ == "__main__":
    main()
