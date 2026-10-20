"""Audit and estimate coverage from a completed Component C probability pilot."""

from __future__ import annotations

import argparse
import csv
import json
import math
import sys
from collections import Counter
from datetime import UTC, datetime
from pathlib import Path
from statistics import NormalDist
from typing import Any

PROJECT_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PROJECT_ROOT / "scripts"))
sys.path.insert(0, str(PROJECT_ROOT / "src"))
import download_nvd_history as downloader  # noqa: E402

from vesper.components.c_graph.historical import (  # noqa: E402
    parse_affected_events,
    parse_cpe_events,
    parse_cwe_events,
    reconstruct_relationships,
)

DEFAULT_PILOT = PROJECT_ROOT / "outputs/c_graph_probability_pilot_2026-10-16"
CUTOFF = datetime(2026, 10, 14, 23, 59, 59, 999999, tzinfo=UTC)


def read_csv(path: Path) -> list[dict[str, str]]:
    with path.open(encoding="utf-8-sig", newline="") as file:
        return list(csv.DictReader(file))


def parse_time(value: str) -> datetime:
    return downloader.parse_timestamp(value)  # type: ignore[return-value]


def score_ci(values: list[int], z: float) -> tuple[float, float]:
    """Return a Wilson score interval for one stratum's observed proportion."""
    n = len(values)
    p = sum(values) / n
    denominator = 1.0 + z * z / n
    center = (p + z * z / (2 * n)) / denominator
    radius = z * math.sqrt(p * (1 - p) / n + z * z / (4 * n * n)) / denominator
    return max(0.0, center - radius), min(1.0, center + radius)


def stratified_estimate(
    outcomes: dict[str, list[int]],
    stratum_sizes: dict[str, int],
    alpha: float = 0.05,
) -> dict[str, Any]:
    """Estimate a population proportion with stratified SRS and interval bounds.

    Point/SE use the standard stratified SRS estimator with finite population
    correction. The reported CI aggregates Bonferroni-adjusted Wilson intervals
    across strata; these score intervals are approximate and conservative for
    the small per-stratum sample, with the finite population correction omitted.
    """
    population_total = sum(stratum_sizes.values())
    point = 0.0
    variance = 0.0
    z = NormalDist().inv_cdf(1 - alpha / (2 * len(outcomes)))
    ci_lower = 0.0
    ci_upper = 0.0
    stratum_values: dict[str, dict[str, float | int]] = {}
    for stratum, values in outcomes.items():
        nh = len(values)
        Nh = stratum_sizes[stratum]
        weight = Nh / population_total
        ph = sum(values) / nh
        point += weight * ph
        if nh > 1:
            variance += weight * weight * (1 - nh / Nh) * ph * (1 - ph) / (nh - 1)
        lower, upper = score_ci(values, z)
        ci_lower += weight * lower
        ci_upper += weight * upper
        stratum_values[stratum] = {"sample_n": nh, "population_N": Nh, "sample_rate": ph}
    standard_error = math.sqrt(variance)
    return {
        "estimate": point,
        "standard_error_stratified_srs": standard_error,
        "normal_95_ci": [
            max(0.0, point - 1.96 * standard_error),
            min(1.0, point + 1.96 * standard_error),
        ],
        "95_ci_bonferroni_wilson": [ci_lower, ci_upper],
        "ci_method": (
            "Bonferroni-adjusted Wilson score intervals within 13 strata, aggregated by "
            "population shares; approximate, finite-population correction omitted."
        ),
        "strata": stratum_values,
    }


def filter_history_to_cutoff(history: dict[str, Any], cutoff: datetime) -> dict[str, Any]:
    """Return a validated-response-shaped copy containing only pre-cutoff events."""
    filtered = dict(history)
    changes = [
        item for item in history["cveChanges"] if parse_time(item["change"]["created"]) <= cutoff
    ]
    filtered.pop("vesperPagination", None)
    filtered["cveChanges"] = changes
    filtered["startIndex"] = 0
    filtered["resultsPerPage"] = len(changes)
    filtered["totalResults"] = len(changes)
    return filtered


def analyze(pilot_dir: Path) -> dict[str, Any]:
    sample = read_csv(pilot_dir / "sample_frame.csv")
    selection = json.loads((pilot_dir / "selection_metadata.json").read_text(encoding="utf-8"))
    download = json.loads(
        (pilot_dir / "histories" / "download_report.json").read_text(encoding="utf-8")
    )
    pipeline = json.loads(
        (pilot_dir / "reconstruction/window_end/features.metadata.json").read_text(encoding="utf-8")
    )
    feature_rows = read_csv(pilot_dir / "reconstruction/window_end/features.csv")
    exclusions = read_csv(pilot_dir / "reconstruction/window_end/features.exclusions.csv")
    feature_ids = {row["cve_id"] for row in feature_rows}
    exclusion_reasons = {row["cve_id"]: row["reason"].split(";") for row in exclusions}
    sample_ids = {row["cve_id"] for row in sample}
    feature_eligible_ids = sample_ids - set(exclusion_reasons)
    events_by_state: Counter[str] = Counter()
    affected_era_events: dict[str, Counter[str]] = {}
    affected_era_cves: dict[str, dict[str, set[str]]] = {}
    cpe_ids: set[str] = set()
    cwe_ids: set[str] = set()
    embedded_ids: set[str] = set()
    link_ids: set[str] = set()
    uncertain_ids: set[str] = set()
    valid_empty: set[str] = set()
    eventful: set[str] = set()
    reconstruction_ok: set[str] = set()
    response_valid: set[str] = set()
    post_cutoff_events = 0
    pre_cutoff_event_count = 0
    rows_by_id: dict[str, dict[str, str]] = {}
    temporal_check_ids: list[str] = []
    event_count_total = 0

    for row in sample:
        cve_id = row["cve_id"]
        published = parse_time(row["published"])
        if published > CUTOFF:
            raise ValueError(f"Publication-time cutoff defect for {cve_id}")
        path = pilot_dir / "histories" / f"{cve_id}.json"
        history = downloader.load_saved_history(path)
        if history is None:
            continue
        response_valid.add(cve_id)
        rows_by_id[cve_id] = row
        event_count = len(history["cveChanges"])
        event_count_total += event_count
        if event_count == 0:
            valid_empty.add(cve_id)
        else:
            eventful.add(cve_id)

        for item in history["cveChanges"]:
            if parse_time(item["change"]["created"]) <= CUTOFF:
                pre_cutoff_event_count += 1
            else:
                post_cutoff_events += 1

        cpe_events = [event for event in parse_cpe_events(history) if event.created_at <= CUTOFF]
        cwe_events = [event for event in parse_cwe_events(history) if event.created_at <= CUTOFF]
        all_affected_events = parse_affected_events(history)
        affected_events = [event for event in all_affected_events if event.created_at <= CUTOFF]
        if cpe_events:
            cpe_ids.add(cve_id)
        if cwe_events:
            cwe_ids.add(cve_id)
        for event in affected_events:
            events_by_state[event.evidence_state] += 1
            if event.evidence_state == "supported_embedded_affected_data":
                embedded_ids.add(cve_id)
            if event.evidence_state == "github_reference_unrecoverable":
                link_ids.add(cve_id)
        for event in all_affected_events:
            if event.created_at < datetime(2026, 6, 17, tzinfo=UTC):
                era = "before_2026-06-17"
            elif event.created_at.date() == datetime(2026, 6, 17, tzinfo=UTC).date():
                era = "2026-06-17_bulk_refresh_date"
            elif event.created_at < datetime(2026, 8, 26, tzinfo=UTC):
                era = "2026-06-18_to_2026-08-25"
            elif event.created_at <= CUTOFF:
                era = "2026-08-26_through_cutoff"
            else:
                era = "after_cutoff"
            affected_era_events.setdefault(era, Counter())[event.evidence_state] += 1
            affected_era_cves.setdefault(era, {}).setdefault(event.evidence_state, set()).add(
                cve_id
            )
        if any(
            reason.startswith("uncertain_initial_") for reason in exclusion_reasons.get(cve_id, [])
        ):
            uncertain_ids.add(cve_id)

        reconstructed = reconstruct_relationships(history, CUTOFF, cve_id=cve_id)
        reconstruction_ok.add(cve_id)
        # Independently remove every event after the cutoff and confirm it does
        # not alter the result reconstructed from the unfiltered response.
        filtered = filter_history_to_cutoff(history, CUTOFF)
        filtered_result = reconstruct_relationships(filtered, CUTOFF, cve_id=cve_id)

        def signature(result: Any) -> tuple[Any, ...]:
            return (
                result.affected,
                result.cwe_ids,
                result.feature_eligible,
                result.exclusion_reasons,
            )

        if signature(reconstructed) != signature(filtered_result):
            raise ValueError(f"Event-time cutoff defect for {cve_id}")
        temporal_check_ids.append(cve_id)

    if set(rows_by_id) != response_valid:
        raise ValueError("Response-validity reconciliation failed")
    if len(feature_ids) != len(feature_rows) or feature_ids - set(rows_by_id):
        raise ValueError("Feature rows contain duplicates or CVEs outside valid sample histories")
    if len(sample) != 130 or len({row["cve_id"] for row in sample}) != 130:
        raise ValueError("Pilot sample is not exactly 130 unique CVEs")
    if len(feature_eligible_ids) != pipeline["feature_eligible_cves"]:
        raise ValueError("Feature eligibility does not reconcile with pipeline metadata")

    stratum_sizes = {
        key: int(value) for key, value in selection["stratum_population_counts"].items()
    }
    strata = list(selection["stratum_population_counts"])
    sampled_by_stratum = {
        stratum: [row for row in sample if row["stratum"] == stratum] for stratum in strata
    }
    metrics: dict[str, set[str]] = {
        "valid_response": response_valid,
        "valid_empty_history": valid_empty,
        "history_with_events": eventful,
        "supported_cpe_evidence": cpe_ids,
        "supported_cwe_evidence": cwe_ids,
        "embedded_affected_evidence": embedded_ids,
        "link_only_affected_evidence": link_ids,
        "uncertain_initial_state": uncertain_ids,
        "reconstruction_success": reconstruction_ok,
        "feature_eligible": feature_eligible_ids,
        "usable_feature_row": feature_ids,
    }
    estimates: dict[str, Any] = {}
    for name, positive_ids in metrics.items():
        lower_outcomes: dict[str, list[int]] = {}
        upper_outcomes: dict[str, list[int]] = {}
        for stratum, stratum_sample in sampled_by_stratum.items():
            lower_values: list[int] = []
            upper_values: list[int] = []
            for row in stratum_sample:
                cve_id = row["cve_id"]
                if name == "valid_response":
                    value = int(cve_id in positive_ids)
                    lower_values.append(value)
                    upper_values.append(value)
                elif cve_id in response_valid:
                    value = int(cve_id in positive_ids)
                    lower_values.append(value)
                    upper_values.append(value)
                else:
                    lower_values.append(0)
                    upper_values.append(1)
            lower_outcomes[stratum] = lower_values
            upper_outcomes[stratum] = upper_values
        low = stratified_estimate(lower_outcomes, stratum_sizes)
        high = stratified_estimate(upper_outcomes, stratum_sizes)
        estimates[name] = {
            "observed_sample_count": len(positive_ids),
            "observed_sample_proportion": len(positive_ids) / len(sample),
            "nonresponse_sensitivity_bounds": [low["estimate"], high["estimate"]],
            "nonresponse_sensitivity_95_ci_envelope": [
                low["95_ci_bonferroni_wilson"][0],
                high["95_ci_bonferroni_wilson"][1],
            ],
            "lower_endpoint_estimate_and_ci": low,
            "upper_endpoint_estimate_and_ci": high,
        }

    dispositions = Counter(row["preexisting_history_status"] for row in sample)
    if len(response_valid) != len(sample):
        retrieval_unknown_ids = {row["cve_id"] for row in sample} - response_valid
    else:
        retrieval_unknown_ids = set()
    report = {
        "pilot_dir": str(pilot_dir),
        "selection_seed": selection["seed"],
        "sampling_design": selection["design"],
        "target_population_size": selection["manifest_unique_cves"],
        "sample_size": len(sample),
        "cutoff_utc": CUTOFF.isoformat(),
        "retrieval": {
            "selected_cves": len(sample),
            "requested_cves": download["attempted_this_run"],
            "page_requests": download["page_requests"],
            "page_request_ceiling": download["max_page_requests"],
            "retries": download["retries"],
            "elapsed_seconds": download["elapsed_seconds"],
            "api_key_configured": download["api_key_configured"],
            "downloaded_valid": download["new_responses_saved"],
            "failed": download["failed_this_run"],
            "valid_response_rate_sample": len(response_valid) / len(sample),
            "valid_response_rate_design_estimate": estimates["valid_response"][
                "nonresponse_sensitivity_bounds"
            ][0],
            "preexisting_dispositions": dict(dispositions),
            "unknown_retrieval_or_response_ids": sorted(retrieval_unknown_ids),
        },
        "response_and_evidence_counts": {
            "valid_responses": len(response_valid),
            "valid_empty_histories": len(valid_empty),
            "histories_with_events": len(eventful),
            "total_history_events": event_count_total,
            "events_at_or_before_cutoff": pre_cutoff_event_count,
            "events_after_cutoff": post_cutoff_events,
            "supported_cpe_cves": len(cpe_ids),
            "supported_cwe_cves": len(cwe_ids),
            "embedded_affected_cves": len(embedded_ids),
            "link_only_affected_cves": len(link_ids),
            "affected_event_states": dict(events_by_state),
            "affected_data_by_event_timestamp": {
                era: {
                    "event_count_by_evidence_state": dict(states),
                    "unique_cves_by_evidence_state": {
                        state: len(ids) for state, ids in affected_era_cves[era].items()
                    },
                }
                for era, states in affected_era_events.items()
            },
            "uncertain_initial_state_cves": len(uncertain_ids),
            "reconstruction_successes": len(reconstruction_ok),
            "feature_eligible_cves": pipeline["feature_eligible_cves"],
            "feature_eligible_cve_ids": len(feature_eligible_ids),
            "usable_feature_rows": len(feature_ids),
            "exclusion_reason_combinations": dict(Counter(row["reason"] for row in exclusions)),
        },
        "temporal_validation": {
            "publication_cutoff_checks_passed": len(sample),
            "event_cutoff_equivalence_checks_passed": len(temporal_check_ids),
            "post_cutoff_events_excluded_from_reconstruction": post_cutoff_events,
        },
        "weighted_estimates": estimates,
        "interpretation": {
            "nonresponse": (
                "Evidence outcomes for CVEs without a valid response remain unknown. Sensitivity "
                "bounds assign them 0 and 1 only as explicit lower/upper endpoints."
            ),
            "ci": (
                "Intervals are approximate Bonferroni-aggregated Wilson score bounds across the "
                "13 strata, with finite-population correction omitted; weighted point estimates "
                "use stratified SRS weights."
            ),
            "pilot_scope": (
                "Estimates describe this probability sample and the current conservative policy. "
                "They do not establish historical graph completeness, validate exploitation "
                "prediction, or justify policy relaxation."
            ),
        },
        "source_files": {
            "sample": str(pilot_dir / "sample_frame.csv"),
            "selection_metadata": str(pilot_dir / "selection_metadata.json"),
            "download_report": str(pilot_dir / "histories/download_report.json"),
            "feature_metadata": str(pilot_dir / "reconstruction/window_end/features.metadata.json"),
            "features": str(pilot_dir / "reconstruction/window_end/features.csv"),
            "exclusions": str(pilot_dir / "reconstruction/window_end/features.exclusions.csv"),
            "sample_outcomes": str(pilot_dir / "sample_outcomes.csv"),
        },
        "sample_outcomes": [
            {
                **row,
                "retrieval_disposition": (
                    "preexisting_valid_reused"
                    if row["preexisting_history_status"] == "valid_existing"
                    else (
                        "downloaded_valid"
                        if row["cve_id"] in response_valid
                        else "missing_or_failed"
                    )
                ),
                "response_valid": row["cve_id"] in response_valid,
                "history_event_count": (
                    len(
                        downloader.load_saved_history(
                            pilot_dir / "histories" / f"{row['cve_id']}.json"
                        )["cveChanges"]
                    )
                    if row["cve_id"] in response_valid
                    else None
                ),
                "supported_cpe": row["cve_id"] in cpe_ids,
                "supported_cwe": row["cve_id"] in cwe_ids,
                "embedded_affected": row["cve_id"] in embedded_ids,
                "link_only_affected": row["cve_id"] in link_ids,
                "uncertain_initial_state": row["cve_id"] in uncertain_ids,
                "reconstruction_success": row["cve_id"] in reconstruction_ok,
                "feature_eligible": row["cve_id"] in feature_eligible_ids,
                "usable_feature_row": row["cve_id"] in feature_ids,
                "exclusion_reason": ";".join(exclusion_reasons.get(row["cve_id"], [])),
            }
            for row in sample
        ],
    }
    return report


def render_markdown(report: dict[str, Any]) -> str:
    counts = report["response_and_evidence_counts"]
    retrieval = report["retrieval"]
    lines = [
        "# Component C probability-based historical coverage pilot",
        "",
        f"- Sample: {report['sample_size']} of {report['target_population_size']:,} CVEs.",
        f"- Seed: `{report['selection_seed']}`; stratified SRS without replacement.",
        f"- Cutoff: `{report['cutoff_utc']}`.",
        f"- Requests: {retrieval['page_requests']} page requests; {retrieval['retries']} retries; "
        f"ceiling {retrieval['page_request_ceiling']}; {retrieval['elapsed_seconds']} seconds.",
        "",
        "## Sample outcomes",
        "",
        "| Outcome | Count | Weighted estimate | Approx. 95% CI |",
        "|---|---:|---:|---:|",
    ]
    labels = {
        "valid_response": "Valid response",
        "valid_empty_history": "Valid empty history",
        "history_with_events": "History with events",
        "supported_cpe_evidence": "Supported CPE evidence",
        "supported_cwe_evidence": "Supported CWE evidence",
        "embedded_affected_evidence": "Embedded Affected evidence",
        "link_only_affected_evidence": "Link-only Affected evidence",
        "uncertain_initial_state": "Uncertain initial state",
        "reconstruction_success": "Reconstruction success",
        "feature_eligible": "Feature-eligible CVE",
        "usable_feature_row": "Usable feature row",
    }
    for key, label in labels.items():
        estimate = report["weighted_estimates"][key]
        interval = estimate["nonresponse_sensitivity_95_ci_envelope"]
        lines.append(
            f"| {label} | {estimate['observed_sample_count']} | "
            f"{estimate['nonresponse_sensitivity_bounds'][0]:.3f} | "
            f"[{interval[0]:.3f}, {interval[1]:.3f}] |"
        )
    affected_eras = report["response_and_evidence_counts"]["affected_data_by_event_timestamp"]
    era_summary = (
        "; ".join(
            f"{era}: {values['event_count_by_evidence_state']}"
            for era, values in affected_eras.items()
        )
        or "no Affected events"
    )
    lines.extend(
        [
            "",
            "## Validation and limitations",
            "",
            f"- Retrieval: {retrieval['requested_cves']} requested; "
            f"{retrieval['downloaded_valid']} downloaded and valid; "
            f"{retrieval['failed']} failed.",
            f"- Valid responses: {counts['valid_responses']}; valid-empty: "
            f"{counts['valid_empty_histories']}; with events: {counts['histories_with_events']}.",
            f"- Total events: {counts['total_history_events']}; at/before cutoff: "
            f"{counts['events_at_or_before_cutoff']}; after cutoff: "
            f"{counts['events_after_cutoff']}.",
            f"- Supported CPE/CWE CVEs: {counts['supported_cpe_cves']}/"
            f"{counts['supported_cwe_cves']}; embedded Affected: "
            f"{counts['embedded_affected_cves']}; link-only Affected: "
            f"{counts['link_only_affected_cves']}.",
            f"- Affected payload states by event-time era: {era_summary}.",
            f"- Reconstruction succeeded for {counts['reconstruction_successes']} CVEs; "
            f"feature-eligible: {counts['feature_eligible_cves']}; feature rows: "
            f"{counts['usable_feature_rows']}.",
            "- Temporal checks passed for "
            f"{report['temporal_validation']['publication_cutoff_checks_passed']} "
            f"publication timestamps and "
            f"{report['temporal_validation']['event_cutoff_equivalence_checks_passed']} "
            "event-filter comparisons.",
            "- Confidence intervals are approximate Bonferroni-aggregated Wilson score intervals "
            "across strata; the plus/minus 9.3 percentage-point design figure was preliminary "
            "and represented a worst-case "
            "normal approximation, not a guaranteed margin of error.",
            "- Any unresolved histories are treated as unknown; lower/upper sensitivity endpoints "
            "assign unknown outcomes 0/1 explicitly. No links were followed and no relationships "
            "were inferred from GitHub URLs.",
            "- This pilot does not establish complete historical graph reconstruction, nor does it "
            "support extrapolation beyond the declared finite population and frozen policy.",
            "",
            "## Selected sample",
            "",
            "The complete 130-ID draw, publication strata, selection probabilities, weights, and "
            "pre-existing-history disposition are in `sample_frame.csv`.",
            "",
        ]
    )
    return "\n".join(lines)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--pilot-dir", type=Path, default=DEFAULT_PILOT)
    args = parser.parse_args()
    report = analyze(args.pilot_dir)
    json_path = args.pilot_dir / "pilot_report.json"
    markdown_path = args.pilot_dir / "pilot_report.md"
    json_path.write_text(json.dumps(report, indent=2), encoding="utf-8")
    markdown_path.write_text(render_markdown(report), encoding="utf-8")
    outcomes = report["sample_outcomes"]
    outcome_path = args.pilot_dir / "sample_outcomes.csv"
    with outcome_path.open("w", encoding="utf-8", newline="") as file:
        columns = list(outcomes[0])
        writer = csv.DictWriter(file, fieldnames=columns)
        writer.writeheader()
        writer.writerows(outcomes)
    print(json.dumps(report["response_and_evidence_counts"], indent=2))
    print(json.dumps(report["weighted_estimates"], indent=2))


if __name__ == "__main__":
    main()
