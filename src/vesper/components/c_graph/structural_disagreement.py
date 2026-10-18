"""Current-snapshot structural/scalar disagreement, without predictive claims."""

from __future__ import annotations

import json
import math
from collections import defaultdict
from typing import Any

import pandas as pd

from vesper.components.c_graph.feature_provider import (
    FEATURE_PROVIDER_COLUMNS,
    normalize_timestamp,
    validate_feature_provider,
)
from vesper.components.c_graph.score_export import SCORE_COLUMNS

RULES = {"A": (0.90, 0.50), "B": (0.75, 0.50), "C": (0.75, 0.25)}
DIMENSIONS = ("degree", "pagerank")
ADAPTER_MODEL_VERSION = "c_graph-pagerank-percentile-structural-0.2"


def build_real_scores(provider: pd.DataFrame, metadata: dict[str, Any]) -> pd.DataFrame:
    """Percentile-rank available validated PageRank; preserve all other states."""
    validate_feature_provider(provider, reference_timestamp=metadata["reference_timestamp"])
    for field in ("snapshot_id", "graph_scope_id", "feature_schema_version"):
        if not provider[field].astype(str).eq(str(metadata[field])).all():
            raise ValueError(f"Provider {field} disagrees with metadata")
    if metadata.get("historical_reconstruction") != "not_performed":
        raise ValueError("This adapter requires the declared current snapshot")
    if metadata.get("feature_provider_columns") != FEATURE_PROVIDER_COLUMNS:
        raise ValueError("Metadata feature-provider schema does not match")
    reference = normalize_timestamp(metadata["reference_timestamp"])
    if metadata["snapshot_id"] != f"nvd-current-snapshot-{reference.date().isoformat()}":
        raise ValueError("snapshot_id does not identify the reference date")
    if not metadata["graph_scope_id"].startswith(metadata["snapshot_id"] + "-graph-"):
        raise ValueError("graph_scope_id does not identify this snapshot graph")
    declared_horizon = metadata.get("horizon_days")
    if declared_horizon is not None and not provider["horizon_days"].eq(declared_horizon).all():
        raise ValueError("Provider horizon disagrees with metadata")
    if provider["trained_through"].notna().any():
        raise ValueError("The untrained structural adapter requires blank trained_through")
    if provider["model_version"].astype(str).str.contains("synthetic|dummy", case=False).any():
        raise ValueError("Synthetic inputs are not real Component C results")
    result = provider[SCORE_COLUMNS].copy()
    available = result["status"].eq("available")
    result["score"] = float("nan")
    result.loc[available, "score"] = percentile(provider.loc[available, "pagerank"])
    result["model_version"] = ADAPTER_MODEL_VERSION
    return result.sort_values("cve_id", kind="stable").reset_index(drop=True)


def percentile(values: pd.Series) -> pd.Series:
    """Average tied ascending ranks, normalized as (rank - 1)/(N - 1)."""
    numeric = pd.to_numeric(values, errors="coerce")
    if numeric.isna().any() or not numeric.map(math.isfinite).all():
        raise ValueError("Percentiles require finite observed values")
    if not len(values):
        return pd.Series(index=values.index, dtype=float)
    if len(values) == 1:
        return pd.Series(0.5, index=values.index)
    return (numeric.rank(method="average") - 1) / (len(values) - 1)


def analyze_disagreement(
    provider: pd.DataFrame, cvss: pd.DataFrame, *, graph_nodes: int
) -> pd.DataFrame:
    """Use one complete-case population for every descriptive percentile.

    Degree is observed incoming product plus outgoing CWE edge count. Both
    evidence layers are required here; adapter availability remains a separate
    existing contract decision. KEV is neither an input nor a selection field.
    """
    if graph_nodes < 2 or isinstance(graph_nodes, bool):
        raise ValueError("The saved graph must have at least two nodes")
    if provider["cve_id"].duplicated().any() or cvss["cve_id"].duplicated().any():
        raise ValueError("Duplicate CVEs cannot define a common analysis population")
    needed = ["cve_id", "cvss_base_score", "cvss_version", "cvss_severity"]
    result = provider.merge(cvss[needed], on="cve_id", how="left", validate="one_to_one")
    score = pd.to_numeric(result["cvss_base_score"], errors="coerce")
    invalid = score.notna() & (~score.between(0, 10) | ~score.map(math.isfinite))
    if invalid.any():
        raise ValueError("Observed CVSS scores must be finite and in [0,10]")
    result["cvss_base_score"] = score
    result["analysis_status"] = "available"
    result["analysis_reason"] = ""
    missing_cvss = score.isna()
    result.loc[missing_cvss, ["analysis_status", "analysis_reason"]] = [
        "unavailable",
        "no_compatible_current_cvss_score",
    ]
    missing_evidence = ~result["cpe_evidence_status"].eq("supported") | ~result[
        "cwe_evidence_status"
    ].eq("supported")
    result.loc[missing_evidence, ["analysis_status", "analysis_reason"]] = [
        "unavailable",
        "both_supported_relationship_layers_required_for_common_cohort",
    ]
    unavailable = ~result["status"].eq("available")
    result.loc[unavailable, "analysis_status"] = result.loc[unavailable, "status"]
    result.loc[unavailable, "analysis_reason"] = result.loc[unavailable, "reason"]
    eligible = result["analysis_status"].eq("available")
    structural_columns = ["in_degree_centrality", "out_degree_centrality", "pagerank"]
    observed = result.loc[eligible, structural_columns].apply(pd.to_numeric, errors="coerce")
    if observed.isna().any().any() or not observed.ge(0).all().all():
        raise ValueError("Eligible graph features must be observed and nonnegative")
    if not observed.le(1).all().all():
        raise ValueError("Eligible graph features must be finite and in [0,1]")
    raw_degree = (observed["in_degree_centrality"] + observed["out_degree_centrality"]) * (
        graph_nodes - 1
    )
    degree = raw_degree.round()
    if (raw_degree - degree).abs().gt(1e-6).any():
        raise ValueError("Degree normalization disagrees with saved graph node count")
    for column in (
        "degree",
        "P_degree",
        "P_pagerank",
        "P_cvss",
        "degree_cvss_disagreement",
        "pagerank_cvss_disagreement",
    ):
        result[column] = float("nan")
    result.loc[eligible, "degree"] = degree
    for target, values in (
        ("P_degree", degree),
        ("P_pagerank", observed["pagerank"]),
        ("P_cvss", score.loc[eligible]),
    ):
        result.loc[eligible, target] = percentile(values)
    for dimension in DIMENSIONS:
        result.loc[eligible, dimension + "_cvss_disagreement"] = (
            result.loc[eligible, "P_" + dimension] - result.loc[eligible, "P_cvss"]
        )
    result["structural_score"] = result["score"]
    return result.sort_values("cve_id", kind="stable").reset_index(drop=True)


def ranked_candidates(frame: pd.DataFrame, dimension: str = "pagerank") -> pd.DataFrame:
    if dimension not in DIMENSIONS:
        raise ValueError("Unknown structural dimension")
    result = (
        frame[frame["analysis_status"].eq("available")]
        .sort_values(
            [dimension + "_cvss_disagreement", "cve_id"],
            ascending=[False, True],
            kind="stable",
        )
        .copy()
    )
    result["disagreement_rank"] = range(1, len(result) + 1)
    return result.reset_index(drop=True)


def sensitivity(frame: pd.DataFrame) -> tuple[pd.DataFrame, pd.DataFrame, dict[str, set[str]]]:
    """Apply fixed rules independently for degree and PageRank; no combined score."""
    eligible = frame[frame["analysis_status"].eq("available")]
    sets = {}
    rows = []
    for dimension in DIMENSIONS:
        for rule, (graph_min, cvss_max) in RULES.items():
            name = f"{dimension}_{rule}"
            mask = eligible["P_" + dimension].ge(graph_min) & eligible["P_cvss"].lt(cvss_max)
            sets[name] = set(eligible.loc[mask, "cve_id"])
            rows.append(
                {
                    "definition": name,
                    "dimension": dimension,
                    "rule": rule,
                    "structural_percentile_min_inclusive": graph_min,
                    "cvss_percentile_max_exclusive": cvss_max,
                    "candidate_count": len(sets[name]),
                }
            )
    overlaps = []
    for left in sets:
        for right in sets:
            if left >= right:
                continue
            intersection, union = sets[left] & sets[right], sets[left] | sets[right]
            overlaps.append(
                {
                    "left": left,
                    "right": right,
                    "intersection": len(intersection),
                    "union": len(union),
                    "jaccard": len(intersection) / len(union) if union else None,
                }
            )
    return pd.DataFrame(rows), pd.DataFrame(overlaps), sets


def annotate_kev(
    frame: pd.DataFrame, catalog: dict[str, Any]
) -> tuple[pd.DataFrame, dict[str, str]]:
    """Post-selection membership in the frozen current catalog, never a score input."""
    released = normalize_timestamp(catalog["dateReleased"])
    added = {}
    records = catalog["vulnerabilities"]
    if len(records) != catalog["count"]:
        raise ValueError("KEV catalog count mismatch")
    for record in records:
        cve = record["cveID"]
        stamp = pd.Timestamp(record["dateAdded"], tz="UTC")
        if cve in added or stamp > released:
            raise ValueError("Duplicate or post-release KEV record")
        added[cve] = record["dateAdded"]
    result = frame.copy()
    result["kev_catalog_member"] = result["cve_id"].isin(added)
    result["kev_date_added"] = result["cve_id"].map(added)
    result["kev_annotation_state"] = result["kev_catalog_member"].map(
        {True: "listed_in_saved_current_catalog", False: "not_listed_in_saved_current_catalog"}
    )
    result["kev_catalog_as_of"] = released.isoformat()
    return result, added


def enrichment(frame: pd.DataFrame, cohorts: dict[str, set[str]]) -> pd.DataFrame:
    eligible = frame[frame["analysis_status"].eq("available")]
    by_id = eligible.set_index("cve_id")
    base = float(eligible["kev_catalog_member"].mean()) if len(eligible) else None
    rows = []
    for name, ids in cohorts.items():
        if not ids.issubset(by_id.index):
            raise ValueError("Annotation cohorts must be subsets of the fixed eligible population")
        members = int(by_id.loc[sorted(ids), "kev_catalog_member"].sum()) if ids else 0
        prevalence = members / len(ids) if ids else None
        rows.append(
            {
                "cohort": name,
                "candidate_count": len(ids),
                "catalog_members": members,
                "candidate_kev_prevalence": prevalence,
                "eligible_population_count": len(eligible),
                "eligible_population_catalog_members": int(eligible["kev_catalog_member"].sum()),
                "eligible_population_kev_prevalence": base,
                "descriptive_enrichment_ratio": prevalence / base
                if prevalence is not None and base
                else None,
                "interpretation": (
                    "CURRENT-SNAPSHOT DESCRIPTIVE ENRICHMENT; not predictive performance"
                ),
            }
        )
    return pd.DataFrame(rows)


def concentrations(frame: pd.DataFrame, cohorts: dict[str, set[str]], layer: str) -> pd.DataFrame:
    """Count unique candidate CVEs per observed product, vendor or CWE."""
    if layer not in {"product", "vendor", "cwe"}:
        raise ValueError("Unknown explanation layer")
    rows = []
    field = "cwe_ids_json" if layer == "cwe" else "vendor_product_evidence_json"
    for cohort, ids in cohorts.items():
        members = defaultdict(set)
        for row in frame.loc[frame["cve_id"].isin(ids), ["cve_id", field]].itertuples(index=False):
            raw = row[1]
            if not isinstance(raw, str) or not raw:
                continue
            for value in json.loads(raw):
                key = value if layer == "cwe" else value[0] if layer == "vendor" else tuple(value)
                members[key].add(row.cve_id)
        for key, cves in sorted(members.items(), key=lambda item: (-len(item[1]), item[0])):
            rows.append(
                {
                    "cohort": cohort,
                    "entity": "/".join(key) if isinstance(key, tuple) else key,
                    "cve_count": len(cves),
                    "candidate_count": len(ids),
                    "candidate_share": len(cves) / len(ids),
                    "cve_ids": json.dumps(sorted(cves), separators=(",", ":")),
                }
            )
    return pd.DataFrame(
        rows,
        columns=["cohort", "entity", "cve_count", "candidate_count", "candidate_share", "cve_ids"],
    )
