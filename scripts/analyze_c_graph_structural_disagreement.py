"""Offline current-snapshot disagreement and real shared-Score adapter for C."""

from __future__ import annotations

import argparse
import hashlib
import importlib.metadata
import json
import sys
from pathlib import Path

import matplotlib

matplotlib.use("Agg")
import matplotlib.pyplot as plt
import pandas as pd

sys.path.insert(0, str(Path(__file__).resolve().parent))
from analyze_c_graph_cvss_clusters import _cvss_details  # noqa: E402

from vesper.components.c_graph.feature_provider import normalize_timestamp  # noqa: E402
from vesper.components.c_graph.nvd_parser import _parse_timestamp  # noqa: E402
from vesper.components.c_graph.pipeline import discover_monthly_files, read_month  # noqa: E402
from vesper.components.c_graph.structural_disagreement import (  # noqa: E402
    analyze_disagreement,
    annotate_kev,
    build_real_scores,
    concentrations,
    enrichment,
    ranked_candidates,
    sensitivity,
)

DEFAULT_PROVIDER = Path(
    "outputs/c_graph_feature_provider_2026-10-17_run2/c_graph_feature_provider.csv"
)
DEFAULT_OUTPUT = Path("outputs/c_graph_structural_scalar_disagreement_2026-10-17_run1")
EXISTING_CLUSTERS = Path("outputs/c_graph_cvss_cluster_exploration_2026-10-16_run3")


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as source:
        for block in iter(lambda: source.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def read_current_cvss(
    provider: pd.DataFrame, metadata: dict, nvd_dir: Path
) -> tuple[pd.DataFrame, dict[str, str]]:
    """Read the same hash-verified NVD records; never restrict severity."""
    records = provider.set_index("cve_id")
    reference = normalize_timestamp(metadata["reference_timestamp"])
    expected_hashes = metadata["source_provenance"]["local_nvd_monthly_files_sha256"]
    files = discover_monthly_files(nvd_dir)
    if {p.name for _, p in files} != set(expected_hashes):
        raise ValueError("Monthly input file set differs from the validated provider")
    seen, rows, hashes = set(), [], {}
    for index, (_, path) in enumerate(files, 1):
        hashes[path.name] = sha256(path)
        if hashes[path.name] != expected_hashes[path.name]:
            raise ValueError(f"NVD source hash changed: {path}")
        for envelope in read_month(path):
            record = envelope.get("cve", {})
            cve = record.get("id")
            if cve not in records.index:
                continue
            if cve in seen:
                raise ValueError(f"Duplicate current CVE: {cve}")
            seen.add(cve)
            source = records.loc[cve]
            for raw, field in (
                (record.get("published"), "source_record_published_at"),
                (record.get("lastModified"), "source_record_last_modified_at"),
            ):
                stamp = _parse_timestamp(raw)
                if stamp > reference or stamp != normalize_timestamp(source[field]):
                    raise ValueError(f"Incompatible snapshot record: {cve} / {field}")
            if source["source_nvd_file"] != path.name:
                raise ValueError(f"Source filename disagrees for {cve}")
            rejected = str(record.get("vulnStatus", "")).strip().casefold() == "rejected"
            if rejected != (source["status"] == "not_eligible"):
                raise ValueError(f"Rejected status disagrees for {cve}")
            score, version, severity = _cvss_details(record)
            rows.append(
                {
                    "cve_id": cve,
                    "cvss_base_score": score,
                    "cvss_version": version,
                    "cvss_severity": severity,
                }
            )
        if index % 12 == 0 or index == len(files):
            print(f"Read compatible current CVSS inputs: {index}/{len(files)} files", flush=True)
    if seen != set(records.index):
        raise ValueError("Some provider CVEs have no compatible current NVD record")
    return pd.DataFrame(rows), hashes


def figures(
    frame: pd.DataFrame, top: pd.DataFrame, products: pd.DataFrame, cwes: pd.DataFrame, output: Path
) -> None:
    plt.rcParams["svg.hashsalt"] = "vesper-c-structural-disagreement-v1"

    def save(fig, name):
        fig.savefig(output / (name + ".png"), dpi=180)
        fig.savefig(output / (name + ".svg"), metadata={"Date": None})
        plt.close(fig)

    eligible = frame[frame["analysis_status"].eq("available")]
    fig, axes = plt.subplots(1, 2, figsize=(14, 6), layout="constrained")
    for ax, dimension in zip(axes, ("degree", "pagerank"), strict=True):
        if len(eligible):
            cells = ax.hexbin(
                eligible["P_cvss"],
                eligible["P_" + dimension],
                gridsize=50,
                extent=(0, 1, 0, 1),
                mincnt=1,
                bins="log",
            )
            fig.colorbar(cells, ax=ax, label="CVE count (log color scale)")
        ax.plot([0, 1], [0, 1], color="gray", linewidth=1)
        ax.set(
            xlabel="Current CVSS percentile",
            ylabel=f"{dimension.title()} percentile",
            xlim=(0, 1),
            ylim=(0, 1),
        )
    fig.suptitle(
        f"Current-snapshot structural/scalar comparison; N={len(eligible):,}\n"
        "Common complete-case cohort; descriptive, not exploitation prediction"
    )
    save(fig, "structural_vs_cvss")

    shown = top.head(25).iloc[::-1]
    fig, ax = plt.subplots(figsize=(11, 10), layout="constrained")
    ax.barh(shown["cve_id"], shown["pagerank_cvss_disagreement"], color="#355f8d")
    ax.set(
        xlabel="PageRank percentile minus CVSS percentile",
        title="Top current-snapshot disagreement cases (up to 25)\nNot exploitation risk",
    )
    save(fig, "top_disagreement")

    fig, axes = plt.subplots(1, 2, figsize=(17, 7), layout="constrained")
    for ax, table, label in zip(axes, (products, cwes), ("Vendor/product", "CWE"), strict=True):
        shown = table[table["cohort"].eq("top50_pagerank")].head(10).iloc[::-1]
        labels = shown["entity"].map(
            lambda value: value if len(value) <= 65 else value[:62] + "..."
        )
        ax.barh(labels, shown["cve_count"], color="#287c8e")
        ax.set(xlabel="Distinct candidate CVEs", ylabel=label)
    fig.suptitle(
        "Concentrations among primary Top 50 disagreement cases\n"
        "Observed graph evidence; overlapping memberships; not exploitation risk"
    )
    save(fig, "product_cwe_concentration")


def run(provider_path: Path, nvd_dir: Path, kev_path: Path, output: Path) -> dict:
    if output.exists():
        raise FileExistsError(f"Refusing to overwrite output: {output}")
    metadata_path = provider_path.with_suffix(".metadata.json")
    metadata = json.loads(metadata_path.read_text(encoding="utf-8"))
    full = metadata["source_provenance"]["full_graph_features"]
    full_path, full_metadata_path = Path(full["path"]), Path(full["metadata_path"])
    previous_candidates = EXISTING_CLUSTERS / "cvss_high_critical_candidates.csv"
    protected_paths = [
        provider_path,
        metadata_path,
        full_path,
        full_metadata_path,
        previous_candidates,
        EXISTING_CLUSTERS / "analysis_metadata.json",
        EXISTING_CLUSTERS / "product_weakness_cluster_edges.csv",
        EXISTING_CLUSTERS / "cvss_product_weakness_clusters.png",
    ]
    protected = {str(path): sha256(path) for path in protected_paths}
    if protected[str(provider_path)] != metadata["output_sha256"]:
        raise ValueError("Provider checksum disagrees with saved metadata")
    if protected[str(full_path)] != full["sha256"]:
        raise ValueError("Full graph feature checksum disagrees with provider scope")
    provider = pd.read_csv(provider_path)
    print("Validating the saved 31-column provider without regenerating it", flush=True)
    adapter = build_real_scores(provider, metadata)
    print(
        f"Validated existing provider and graph-only Score adapter: {len(adapter):,} rows",
        flush=True,
    )
    graph_meta = json.loads(full_metadata_path.read_text(encoding="utf-8"))
    graph_nodes = sum(graph_meta["graph_summary"][k] for k in ("vendor", "product", "cve", "cwe"))
    cvss, monthly_hashes = read_current_cvss(provider, metadata, nvd_dir)
    analysis = analyze_disagreement(provider, cvss, graph_nodes=graph_nodes)
    primary, secondary = ranked_candidates(analysis), ranked_candidates(analysis, "degree")
    primary_ids_before_annotation = primary["cve_id"].tolist()
    for dimension, ordered in (("pagerank", primary), ("degree", secondary)):
        order = ordered.set_index("cve_id")["disagreement_rank"]
        analysis[dimension + "_disagreement_rank"] = analysis["cve_id"].map(order).astype("Int64")
    thresholds, overlaps, cohorts = sensitivity(analysis)
    for dimension, ordered in (("pagerank", primary), ("degree", secondary)):
        for k in (10, 25, 50):
            cohorts[f"top{k}_{dimension}"] = set(ordered.head(k)["cve_id"])

    # Membership is deliberately loaded only after all scores/candidates are fixed.
    catalog = json.loads(kev_path.read_text(encoding="utf-8"))
    analysis, _ = annotate_kev(analysis, catalog)
    prior_ids = set(pd.read_csv(previous_candidates, usecols=["cve_id"])["cve_id"])
    analysis["in_previous_high_critical_candidates"] = analysis["cve_id"].isin(prior_ids)
    primary, secondary = ranked_candidates(analysis), ranked_candidates(analysis, "degree")
    if primary["cve_id"].tolist() != primary_ids_before_annotation:
        raise RuntimeError("Post-selection annotation changed the primary ranking")
    top = primary.head(50).copy()
    for k in (10, 25, 50):
        top[f"in_top{k}"] = top["disagreement_rank"].le(k)
    kev = enrichment(analysis, cohorts)
    products = concentrations(analysis, cohorts, "product")
    cwes = concentrations(analysis, cohorts, "cwe")
    vendors = concentrations(analysis, cohorts, "vendor")
    output.mkdir(parents=True, exist_ok=False)
    tables = {
        "disagreement_all.csv": analysis,
        "top_disagreement.csv": top,
        "top_degree_disagreement.csv": secondary.head(50),
        "threshold_sensitivity.csv": thresholds,
        "threshold_overlap.csv": overlaps,
        "product_clusters.csv": products,
        "cwe_clusters.csv": cwes,
        "vendor_clusters.csv": vendors,
        "kev_enrichment.csv": kev,
        "c_graph_scores.csv": adapter,
    }
    for name, table in tables.items():
        table.to_csv(output / name, index=False)
    roundtrip = pd.read_csv(output / "c_graph_scores.csv")
    pd.testing.assert_frame_equal(roundtrip, adapter, check_dtype=False)
    assert len(
        adapter.merge(
            provider[["cve_id", "decision_time"]],
            on=["cve_id", "decision_time"],
            validate="one_to_one",
        )
    ) == len(provider)
    figures(analysis, top, products, cwes, output)
    input_hashes = {**protected, str(kev_path): sha256(kev_path)}
    scope = {k: metadata[k] for k in ("snapshot_id", "graph_scope_id", "reference_timestamp")}
    score_meta = {
        **scope,
        "horizon_days": int(adapter["horizon_days"].iloc[0]),
        "component": "c_graph",
        "score_kind": "ranking_score",
        "model_version": sorted(adapter["model_version"].unique().tolist()),
        "columns": adapter.columns.tolist(),
        "rows": len(adapter),
        "status_counts": adapter["status"].value_counts().to_dict(),
        "definition": (
            "Relative PageRank structural percentile = (average_rank(pagerank)-1)/(N-1); "
            "available provider rows only; no scalar inputs"
        ),
        "interpretation": "RELATIVE GRAPH STRUCTURAL IMPORTANCE; not exploitation probability",
        "horizon_semantics": "Shared interface field, not a trained 30-day prediction target",
        "availability_semantics": (
            "Preserves provider score statuses and blanks. Layer completeness is "
            "separate; join original provider evidence statuses."
        ),
        "percentile_population": int(adapter["status"].eq("available").sum()),
        "source_provider": str(provider_path),
        "source_provider_sha256": protected[str(provider_path)],
        "output_sha256": sha256(output / "c_graph_scores.csv"),
        "shared_score_dataclass_compatibility": "all rows valid; round trip and key join passed",
        "d_loader_compatibility": (
            "UNVERIFIED: requested dummy_inputs README, fixtures and D loader absent;"
            " package stub only"
        ),
        "d_fixture_overwritten": False,
    }
    (output / "c_graph_scores.csv.metadata.json").write_text(
        json.dumps(score_meta, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    boundaries = {}
    for k in (10, 25, 50):
        if len(primary) >= k:
            value = float(primary.iloc[k - 1]["pagerank_cvss_disagreement"])
            boundaries[str(k)] = {
                "disagreement": value,
                "total_tied_at_boundary": int(
                    primary["pagerank_cvss_disagreement"].eq(value).sum()
                ),
            }
    summary = {
        "analysis": "CURRENT-SNAPSHOT STRUCTURAL-SCALAR DISAGREEMENT; descriptive only",
        **scope,
        "provider_rows": len(provider),
        "provider_columns": len(provider.columns),
        "inspected_provider_fields": {
            "degree": ["in_degree_centrality", "out_degree_centrality"],
            "pagerank": ["pagerank", "score"],
            "existing_degree_or_pagerank_percentile_or_rank": None,
            "product_cpe": ["vendor_product_evidence_json", "cpe_evidence_status"],
            "cwe": ["cwe_ids_json", "cwe_evidence_status"],
            "availability": [
                "status",
                "reason",
                "in_degree_status",
                "out_degree_status",
                "pagerank_status",
            ],
            "identity": ["snapshot_id", "graph_scope_id", "reference_timestamp"],
            "time_and_horizon": [
                "decision_time",
                "snapshot_date",
                "horizon_days",
                "trained_through",
            ],
        },
        "eligible_analysis_cves": len(primary),
        "analysis_graph_nodes": graph_nodes,
        "eligibility": (
            "Provider available + both CPE/CWE supported + compatible numeric current"
            " CVSS, any severity"
        ),
        "excluded_by_reason": analysis.loc[
            analysis["analysis_status"].ne("available"), "analysis_reason"
        ]
        .value_counts()
        .to_dict(),
        "structural_score": score_meta["definition"],
        "percentile_formula": (
            "(average ascending rank - 1)/(N - 1), same eligible cohort for all "
            "three; singleton=0.5; ties share midrank"
        ),
        "degree_definition": (
            "Observed product in-degree plus CWE out-degree = (in_degree_centrality +"
            " out_degree_centrality)*(full_graph_nodes - 1), rounded only after "
            "integer-consistency check"
        ),
        "combined_graph_percentile": (
            "NOT CREATED: existing raw PageRank score reused; degree and PageRank "
            "rules analyzed separately"
        ),
        "primary_order": "P_pagerank - P_cvss descending, CVE ID ascending for equal differences",
        "secondary_order": "P_degree - P_cvss descending, CVE ID ascending for equal differences",
        "top_k_boundary_ties": boundaries,
        "cvss_policy": (
            "Reuse existing _cvss_details: highest available baseScore across "
            "v4/v3.1/v3.0/v2; equal-score version priority in that order; first "
            "source entry for remaining ties. No severity filtering."
        ),
        "thresholds": thresholds.to_dict(orient="records"),
        "overlap": overlaps.to_dict(orient="records"),
        "kev_annotation_as_of": catalog["dateReleased"],
        "kev_enrichment": kev.to_dict(orient="records"),
        "kev_timing_caveat": (
            "Retrospective membership in the saved current catalog, which may be "
            "released after graph reference time; never a prospective label or "
            "score/selection input."
        ),
        "top10": top.head(10)[
            [
                "cve_id",
                "cvss_base_score",
                "degree",
                "pagerank",
                "P_degree",
                "P_pagerank",
                "P_cvss",
                "pagerank_cvss_disagreement",
                "kev_catalog_member",
            ]
        ].to_dict(orient="records"),
        "top50_prior_high_critical_overlap": int(top["in_previous_high_critical_candidates"].sum()),
        "adapter": score_meta,
        "input_hashes": input_hashes,
        "monthly_nvd_sha256": monthly_hashes,
        "source_code_sha256": {
            str(p): sha256(p)
            for p in [
                Path(__file__),
                Path("src/vesper/components/c_graph/structural_disagreement.py"),
                Path("scripts/analyze_c_graph_cvss_clusters.py"),
            ]
        },
        "audit_environment": {
            p: importlib.metadata.version(p) for p in ("pandas", "networkx", "matplotlib")
        },
        "limits": [
            "No exploitation prediction, prospective validation or historical claims.",
            "Complete-case cohort is selected, not representative of all vulnerabilities.",
            (
                "Percentiles depend on the declared common cohort; centralities depend on"
                " the full graph."
            ),
            "Thresholds are descriptive rules, not universal cybersecurity cutoffs.",
            "Product/CWE membership is multi-label; concentrations can overlap.",
            "Historical evaluation limitations remain unchanged.",
            (
                "Actual D loader/fixture compatibility cannot be certified because those "
                "assets are absent."
            ),
        ],
    }
    for path, expected in protected.items():
        if sha256(Path(path)) != expected:
            raise RuntimeError(f"Protected source changed: {path}")
    summary["protected_inputs_unchanged"] = True
    (output / "summary.json").write_text(
        json.dumps(summary, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    lines = [
        "# Component C current-snapshot Structural-Scalar Disagreement Analysis",
        "",
        (
            "Relationship-aware vulnerability prioritization using CVE-product-"
            "weakness graph structure."
        ),
        (
            "This is descriptive structural importance, not exploitation probability "
            "or model performance."
        ),
        "",
        f"Common complete-case cohort: {len(primary):,} of {len(provider):,} provider CVEs.",
        summary["eligibility"],
        "",
        "## Exact score and percentile definitions",
        "",
        summary["structural_score"],
        summary["degree_definition"],
        summary["percentile_formula"],
        summary["primary_order"],
        summary["combined_graph_percentile"],
        summary["cvss_policy"],
        "",
        (
            "The D score is unchanged by CVSS availability or the analysis-cohort "
            "filter. Its original score/evidence availability dimensions remain "
            "distinct."
        ),
        "",
        "## Top cases",
        "",
        pd.DataFrame(summary["top10"]).to_string(index=False),
        "",
        (
            "Top 10/25/50 are prefixes of top_disagreement.csv, with explicit flags. "
            "Secondary degree Top 50 is separate. Boundary ties are disclosed in "
            "summary.json."
        ),
        "",
        "## Predefined sensitivity rules",
        "",
        thresholds.to_string(index=False),
        "",
        (
            "A: structural >=0.90 and CVSS <0.50; B: >=0.75 and <0.50; C: >=0.75 and "
            "<0.25. Each dimension is separate. Candidate overlaps/Jaccard stability "
            "are in threshold_overlap.csv."
        ),
        "",
        "## CURRENT-SNAPSHOT DESCRIPTIVE KEV ENRICHMENT",
        "",
        kev.to_string(index=False),
        "",
        summary["kev_timing_caveat"],
        (
            "KEV was loaded after scores, rankings and cohorts were fixed. "
            "Nonmembership means not listed in this catalog, not no exploitation. "
            "Enrichment is not accuracy, recall, AUC, lift validation or prospective "
            "prediction."
        ),
        "",
        "## Explainability and reproducibility",
        "",
        (
            "Top cases retain full existing vendor/product and CWE evidence, graph "
            "scope, scalar values and availability states. Product/vendor/CWE tables "
            "count distinct candidates per entity; multi-label shares need not sum to"
            " one."
        ),
        f"Top 50 overlap with previous HIGH/CRITICAL table: "
        f"{summary['top50_prior_high_critical_overlap']}. "
        "The prior severity-filtered table was used only for annotation, not population selection.",
        (
            "No validated graph, cluster output or detailed 31-column provider was "
            "modified. Original unavailable analysis values stay blank. Input, "
            "source-code, environment and output identities are recorded in "
            "summary.json and the adapter metadata."
        ),
        "",
        "## C to D contract",
        "",
        f"c_graph_scores.csv: {len(adapter):,} rows, exactly the existing 11 Score fields. "
        "Relative PageRank structural percentile, component=c_graph, ranking_score; "
        "original statuses. "
        "Scope identity is bound to the CSV by its sidecar checksum. "
        "horizon_days is an interface field, not training or a predictive promise.",
        score_meta["d_loader_compatibility"],
        "No synthetic fixture was overwritten and no D implementation or training was performed.",
        "",
        "## Limitations",
        "",
        *["- " + item for item in summary["limits"]],
    ]
    (output / "report.md").write_text("\n".join(lines) + "\n", encoding="utf-8")
    print(
        json.dumps(
            {
                "output": str(output),
                "eligible": len(primary),
                "adapter_rows": len(adapter),
                "thresholds": summary["thresholds"],
            },
            indent=2,
        )
    )
    return summary


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--provider", type=Path, default=DEFAULT_PROVIDER)
    parser.add_argument("--nvd-dir", type=Path, default=Path("data/raw/nvd"))
    parser.add_argument(
        "--kev",
        type=Path,
        default=Path("outputs/c_graph_kev_label_readiness_2026-10-16/kev_catalog.json"),
    )
    parser.add_argument("--output-dir", type=Path, default=DEFAULT_OUTPUT)
    args = parser.parse_args()
    run(args.provider, args.nvd_dir, args.kev, args.output_dir)


if __name__ == "__main__":
    main()
