# Component C Research-Readiness Gap Assessment

> This is the earlier assessment, retained for its original evidence record.
> Its 401-history counts and historical next-step sequence are superseded by
> [the final implementation/handoff audit](COMPONENT_C_FINAL_AUDIT.md) and
> [the established historical-readiness decision](COMPONENT_C_HISTORICAL_EVALUATION_READINESS.md).
> The current local corpus has 499 histories; collection is stopped. Unavailable
> historical evaluation is an evidence/protocol limitation, not an implementation
> failure or authorization for further acquisition.

- **Branch reviewed:** `c-graph/complete-pipeline`
- **Assessment basis:** repository code, current documentation, saved reports and
outputs. The original proposal and Topic Assessment Form PDFs are not present
in this worktree. A prior repository report also records that those PDFs were
not available locally (`outputs/c_graph_cvss_cluster_exploration_2026-10-16_run3/completion_report.md`).
Accordingly, the C1–C9 labels below organize the nine Component C requirement
areas previously summarized in repository reviews; they are not claimed to be
verbatim proposal milestone titles. Exact proposal-specific definitions,
thresholds, and evaluation metrics still require checking against the original
documents.

## Overall verdict

**Component C is implementation-complete for a full current-record snapshot
graph and documentation-ready for a Component D handoff. It is not research-
complete.** Current-state construction, structural scoring, a bounded runtime
benchmark, temporal replay code/tests, KEV label-readiness outputs, exploratory
clusters, and a versioned Score-compatible provider are present. These do not
establish population-wide point-in-time relationship states, predictive
performance, the proposal's missed-risk result, or actual Component D
integration.

## C1–C9 requirement matrix

| ID / requirement area | Status | Evidence of completion | Gap and smallest justified next action |
| --- | --- | --- | --- |
| **C1. NVD CPE/CWE acquisition and evidence coverage** | **Partial** | Current-snapshot inputs include 142 monthly NVD files, recorded in `outputs/c_graph_completion_sprint_2026-10-16_run1/completion_summary.md` and snapshot metadata. The history downloader validates pagination, retries, resumes, and writes atomically (`scripts/download_nvd_history.py`; offline cases in `tests/components/c_graph/test_download_nvd_history.py`). The population manifest has 333,178 CVEs (`data/processed/c_graph/research_population.csv`). The offline coverage report combines local histories and pilot directories and reports 401 distinct local histories, versus the 333,178-CVE population (`outputs/c_graph_full_population_history_coverage_2026-10-16/coverage_report.md`, `coverage_metadata.json`). | The 401 records are only a tiny fraction of the population and do not provide broad historical coverage. The monthly files are current records partitioned by publication month, not archived historical states. Preserve the existing coverage report as the baseline; next resolve the research scope/source decision before any collection expansion. |
| **C2. Relationship extraction, normalization, and graph schema** | **Partial** | `src/vesper/components/c_graph/nvd_parser.py`, `historical.py`, and `graph.py` extract supported vendor/product and CWE relationships and build namespaced, directed edges. Tests cover CPE/CWE event actions, Affected evidence, uncertainty, and preserved provenance (`tests/components/c_graph/test_historical.py`). The manual audit found 6 CPE and 7 CWE event matches and classified 6 link-only Affected events as unsupported (`outputs/c_graph_completion_sprint_2026-10-16_run1/manual_relationship_audit.csv`, described in its `completion_summary.md`). | The graph's vendor/product abstraction does not retain all CPE version ranges or logical applicability. Link-only modern Affected events have no immutable event-time record state. The manual audit is parser consistency checking, not independent validation. Next validate a bounded set of comparable historical CPE values against independent dated records; report non-comparable CPE conditions separately. |
| **C3. Full graph construction and structural feature implementation** | **Complete for the 2026-10-15 current snapshot; exploratory for historical cutoffs** | `src/vesper/components/c_graph/graph.py` builds the vendor → product → CVE → CWE `DiGraph`; `scoring.py` calculates in/out-degree centrality and PageRank. `outputs/c_graph_full_snapshot_2026-10-15/features.metadata.json` and `outputs/c_graph_completion_sprint_2026-10-16_run1/completion_summary.md` record 538,775 nodes and 1,779,076 edges for the current snapshot. The provider export contains 333,178 unique manifest CVEs. A symmetric three-CVE cycle has hand-calculated centralities and PageRank (`tests/components/c_graph/test_scoring.py`). | Correct implementation on tested graphs does not establish correctness of every parsed relationship or historical graph state. The cutoff pilot is only a saved 130-CVE sample. Keep current-state and historical claims separate; do not expand this status to full historical validity. |
| **C4. Degree centrality, PageRank, and feature stability** | **Partial: calculation verified; research stability not established** | `src/vesper/components/c_graph/scoring.py` uses NetworkX in/out-degree centrality and `nx.pagerank`. The centrality fixture expects 0.5 in/out centrality and 1/3 PageRank per node (`tests/components/c_graph/test_scoring.py::test_symmetric_three_cve_cycle_has_hand_calculated_centralities`). Provider schema documentation defines graph scope and missing values (`docs/COMPONENT_C_FEATURE_PROVIDER.md`). | Hand calculations verify a small symmetric graph, not score stability across graph populations, extraction changes, or alternative graph definitions. Degree and PageRank are global to their graph; the manifest filter occurs after graph calculation. Next, if stability is a proposal criterion, run a documented sensitivity comparison using already saved graphs/features without changing policy. |
| **C5. Full-scale construction and performance target** | **Partial / target evidence depends on the exact proposal wording** | The benchmark measured graph construction at **113.91 s**, research-population export at **87.09 s**, and sampled process peak RSS at **2,286,792,704 bytes** (about 2.13 GiB); the graph had 538,775 nodes and 1,779,076 edges (`outputs/c_graph_completion_sprint_2026-10-16_run1/benchmark.json`, `completion_summary.md`). Both measured stages were individually under five minutes. | The timings are separate stages; no single end-to-end wall-clock measurement is reported. If the proposal's <5-minute requirement means graph build alone, the recorded run met it on this machine. If it means the complete pipeline, measure the complete route once with one timer. Neither result is a guarantee on other hardware. The exact proposal target cannot be confirmed without the PDF. |
| **C6. Chronological KEV evaluation and baseline ablations** | **Not complete** | KEV addition labels/readiness are available for five cutoffs, using a 2026-10-15 catalog snapshot (`outputs/c_graph_kev_label_readiness_2026-10-16_run2/kev_label_readiness_report.md`; implementation/tests in `src/vesper/components/c_graph/kev_labels.py`, `tests/components/c_graph/test_kev_label_readiness.py`). A 30-day label-readiness rule distinguishes positives, fully observed negatives, already-listed cases, and censored/unlabeled outcomes. | The label report explicitly does not join historical graph features or evaluate a model. Historical C feature coverage is inadequate: at 2026-01-01, the coverage report lists 316 CPE-usable and 267 CWE-usable records among 250,950 CVEs published by then, and recorded event time is not proof of public availability. Historical EPSS is absent. No graph-only, CVSS-only, EPSS-only, CVSS+EPSS, or CVSS+EPSS+Graph chronological comparison or performance metrics are present. First obtain approval for a defensible historical evidence/scope protocol; then join eligible cutoff features to the saved KEV labels and frozen baseline data. |
| **C7. Missed-risk CVE analysis with traceable explanations** | **Not complete** | `outputs/c_graph_cvss_cluster_exploration_2026-10-16_run3/cvss_high_critical_candidates.csv` carries CVE IDs, current graph features, CVSS fields, and product/CWE evidence. | The report explicitly says it does not classify missed risks. The proposal's exact missed-risk definition and decision rule are unavailable; no qualifying threshold/rule has been approved in repository evidence. EPSS fields in candidates are unavailable. Obtain the original rule and researcher approval, then evaluate against existing labels and retain traceable CVE/product/CWE explanations. Do not relabel the CVSS-high subset as missed risk. |
| **C8. Product/weakness cluster visualization** | **Partial** | `outputs/c_graph_cvss_cluster_exploration_2026-10-16_run3/cvss_product_weakness_clusters.png` visualizes product/CWE co-occurrence among 165,226 current-snapshot CVSS HIGH/CRITICAL candidates; its edges and metadata are saved alongside the image. Tests cover aggregation and rendering (`tests/components/c_graph/test_cvss_cluster_analysis.py`). | This is a current-snapshot severity-filtered co-occurrence heatmap, not a validated high-exploitation-risk cluster visualization. It uses neither validated historical risk nor KEV labels. Once the research target and definition are approved, add a separately labeled visualization driven by the approved target; do not reinterpret the existing heatmap. |
| **C9. Shared Score contract, handoff, reproducibility, and research reporting** | **Partial: handoff documentation ready; integration and research report incomplete** | `src/vesper/components/c_graph/score_export.py` maps PageRank to `component=c_graph`, `score_kind=ranking_score`; `src/vesper/components/c_graph/feature_provider.py` validates table scope, status/value consistency, and the shared contract. The saved provider is `outputs/c_graph_feature_provider_2026-10-17_run2/c_graph_feature_provider.csv` with metadata and SHA-256. Handoff guidance is in `docs/COMPONENT_C_HANDOFF.md`; schema is in `docs/COMPONENT_C_FEATURE_PROVIDER.md`. The handoff records 156 passing Component C tests and the CSV checksum. | There is no actual Component D consumer test. No full set of proposal-required evaluation/ablation results or final research-report evidence exists. Test the actual D loader when available, preserving statuses and nulls. Obtain proposal text before asserting proposal-specific report/ablation completion. |

## Applicable evaluation and self-evaluation criteria

| Criterion | Evidence | Readiness and remaining action |
| --- | --- | --- |
| Chronological cutoffs and target labels | `outputs/c_graph_kev_label_readiness_2026-10-16_run2/kev_label_readiness_report.md` reports cutoffs 2022-01-01 through 2026-01-01 and explicit KEV addition/date-only and censoring conventions. | **Labels prepared; evaluation not done.** Historical graph features have not been joined to these cohorts. Earlier cutoffs also require careful handling of the KEV catalog's 2021-11-03 start. |
| Graph-only versus CVSS-only, EPSS-only, CVSS+EPSS, and CVSS+EPSS+Graph | No Component C evaluation report or output implements these ablations. `outputs/c_graph_cvss_cluster_exploration_2026-10-16_run3/` is descriptive, not an evaluation. | **Not complete.** Freeze the cohort, feature cutoffs, baselines, and metrics from the proposal/researcher decision; run only after point-in-time feature inputs and historical EPSS are defensible. |
| Proposal-specified evaluation metrics | Original proposal PDFs were not found in this repository; a previous report records the same blocker (`outputs/c_graph_cvss_cluster_exploration_2026-10-16_run3/completion_report.md`). | **Not verifiable.** Do not guess the required metrics. Recover the proposal/TAF and transcribe its exact metric definitions before evaluation. |
| Missed-risk and explanation review | Current candidate/cluster artifacts retain CVE and relationship traces, but the completion report says missed-risk classification is blocked. | **Not complete.** Approve a precise missed-risk rule, then use saved labels and candidate evidence; report unavailable baselines rather than imputing them. |
| Runtime, hand calculation, and manual source audit | Benchmark, centrality fixture, and manual audit are recorded in `outputs/c_graph_completion_sprint_2026-10-16_run1/`. | **Partially demonstrated.** Runtime evidence is machine-specific; source audit checks parser consistency, not independent truth. Preserve these as implementation validation rather than research performance claims. |
| Component D handoff | Shared `Score` mapping and versioned feature-provider contract are documented and tested locally. | **Documentation-ready only.** An actual D consumer must load/join the file and prove it preserves statuses, scope, and missing values before integration can be marked complete. |

## Evidence coverage and interpretation

The manifest population is 333,178 CVEs for the declared research window.
`outputs/c_graph_full_population_history_coverage_2026-10-16/coverage_report.md`
reports only 401 distinct local histories across the main corpus and saved
pilot/expansion directories. At the 2026-01-01 cutoff, it reports 250,950
published CVEs, 316 with usable dated CPE evidence, and 267 with usable dated
CWE evidence. These are evidence-eligibility counts under the documented
reconstruction policy, not estimates of historical relationship availability
to a decision-maker. The report explicitly treats monthly snapshots as current
records and history event timestamps as event-time replay evidence only.

The separate 130-CVE cutoff pilot in
`outputs/c_graph_historical_cutoff_pilot_2026-10-16_run3/report.md` demonstrates
that cutoff-specific exploratory CPE/CWE layers can be constructed for that
sample, with changing eligibility and graph sizes. It is not a representative
population evaluation. The probability sample's saved histories and the
layer-comparison pilot likewise do not establish population-wide accuracy or
coverage.

## Smallest defensible next-step sequence

1. Obtain the original proposal and Topic Assessment Form so the exact C1–C9
   milestone wording, missed-risk definition, and evaluation metrics can be
   checked rather than inferred.
2. Make a documented research-scope decision for historical evidence. The
   present reports do not support calling the whole research population a
   validated historical graph cohort; do not fill gaps with current snapshots
   or zeros.
3. If evaluation is retained, define and approve a cohort supported by
   defensible point-in-time features, KEV label maturity, and frozen historical
   CVSS/EPSS baselines; report feature availability separately from model
   performance.
4. Run the specified chronological ablations and missed-risk analysis only
   after steps 1–3. Use existing label outputs where they match the approved
   protocol; do not regenerate them without a demonstrated need.
5. Exercise the provider in the real Component D consumer and retain a
   consumer-level contract test.

## Claims that are not supported

The available evidence does **not** support claims of predictive lift,
population-wide historical validity or completeness, independently validated
historical CPE applicability, completed proposal-defined missed-risk analysis,
completed chronological baseline evaluation, or successful Component D
integration. Component C's current structural output and handoff should be
presented with those boundaries intact.
