# Component C final implementation and handoff audit

Date: 2026-10-17. Branch: `c-graph/complete-pipeline`.

## Completion decision

Component C is ready for research handoff as a current-snapshot structural
feature provider with documented historical replay capabilities and explicit
research limitations. No remaining implementation defect was identified in
that scope. Historical predictive validation and proposal-defined missed-risk
results remain unavailable for evidence/protocol reasons; they are not
reported as implementation failures or replaced with fabricated metrics.

This final audit reuses the established historical-readiness findings. It
does not repeat the readiness audit, collect histories, rebuild graphs,
regenerate the validated provider or cluster analysis, or implement Component D.
The original proposal is not available locally, so the inventory maps the
documented requirement areas rather than claiming verbatim proposal wording.

## Requirements inventory

| Requirement | Final classification | Implementation/evidence and limitation |
| --- | --- | --- |
| NVD CPE/CWE normalization | COMPLETE WITH LIMITATION | `nvd_parser.py` and `historical.py` normalize supported vendor/product and explicit CWE values, preserve history values and reject unsupported identifiers/actions. CPE graph abstraction does not preserve full version/range or logical applicability semantics. |
| Temporal graph representation | COMPLETE WITH LIMITATION | Time-aware relationship replay produces cutoff-specific graph states with source timestamps and explicit exclusions. This is snapshot replay, not a complete independently validated temporal record of public information. |
| Degree-centrality features | COMPLETE | Directed in/out degree divided by full-graph `N - 1`, explicit small-graph behavior, finite-value checks and hand-calculated fixtures; schema and saved outputs validated. |
| PageRank features | COMPLETE | NetworkX PageRank, deterministic CVE row ordering, structural Score mapping and hand-calculated fixtures; saved provider values match source features. No probability/performance interpretation is claimed. |
| Temporal leakage controls | COMPLETE WITH LIMITATION | Publication/last-modified gates, timezone-aware replay cutoffs, event filtering and label eligibility prevent the documented forms of temporal mixing. They cannot prove historical public availability; naive UTC and current-snapshot date-granularity limits remain. |
| Historical cutoff/replay machinery | COMPLETE WITH LIMITATION | Combined and independent-layer replay, explicit state/reason outputs, cutoff-scoped exports and offline regression tests exist. Historical completeness/public availability is not established. |
| KEV future-outcome labeling | COMPLETE WITH LIMITATION | Existing classifier separates already-listed, positive, mature-negative, censored and unpublished cases. The established audit checked 1,665,890 saved rows. Target is retrospective 30-day catalog addition, not exploitation onset; date-only and catalog-snapshot assumptions remain. |
| Graph-only predictive evaluation | NOT EVALUABLE DUE TO DATA/EVIDENCE LIMITATION | Pilot features exist, but public availability is unverified, scopes are incomplete and none of the 499 local-history CVEs is a future positive at any evaluated cutoff. Implemented descriptive infrastructure is partially ready; scientific performance evaluation is not. |
| CVSS-only baseline | NOT EVALUABLE DUE TO DATA/EVIDENCE LIMITATION | Available current CVSS scores are not validated historical predictors. A cutoff-specific baseline cannot be inferred from current values. |
| EPSS-only baseline | NOT EVALUABLE DUE TO DATA/EVIDENCE LIMITATION | Independently valid historical EPSS scores/date/model provenance are absent. |
| CVSS + EPSS baseline | NOT EVALUABLE DUE TO DATA/EVIDENCE LIMITATION | Historical baseline inputs and a frozen combined-score protocol are unavailable. |
| CVSS + EPSS + Graph comparison | NOT EVALUABLE DUE TO DATA/EVIDENCE LIMITATION | Baseline, temporal predictor, common cohort/class-coverage and graph-scope gates are unresolved. No fusion or Component D implementation is substituted. |
| Precision@10/25/50 and Recall@10/25/50 | NOT EVALUABLE DUE TO DATA/EVIDENCE LIMITATION | No scientifically supported rankings/cohorts. Local future-positive recall denominators are zero; recall is undefined, not zero. Some saved pilot scopes have fewer than K scored records. |
| AUC / incremental AUC / lift | NOT EVALUABLE DUE TO DATA/EVIDENCE LIMITATION | Local history cohorts lack a positive class; valid paired baseline scores and approved lift/reference definitions are absent. No metrics were calculated. |
| Missed-risk analysis | NOT EVALUABLE DUE TO DATA/EVIDENCE LIMITATION | Pending authoritative protocol clarification: local documentation does not supply an exact missed-risk definition or thresholds. Candidate interpretations are listed separately below. |
| Current-snapshot product/CWE cluster analysis | COMPLETE WITH LIMITATION | Existing CVSS HIGH/CRITICAL candidate table, product/CWE memberships and descriptive image are preserved. All saved edge memberships/counts and ordering were independently checked from candidates. Severity selection is not validated exploitation risk. |
| Predictive high-risk product/CWE claim | NOT EVALUABLE DUE TO DATA/EVIDENCE LIMITATION | No validated historical risk target/performance or approved missed-risk population supports such a claim. Existing descriptive clusters must not be relabeled. |
| Shared Score contract | COMPLETE | Eleven leading columns, timestamp/horizon constraints, enum mapping, score equality with PageRank, reasons and nulls validated for all provider rows against the shared dataclass. |
| Feature-provider handoff | COMPLETE WITH LIMITATION | Versioned 31-column provider, IDs, evidence states, provenance, consumer rules and integrity checks are supplied. Actual downstream-loader acceptance is a Component D responsibility and is not claimed. |
| Reproducibility and provenance | COMPLETE WITH LIMITATION | Saved hashes, population/scope identities, raw/ledger/sidecar safeguards and deterministic input/row ordering are implemented. Legacy generation metadata lacks some configuration/environment/source hashes; byte-identical reproduction across environments is unproven. Audit hashes identify inspected bytes, not retroactively recovered generation provenance. |
| Full-scale execution / runtime evidence | COMPLETE WITH LIMITATION | Existing graph has 538,775 nodes and 1,779,076 edges. The prior benchmark records 113.91 s graph construction and 87.09 s population export as separate stages; no combined runtime or hardware-independent guarantee is inferred. |

No inventory item is classified as REMAINING IMPLEMENTATION WORK for the scoped
current-snapshot/replay/provider deliverable. Future predictive evaluation
software is gated on scientific inputs and an approved study protocol; its
absence is not evidence of a defect in the completed feature implementation.

## Saved deliverables verified without regeneration

| Artifact | Actual rows / identity |
| --- | --- |
| `outputs/c_graph_full_snapshot_2026-10-15/features.csv` | 322,009 unique CVE rows; `cve_id,in_degree_centrality,out_degree_centrality,pagerank`. |
| `outputs/c_graph_full_snapshot_2026-10-15/features.metadata.json` | 44,151 vendor, 171,809 product, 322,009 CVE and 806 CWE nodes; 1,779,076 edges; 142 monthly source files. |
| `outputs/c_graph_full_snapshot_2026-10-15/research_population/research_population_features.csv` | 315,515 eligible research-population feature rows; exact filter of the full features. |
| `outputs/c_graph_full_snapshot_2026-10-15/research_population/c_graph_scores.csv` | 333,178 shared Score rows; 315,515 available and 17,663 not eligible. |
| `outputs/c_graph_feature_provider_2026-10-17_run2/c_graph_feature_provider.csv` | 333,178 unique CVEs; 31 columns; schema `1.0.0`; shared horizon 30 days; `trained_through` blank. |
| `outputs/c_graph_feature_provider_2026-10-17_run2/c_graph_feature_provider.metadata.json` | Snapshot `nvd-current-snapshot-2026-10-15`; reference `2026-10-15T00:00:00+00:00`; scope `nvd-current-snapshot-2026-10-15-graph-b9e7f112a61a`. |
| `outputs/c_graph_cvss_cluster_exploration_2026-10-16_run3/cvss_high_critical_candidates.csv` | 165,226 unique current-snapshot severity-selected CVEs. |
| `outputs/c_graph_cvss_cluster_exploration_2026-10-16_run3/product_weakness_cluster_edges.csv` | 326,076 product/CWE co-occurrence rows; 149,666 contributing CVEs; sorted, reproducible membership lists. |
| `outputs/c_graph_cvss_cluster_exploration_2026-10-16_run3/cvss_product_weakness_clusters.png` | Existing descriptive current-record visualization; not regenerated. |

The saved provider SHA-256 remains
`dd6175aa0961b4aed9ea3533634a29d7ff80320b18f28a8096007b5b265a38fc`.
The full validator checks every provider row, its shared contract, numeric
degree/PageRank values, null/status/reason consistency, snapshot/scope,
source timestamps and manifest identity. Provider features and Score columns
match the existing source CSVs. CPE/CWE unavailable values remain blank;
numeric calculated degree zeros are not missing-value imputations.

The cluster output is explicitly descriptive/current-snapshot. Every edge's
count and sorted CVE list matches saved candidate relationships. The saved
metadata and plot labeling imply no historical predictive result. Original
cluster metadata does not include full environment/input hashes; the final
audit supplies integrity fingerprints without claiming to recover those
missing generation facts. Image bytewise reproduction is not established.

## Missed-risk protocol clarification

Repository documentation consistently records the original definition as
unavailable; no authoritative local rule was found. The following are distinct
candidate questions for the researcher, not adopted definitions:

1. Future KEV positives outside a baseline top-K list but recovered by a
   graph-augmented list: requires K, ranking/tie rules and a common cohort.
2. Future KEV positives below a CVSS severity threshold: requires the threshold,
   score version/source and a valid historical score date.
3. Future KEV positives below an EPSS threshold: requires the threshold and valid
   historical EPSS/model provenance.
4. Low baseline rank versus high graph rank: descriptive discordance until an
   outcome-based missed-risk rule and denominator are explicitly defined.

None was selected. No missed-risk metric, threshold or predictive result was
calculated. CVSS HIGH/CRITICAL clusters are not an answer to these questions.

## Validation and handoff boundary

Read-only audit records are in
`outputs/c_graph_final_handoff_audit_2026-10-17_run1/`: `provider_validation.json`,
`cluster_validation.json`, `artifact_integrity.json` and
`validation_results.json`. The final validation runs the full Component C
suite, Ruff lint and format checks across its source/tests/scripts, and
`git diff --check`. Results are recorded there and summarized in the handoff.

Final results: **183 tests passed** (26.64 s); Ruff lint passed; Ruff format
check passed for 48 Component C source/test/script files; `git diff --check`
passed. The only Python edit was formatting the existing research-population
builder; no behavior changed and no additional tests were needed for that edit.

The [handoff guide](COMPONENT_C_HANDOFF.md) supplies architecture, input/output
contracts, degree/PageRank definitions, cutoff/leakage and label semantics,
consumer guidance, reproduction/verification commands, completed test coverage
and limitations. The [schema guide](COMPONENT_C_FEATURE_PROVIDER.md) defines
all 31 columns. The [established historical-readiness supplement](COMPONENT_C_HISTORICAL_EVALUATION_READINESS.md)
contains the existing historical evaluation decision; it was not recomputed.

Research handoff is ready with these boundaries. Historical public availability,
naive-UTC interpretation, historical CVSS/EPSS, class coverage and exact
missed-risk/combined-baseline protocol remain unresolved evidence/protocol
limitations. Downstream consumer acceptance remains external integration work.
No predictive validation or research-performance completion is claimed.
