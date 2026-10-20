# Component C historical evaluation readiness after run3

Assessment: 2026-10-17, branch `c-graph/complete-pipeline`. This supplements the
earlier Component C readiness documents with the 499-history local corpus.

The [offline readiness report](../outputs/c_graph_historical_evaluation_readiness_2026-10-17_run1/report.md)
and its adjacent CSV/JSON artifacts record cutoff-specific input availability,
label eligibility, graph scopes, comparison blockers and metric readiness.

## Evaluation decision

- Graph-only: **PARTIALLY READY** for descriptive event-time replay and existing
  pilot-feature inspection, not validated chronological prediction.
- CVSS-only, EPSS-only, CVSS + EPSS, and CVSS + EPSS + Graph:
  **NOT SCIENTIFICALLY SUPPORTED** with the present historical inputs.
- No evaluation-ready predictive dataset or performance metrics were generated.
  The new artifacts are readiness and coverage inventories only.

At 2026-01-01, the local corpus has 400 CPE-usable, 340 CWE-usable and 323
both-layer event-time histories. These do not establish historical public
availability or a complete historical graph. Existing saved numeric graph
features have separate pilot populations; their centralities cannot be pooled.
The validated 2026-10-15 current provider is not a historical predictor.

All 1,665,890 saved KEV label rows were checked against the existing classifier
and frozen sources. The five full-population 30-day cohorts have 32, 2, 12, 6
and 9 future positives, respectively. **None of those positives occurs among
the 499 local-history CVEs.** Already-listed and unpublished cases remain
unlabeled. All five horizons are mature; no actual censored cases occur.
Negatives mean no catalog addition during the observed horizon under the
saved catalog target, not absence of exploitation.

## Scientific limits and handoff

Current CVSS values are not validated historical scores. Historical EPSS is
unavailable. NVD event dates do not prove public availability, and naive event
timestamps retain the explicitly unverified UTC assumption. June 2026
GitHub-linked Affected details cannot supply pre-cutoff product evidence.
The exact proposal-defined missed-risk rule remains unavailable; no substitute
threshold or definition was chosen.

Precision@10/25/50, Recall@10/25/50, AUC/incremental AUC, lift and missed-risk
recall are blocked as scientific performance comparisons. Recall and AUC are
undefined on the local all-negative future-outcome cohorts; they are not zero.

No additional Component C code is required for a handoff restricted to the
current-snapshot provider, documented replay capabilities and these limits.
Historical predictive evaluation remains incomplete. A future evaluation
pipeline requires a prespecified protocol and defensible temporal predictors,
cohort/class coverage and graph scope before implementation. No Component D
work or additional collection is part of this assessment.
