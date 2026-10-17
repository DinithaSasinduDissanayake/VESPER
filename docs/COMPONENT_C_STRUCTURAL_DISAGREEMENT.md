# Component C structural contribution and current-snapshot disagreement

## Locked contribution and scope

Component C supplies relationship-aware vulnerability prioritization using
CVE-product-weakness graph structure to identify structurally important CVEs,
affected product families and weakness concentrations that scalar severity or
exploitation scores do not describe alone. Connectivity is not proof of
exploitation risk. PageRank and degree are not exploitation probabilities.
Component D owns final A/B/C plus CVSS/EPSS fusion and predictive ranking.

This experiment is a **current-snapshot Structural-Scalar Disagreement
Analysis**. It adds descriptive research outputs and a real shared-contract
score adapter without changing the validated graph or detailed provider.
Previous [historical evaluation limitations](COMPONENT_C_HISTORICAL_EVALUATION_READINESS.md)
remain a documented methodological investigation, not a prediction claim.

## Three separate deliverables

| Deliverable | Source/output | Meaning |
| --- | --- | --- |
| Detailed C provider | `outputs/c_graph_feature_provider_2026-10-17_run2/c_graph_feature_provider.csv` and metadata | Unchanged 333,178-row, 31-column current-snapshot feature/evidence table, schema `1.0.0`. |
| Real C score for downstream consumption | `outputs/c_graph_structural_scalar_disagreement_2026-10-17_run1/c_graph_scores.csv` and `.csv.metadata.json` | Exactly the existing 11-field shared Score contract, with the D-facing PageRank percentile correction described below and original availability states. No scalar or outcome input enters its construction. |
| Disagreement research | Other files under `outputs/c_graph_structural_scalar_disagreement_2026-10-17_run1/` | Common-cohort structural versus CVSS percentiles, differences, threshold sensitivity, explanations and post-selection current KEV annotation. These differences are not the D-facing C score. |

## Inspected fields and exact structural score

The provider already contains `in_degree_centrality`,
`out_degree_centrality`, `pagerank` and shared `score`. Its available shared
score equals raw PageRank and already satisfies the requested graph-only
ranking purpose. It is reused, not replaced by a new combined percentile
score. `model_version=c_graph-pagerank-structural-0.1`,
`component=c_graph`, and `score_kind=ranking_score` remain unchanged.
The score is in [0,1]; higher denotes **relative graph structural importance**.

There are no existing degree/PageRank rank or percentile fields. Those are
derived only for the research analysis. Existing product/CPE information is
`vendor_product_evidence_json` with its status/reason; CWE information is
`cwe_ids_json` with its status/reason. Graph/score statuses remain separate
from evidence completeness. Snapshot, scope, reference time, decision time,
snapshot date and horizon already exist; no duplicate provider fields are added.

Current directed graph edges are product -> CVE and CVE -> CWE, alongside
vendor -> product. Degree is the observed incoming product-edge count plus
outgoing CWE-edge count, recovered as
`(in_degree_centrality + out_degree_centrality) * (N_graph - 1)`.
An integer-consistency check is required before rounding. The full graph has
538,775 nodes. PageRank and centralities retain that full graph scope; they
are not recalculated over the analysis subset.

## Population, CVSS and percentiles

All research percentiles use the same declared population: provider rows
with available graph scores, **both supported CPE and CWE evidence**, and an
observed compatible current CVSS base score. Any severity is allowed.
Incomplete relationship evidence, missing CVSS and non-eligible graph rows
remain explicit exclusions with blank research percentiles/differences.
This complete-case research filter does not change D-adapter availability.

CVSS comes from the same hash-verified monthly NVD files recorded by the
provider. Record publication, last-modified timestamp, source filename and
Rejected status must match the provider and cutoff. The existing cluster
analysis's CVSS extraction policy is reused: highest available numeric base
score across v4.0/v3.1/v3.0/v2.0, with that version order for equal scores and
the source record's entry order for remaining ties. This is an explicit
cross-version descriptive policy, not a universal severity calibration.
The old HIGH/CRITICAL table cannot define this cohort because doing so would
exclude low/moderate CVSS cases central to the disagreement question.

For each observed degree, PageRank and CVSS value, let `r` be its ascending
average tied rank in the same eligible cohort of size `M`:

`P = (r - 1) / (M - 1)`.

Ties share a midrank. A constant cohort receives 0.5; a singleton receives
0.5. No random tie breaking is used. For empty/unavailable cases no percentile
is produced. The outputs are `P_degree`, `P_pagerank`, and `P_cvss`.

Differences are `P_degree - P_cvss` and `P_pagerank - P_cvss`. Positive means
the graph measure ranks that CVE relatively higher than CVSS **within this
cohort**. The primary order is PageRank-CVSS difference descending, then CVE
ID ascending for exact ties. Degree-CVSS is a separate secondary analysis.
There is no combined `P_graph` or average-percentile structural score.
Top 10, 25 and 50 are nested prefixes; tied boundary counts are disclosed.

## Predefined descriptive sensitivity and explanations

Apply each rule independently to degree and PageRank:

| Rule | Structural percentile | CVSS percentile |
| --- | --- | --- |
| A | >= 0.90 | < 0.50 |
| B | >= 0.75 | < 0.50 |
| C | >= 0.75 | < 0.25 |

These are descriptive study rules, not universal cybersecurity cutoffs.
Candidate counts and pairwise intersections/unions/Jaccard overlaps disclose
sensitivity across all six definitions. Empty-union Jaccard is undefined.

Top-case rows retain CVSS/version, observed degree and percentile, raw
PageRank and percentile, structural score, disagreement, source product/CWE
evidence, availability, snapshot/scope and post-selection KEV annotation.
Product, vendor and CWE tables count distinct candidates per entity for each
declared cohort. Memberships overlap, so concentration shares need not sum
to one. Existing severity-cluster candidates are reused only as an overlap
annotation; the previous clusters and image are not regenerated.

## KEV: post-selection current descriptive enrichment only

KEV is loaded **after** graph scores, percentiles, rankings and cohort IDs are
fixed. Its fields never enter the score or candidate-selection functions.
The ranking is checked unchanged after annotation. Membership and `dateAdded`
refer to the existing saved current catalog and its recorded release time,
which can be later than the graph reference time. No point-in-time predictor
availability or future-outcome interpretation is implied.

For each candidate cohort, descriptive prevalence is saved-catalog members
divided by cohort size. Population prevalence uses the identical eligible
analysis population. Their ratio is reported only with a nonempty cohort and
positive population prevalence; otherwise it remains undefined/blank.
This is **CURRENT-SNAPSHOT DESCRIPTIVE ENRICHMENT**, not prospective prediction,
accuracy, recall, AUC, validated lift or model performance. Nonmembership is
not evidence of no exploitation. No historical EPSS is used or fabricated.

## Exact downstream contract and compatibility boundary

`c_graph_scores.csv` columns, in order:

`cve_id,component,decision_time,horizon_days,score,score_kind,status,reason,model_version,trained_through,snapshot_date`.

Every adapter row retains the shared-contract identity and availability fields from
the validated real provider, sorted by CVE. The D-facing correction replaces only
`score` and `model_version`: available scores are the relative PageRank structural
percentile `(average_rank(pagerank)-1)/(N-1)` over all 315,515 available provider
rows, with deterministic average ranks for ties. This population differs from
the 279,935-row research cohort. Equal raw values receive equal scores; a singleton
population uses 0.5. Non-available statuses retain blank scores and reasons. No graph
evidence is fabricated or zero-filled. A missing relationship layer is not
the same as a missing computed graph score; its separate state remains in
the detailed provider and must be carried by consumers that need it.

The adapter sidecar binds its CSV checksum to source provider checksum,
snapshot/scope, reference time, horizon and score semantics. The 30-day
`horizon_days` is an interface requirement, not a trained exploitation horizon.
`trained_through` remains blank. Join by `(cve_id, decision_time)` after
verifying the same horizon and snapshot/scope; do not compare centralities
from different graph populations as calibrated scores. Preserve status and
nulls when constructing the shared `vesper.contracts.score.Score` dataclass.

The requested `src/vesper/components/d_fusion/dummy_inputs/README.md`, synthetic
fixtures and a D loader are **absent in this checkout**; D has a package stub
only. No fixture was substituted, overwritten or treated as a real result.
Shared Score validation, CSV round-trip and key-join checks are possible and
tested. Actual D-loader/fixture compatibility remains unverified until its
owner supplies those files. No D source, fusion methodology, training or
predictive evaluation is changed here.

## Observed current-snapshot results

The common cohort has **279,935 CVEs**. Exclusions are 17,663 Rejected rows,
35,520 without both supported relationship layers, and 60 otherwise-complete
rows without compatible CVSS. The real adapter remains all 333,178 provider
rows (315,515 available structural scores and 17,663 not eligible).

The primary leading case is **CVE-2022-0005**: CVSS 2.4, degree 460,
PageRank percentile 0.999164, CVSS percentile 0.002461 and disagreement
0.996703. Its observed evidence spans 459 product identifiers and CWE-319.
Firmware/model enumeration contributes to degree; this is not independent
evidence of exploitation. The next cases are CVE-2021-27456 (CVSS 2.4,
disagreement 0.995703) and CVE-2020-24587 (CVSS 2.6, disagreement 0.995319).
There are no boundary ties at primary ranks 10, 25 or 50.

| Rule | Degree candidates | PageRank candidates |
| --- | ---: | ---: |
| A | 11,116 | 8,972 |
| B | 25,391 | 34,062 |
| C | 12,892 | 14,815 |

Degree/PageRank Jaccard overlap for the same rule is 0.128 (A), 0.126 (B)
and 0.122 (C), indicating strong descriptive definition sensitivity. A and C
are each subsets of B within a dimension. No score/threshold was selected
or retuned based on the subsequent KEV annotations.

**Current-snapshot descriptive KEV enrichment:** the common population has
1,384 members (0.4944%). Primary Top 10, 25 and 50 each contain zero members,
so each observed descriptive ratio is 0. Degree A/B/C ratios are
1.237/0.836/0.502; PageRank A/B/C ratios are 0.293/0.148/0.109. These include
depletion as well as enrichment and do not establish predictive performance.

Among primary Top 50, AMD and Intel each occur for four CVEs; Dell, Lenovo,
Motorola and Siemens each occur for three. CWE-125, CWE-287 and CWE-319 each
occur for three. No individual product identifier occurs in more than two
cases. Numerous product identifiers tie at two, so the product figure's
alphabetical display cutoff shows representative Arista identifiers, not an
Arista-dominance result. The CSVs contain the complete memberships. Source
vendor/product spelling variants are preserved, not silently resolved into
an invented family ontology. None of the primary Top 50 overlaps the old
HIGH/CRITICAL candidate table.

The adapter passed exact shared-schema, null/status, whole-provider contract,
CSV round-trip and key-join validation. Actual D-loader compatibility remains
unverified because the requested D assets are absent. This is the remaining
downstream acceptance boundary, not a reason to create or train D here.

Final validation: **216 tests passed** (202 C tests and 14 shared Score tests),
Ruff lint passed, Ruff format check passed for 52 files, and
`git diff --check` passed. Existing graph/provider/cluster hashes remained
unchanged. Three PNG/SVG figure pairs were generated and visually inspected.

## Reproduction and validation

Use the existing environment with no downloads/dependency synchronization:

```powershell
$env:UV_CACHE_DIR = Join-Path (Get-Location) '.uv-cache\c-structural-disagreement'
uv run --offline --no-sync python scripts/analyze_c_graph_structural_disagreement.py `
  --output-dir outputs/NEW_STRUCTURAL_DISAGREEMENT_OUTPUT
uv run --offline --no-sync pytest tests/components/c_graph/ tests/contracts/test_score.py -q
```

The analysis refuses any existing output directory. Its `summary.json`
records exact inputs/monthly hashes, field mapping, population, formulas,
thresholds/overlaps, version information, tied boundaries and protected-input
integrity. The score sidecar carries a distinct structural contract identity.
No graph or validated provider is rebuilt. Existing matplotlib produces
deterministic data selections and presentation-ready PNG/SVG views; bytewise
rendering across different library/font environments is not guaranteed.

Source: `src/vesper/components/c_graph/structural_disagreement.py` and
`scripts/analyze_c_graph_structural_disagreement.py`. Targeted offline tests
cover percentile/tie determinism, bounds, missingness, differences, thresholds,
KEV independence, Score parsing/joins and metadata mismatch rejection.


## Final D-facing adapter correction

The completed research outputs, candidate selection, KEV analysis and raw provider
are unchanged. The raw-score discussion above records the original research run;
the adjacent adapter sidecar is authoritative for the corrected downstream score.
Historical `summary.json`, `report.md` and `validation.json` remain frozen records
of that run, including their original adapter description/checksum.

The corrected adapter uses `model_version=c_graph-pagerank-percentile-structural-0.2`
and `score_kind=ranking_score`. Score means **relative PageRank structural
percentile**, NOT exploitation probability. Higher score means greater relative
graph structural importance; percentile normalization does not validate predictive
risk ordering. `horizon_days=30` is shared interface metadata, not a validated
30-day Component C prediction target. Snapshot/scope provenance is unchanged.
The detailed 31-column provider retains raw PageRank and its original score/version;
consumers must not replace the corrected adapter score with the provider score
when joining the evidence supplement.

Regenerate only the adapter CSV and its adjacent metadata, offline:

```powershell
uv run --offline --no-sync python scripts/export_c_graph_percentile_adapter.py
```

The exporter verifies the frozen provider checksum and snapshot/scope identity,
and checks all other files in the research output directory remain byte-identical.
It does not rerun the analysis, rebuild the graph, or read scalar/outcome inputs.
