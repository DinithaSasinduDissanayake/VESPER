# Component C final implementation and research handoff

## Historical abstention panel

`scripts/export_c_graph_historical_panel.py` exports a separate historical panel
using the full validated research manifest as its master population. The fixed
grid is the first of each month from 2023-01-01 through 2026-09-01, excluding
2024-12-01: 44 decisions at 00:00:00 UTC. Publication and history events use
inclusive `<= decision_time` cutoffs. The expected row count is calculated from
the actual manifest count times 44, never from a hard-coded population size.

This release is **abstention-only**. Every master CVE has a row at every cutoff,
with blank `score`, `status=abstained`, and a specific primary reason. CVEs not
yet published remain explicit as `cve_not_published_at_decision_time`; they do
not enter graph or percentile populations. No graph, PageRank, percentile,
KEV label, current-score import, or temporal backfill is performed. Current
`c_graph_scores.csv`, provider, graph and disagreement outputs are unchanged.

The exact shared 11-column Score contract is retained. Historical model version
is `c_graph-pagerank-percentile-historical-structural-0.1`, distinct from the
current adapter. `score_kind=ranking_score`; `horizon_days=30` is downstream
evaluation metadata, not evidence of 30-day exploitation training or prediction.
`trained_through` stays blank because C has no supervised training dataset.

Strict replay is reused only to diagnose evidence. Technical eligibility does
not certify historical public availability or sufficient graph context. The
audited local corpus has 499 unique CVEs; the strict policy has some eligible
CVEs at 41 decisions and none at July, August or September 2026. These are audit
observations, not hard-coded export counts. All 44 dates lack certified numerical
score support. Mutable Affected links, uncertain initial states, incomplete
coverage and assumed UTC event timestamps remain explicit limitations.

The exporter streams rows and validates them through a second streaming read.
It refuses existing destination directories. Its two artifacts are
`c_graph_historical_scores.csv` and
`c_graph_historical_scores.csv.metadata.json`. Metadata contains manifest and
source hashes, publication coverage, duplicate-copy policy, per-cutoff technical
eligibility, primary and complete reason counts, and keyed history diagnostics.
Duplicate copies are compared at each cutoff; material state disagreements fail
closed. Invalid copies also fail closed rather than being silently discarded.
Specific reconstruction reasons take precedence over general scientific gates;
the documented ordered policy prefers `github_reference_unrecoverable` over its
broader unsupported-Affected diagnosis. Full concurrent reasons are retained.

Only the manifest, cached local history and reconstruction code are needed.
Use repeatable `--history-dir` arguments to cover all approved local corpora:

```powershell
$env:PYTHONPATH = Join-Path (Get-Location) 'src'
python -B scripts/export_c_graph_historical_panel.py `
  --manifest <research_population.csv> `
  --history-dir <existing-history-directory> `
  --output-dir outputs/NEW_HISTORICAL_ABSTENTION_PANEL `
  --start 2023-01-01 --end 2026-09-01 --exclude-date 2024-12-01 `
  --cutoff-time 00:00:00Z --horizon-days 30 --mode abstention-only
```

No numerical score is absent accidentally. Historical numerical release requires
independently defensible initial states and public-availability timing,
immutable Affected payloads or revisions, and an agreed sufficient graph-context
population. A new reviewed evidence policy and numerical adapter would be needed;
this exporter has no numerical mode. Abstention rows are an auditable missingness
handoff, not a certified historical predictor or a comparison against CVSS/EPSS.

## Minimal PR scope and archived references

The final executable pipeline covers the current-snapshot graph, detailed
feature provider, structural-disagreement analysis, and percentile adapter.
The full CVSS analysis script is retained. Historical collection and evaluation
tooling are excluded from this minimal PR; retained historical modules support
the existing manifest loader and conservative relationship parsing/replay.
They do not establish a final historical collection or evaluation pipeline.

All `data/` and `outputs/` paths below identify external frozen research
artifacts, not files shipped in this minimal PR. References to absent scripts,
modules, reports, or documentation are archived research context, not executable
steps or dependencies of the final pipeline. Historical test counts below are
archived validation results from the broader checkout, not current minimal-PR
test counts. Existing research values and limitations are preserved.

## Final score semantics

The detailed feature provider retains `score = raw PageRank` for available
rows and `model_version=c_graph-pagerank-structural-0.1`.

The D-facing Component C score is a deterministic PageRank percentile
structural ranking: `(average_rank(pagerank) - 1) / (N - 1)`, using ascending
average ranks over available provider rows. Equal PageRank values receive
equal scores. Higher scores indicate greater relative graph structural
importance, not exploitation probability. Unavailable scores remain blank.
`score_kind=ranking_score` and
`model_version=c_graph-pagerank-percentile-structural-0.2`.
`horizon_days=30` is shared interface metadata, not a validated 30-day
Component C prediction target.

For the frozen run, N = 315,515 available provider rows. The research
disagreement cohort remains 279,935; it is not the adapter percentile
population. Joining provider evidence must preserve the adapter score/version.

The current-snapshot implementation is ready for research handoff with the
limitations below. Historical predictive evaluation is not validated. Further
history collection is stopped. This handoff does not implement or certify a
Component D consumer.

The refined structural contribution, current-snapshot disagreement experiment
and separate real Score adapter are documented in
[`COMPONENT_C_STRUCTURAL_DISAGREEMENT.md`](COMPONENT_C_STRUCTURAL_DISAGREEMENT.md).
That experiment does not reopen historical predictive evaluation. The adapter
uses the relative PageRank structural percentile over available provider rows;
scalar/outcome annotations remain research-only. The detailed provider retains raw
PageRank. See the final adapter correction in COMPONENT_C_STRUCTURAL_DISAGREEMENT.md.
The requested D dummy-input README/fixture and actual loader are absent in this
checkout, so compatibility can be verified against the shared Score contract
and joins only, not an unavailable D loader. The original 31-column provider
remains unchanged.

The final requirement-by-requirement disposition is in
`COMPONENT_C_FINAL_AUDIT.md` (archived external report: `COMPONENT_C_FINAL_AUDIT.md`; excluded from this PR). The established
historical evaluation decision is in
`COMPONENT_C_HISTORICAL_EVALUATION_READINESS.md` (archived external report: `COMPONENT_C_HISTORICAL_EVALUATION_READINESS.md`; excluded from this PR).

## Archived collection safety and resume recovery (tooling excluded)

The standard downloader and the history expansion pilot both acquire
`.collection.lock` in their output directory before modifying collection
artifacts. The lock is created atomically and excludes other processes using
these runners on the same filesystem. Exceptions and `KeyboardInterrupt`
release it through context cleanup. Forced process termination can leave a
stale lock. The runner deliberately does not delete stale locks: inspect the
recorded PID and command line. Treat a lock as live if the PID is running or its
state is uncertain. Preserve the lock contents for the run record; remove it
only after confirming that the owning process has exited. The cross-process
checks were run on the local Windows filesystem; network and distributed
filesystems have not been validated.

The standard downloader persists a configured `--max-page-requests` ceiling in
`request_reservations.sqlite3`, counting every reserved HTTP attempt, including
retries. Resume without the option retains the stored ceiling; changing it is
rejected. On first use with an existing valid request ledger, prior request
starts seed the budget. A malformed ledger prevents budget initialization and
collection. Omitting the option on a fresh output directory leaves the standard
runner unbounded. The dedicated history expansion pilot defaults to 260
reservations and accepts a positive `--request-ceiling`. Its SQLite config
retains the selected ceiling on resume and rejects a conflicting explicit
ceiling. Run3's persisted ceiling is 20 and all 20 reservations were consumed.
This is recovery documentation, not authorization for another collection.

Request-ledger JSONL is fail-closed. Malformed records, including a truncated
last line, stop processing with the ledger path and line number. Preserve the
original ledger before any manual recovery; do not truncate or repair it in
place. Resume can rebuild a missing history sidecar when matching completed
ledger entries match the CVE and endpoint, referenced raw response hashes and
byte counts validate, and NVD pages reproduce the saved history and pagination.
Otherwise it writes `provenance_status: incomplete` and
`retrieval_disposition: incomplete_provenance`; that history is not counted as
a complete capture. Existing sidecars are left unchanged.

## Purpose and scope

Component C supplies graph-derived structural ranking features and explicit
vendor/product/weakness evidence. The current deliverable is a **current NVD
snapshot** feature table. It is not a calibrated exploitation probability,
validated historical feature set, or predictive evaluation result.

## Architecture, inputs and graph features

- `nvd_parser.py` normalizes current NVD records to the shared `Vulnerability`
  contract: sorted, deduplicated vendor/product pairs and explicit CWE IDs.
  Placeholder identifiers and non-vulnerable CPE matches are not graph evidence.
- `pipeline.py` reads the local monthly files, rejects duplicate CVEs, gates
  publication/last-modified dates and Rejected records, then calls `graph.py`
  and `scoring.py`. The 142 monthly files are current-record partitions by
  publication month, not archived historical states.
- The directed `DiGraph` uses namespaced vendor, product, CVE and CWE nodes:
  vendor -> product (`offers`), product -> CVE (`affected_by`), and CVE -> CWE
  (`has_weakness`). It retains no parallel edges or explicit edge weights.
- In/out-degree centrality is the corresponding CVE degree divided by
  `N - 1`, where `N` is the full graph node count. For `N < 2`, the implemented
  definition is zero. A computed zero is distinct from an unavailable feature.
- Current graph PageRank uses NetworkX defaults: `alpha=0.85`, `max_iter=100`,
  `tol=1e-6`, uniform personalization and unit edge weights. It is normalized
  over all graph nodes; the exported CVE subset need not sum to one. It is a
  structural ranking score, not an exploitation probability.
- Archived external `export_c_graph_snapshot_population.py` (excluded) filters saved full-graph features
  to the research manifest and emits shared Score rows. The feature-provider
  exporter joins those saved outputs with source-record evidence. Neither
  population filtering nor the provider recalculates graph centrality.
- Retained `historical.py` and `multi_historical_pipeline.py` provide existing
  parsing/replay and manifest validation. The broader historical pipeline
  (`historical_pipeline.py`), exploratory layers (`layered_historical.py`,
  `historical_cutoff_export.py`) and outcome classification (`kev_labels.py`)
  are archived external tooling excluded from this PR. Saved label readiness
  results are research context only and do not train a model.

Inputs are `data/raw/nvd/nvd_*.json.gz`, the 333,178-CVE manifest at
`data/processed/c_graph/research_population.csv`, the existing saved feature
and score files, and (for offline replay only) existing local history corpora.
The frozen KEV source and label provenance are identified in
`outputs/c_graph_kev_label_readiness_2026-10-16_run2/kev_label_provenance.json`.

## External frozen handoff artifacts

Use the existing files; do not regenerate them as part of integration:

- Feature provider CSV: `outputs/c_graph_feature_provider_2026-10-17_run2/c_graph_feature_provider.csv`
- Metadata: `outputs/c_graph_feature_provider_2026-10-17_run2/c_graph_feature_provider.metadata.json`
- Separate real scalar adapter: `outputs/c_graph_structural_scalar_disagreement_2026-10-17_run1/c_graph_scores.csv`
- Adapter identity/semantics: the adjacent `c_graph_scores.csv.metadata.json`;
  exactly 333,178 rows and 11 shared Score fields, using deterministic
  PageRank percentiles and preserving provider statuses. CVSS/KEV do not enter that score.
- Snapshot: `nvd-current-snapshot-2026-10-15`, reference time `2026-10-15T00:00:00+00:00`
- Schema guide: [`COMPONENT_C_FEATURE_PROVIDER.md`](COMPONENT_C_FEATURE_PROVIDER.md)

The CSV has 333,178 rows, one per research-manifest CVE, with unique `cve_id`.
Its first 11 columns are the shared `Score` contract, followed by the
Component C snapshot, feature, relationship-evidence, and source-provenance
fields documented in the schema guide. The metadata records the output and
input hashes, snapshot identity, graph scope, and evidence-status counts.

| Existing artifact | Actual rows / scope |
| --- | --- |
| `outputs/c_graph_full_snapshot_2026-10-15/features.csv` | 322,009 CVE rows; four graph-feature columns. |
| `outputs/c_graph_full_snapshot_2026-10-15/features.metadata.json` | 538,775 total nodes and 1,779,076 edges; 142 monthly input files. |
| `outputs/c_graph_full_snapshot_2026-10-15/research_population/research_population_features.csv` | 315,515 eligible manifest CVE rows; four columns. |
| `outputs/c_graph_full_snapshot_2026-10-15/research_population/c_graph_scores.csv` | 333,178 rows; 11 shared Score columns. |
| `outputs/c_graph_feature_provider_2026-10-17_run2/c_graph_feature_provider.csv` | 333,178 rows; 31 columns; schema `1.0.0`. |

The saved scope ID is
`nvd-current-snapshot-2026-10-15-graph-b9e7f112a61a`. The final audit validates
the entire provider with `validate_feature_provider`, compares its numeric
features and leading Score fields against the existing source exports, and
checks the saved SHA-256 values without rebuilding anything. Machine-readable
results are in `outputs/c_graph_final_handoff_audit_2026-10-17_run1/`.

The metadata was generated before feature-generation, graph-configuration,
NetworkX-version, and source-code-hash fields were added to the exporter. Those
values are not recoverable from that run's metadata and have not been
backfilled or asserted for this saved export. Future exports record them.

## Values, statuses, and null handling

| Field group | Type / interpretation | Missing-value semantics |
| --- | --- | --- |
| `cve_id` | String key | Required, unique within this single-snapshot file. |
| Shared `Score` fields | Contract fields; timestamps, date, integer horizon, enum strings, nullable numeric score | `score` is PageRank only for `status=available`; blank for non-available status. CSV blanks may load as null. |
| `reference_timestamp`, `snapshot_id`, `feature_schema_version`, `graph_scope_id` | Timestamp/string identifiers | Required and consistent across this export. |
| `in_degree_centrality`, `out_degree_centrality`, `pagerank` | Nullable dimensionless floats in [0,1] | Blank when score status is not available. A computed numeric zero is a graph result, not a missing-value substitute. |
| `*_status` | Status strings | Graph feature statuses mirror shared `status`; CPE/CWE evidence has its own `supported`, `unavailable`, or `not_evaluated` status. |
| Relationship JSON fields | JSON array strings or blank | Blank means no supported value was extracted; it does not establish a known-empty relationship set. |
| `*_reason` | Nullable strings | Available `Score.reason` serializes as a blank field; non-available score statuses require a non-empty reason. Readers may parse a blank CSV field as null. |
| Source fields and `feature_provenance` | Timestamps/strings | Required provenance identifying the local record source and extracted record timestamps. |

`available` means the saved graph export produced a numeric structural score;
it does not guarantee that both relationship-evidence layers were extracted.
`unavailable` is used for evidence that the parser could not support and is not
equivalent to an empty set. `not_eligible` means NVD marked the record Rejected
in this snapshot; numeric score and graph features are blank and relationship
evidence is `not_evaluated`. The current file contains 315,515 available and
17,663 not-eligible score records.

Across the full 333,178-row manifest denominator, CPE evidence is 309,656
`supported`, 5,859 `unavailable`, and 17,663 `not_evaluated`; CWE evidence is
285,527 `supported`, 29,988 `unavailable`, and 17,663 `not_evaluated`. Among
the 315,515 available score rows, 279,995 have both layers supported, 35,193
have exactly one supported layer, and 327 have neither layer supported. These
are extraction-status counts; `unavailable` is not a known-empty relationship
state.

The 30-day `horizon_days` value is carried by the shared Score interface. It
does not mean Component C independently predicts exploitation within 30 days
or was trained against a 30-day target. `snapshot_id` identifies the dated
current-record snapshot. `graph_scope_id` identifies the graph feature file
whose full graph population determined the structural values; it is not a
portable calibration identifier. Do not compare values across graph scopes as
though they shared a calibrated scale.

## Current-snapshot cutoff controls and archived replay context

The current snapshot pipeline gates publication and last-modified UTC calendar
dates and excludes Rejected records; it does not reverse later record changes.
The provider validator additionally requires source-record timestamps at or
before its exact reference timestamp. Current October 2026 graph/CVSS values
must not be reused as predictors for an earlier cutoff.

Historical replay requires a timezone-aware cutoff and uses only events with
`created_at <= cutoff`; publication after the cutoff is excluded. Added,
Changed and Removed details are replayed from supported new/old values. An
uncertain initial state, unsupported change or missing history remains an
explicit exclusion rather than a zero-valued node. Strict combined replay
requires supported CPE, CWE and any relevant Affected streams. Exploratory
layer replay gates CPE and CWE independently; another layer's uncertainty or
an unsupported Affected link does not invent or suppress independently
supported legacy-layer evidence. These are distinct documented scopes.

Missing history, invalid history, unavailable/unsupported evidence,
`known_no_active_relationships`, and not-yet-published states remain distinct.
No current snapshot, later Affected URL, or post-cutoff event repairs an earlier
unknown state. Pilot graph centralities depend on the eligible population at
that cutoff and must not be pooled across separately built graph scopes.

Original event strings are retained. Naive event timestamps are assumed UTC;
this remains an explicitly unverified project assumption. Recorded event dates
do not prove that the information was publicly available at that date. The
temporal filters are implemented controls, not independent historical evidence.

## Archived KEV labels and chronological evaluation boundary (tooling excluded)

The existing exploratory outcome is a CISA KEV catalog addition within 30 days
after the cutoff, using the frozen 2026-10-15 catalog. Date-only `dateAdded`
values are interpreted at UTC midnight. Existing classification distinguishes:

- Publication at or after cutoff: `not_published_at_cutoff`, unlabeled.
- Addition at or before cutoff: `already_in_kev_at_cutoff`, unlabeled.
- Addition in `(cutoff, cutoff + 30 days]`: `positive_within_horizon`.
- No addition in a fully observed horizon: `negative_full_horizon_observed`.
- A horizon not fully observed: `censored_horizon_not_fully_observed`, unlabeled,
  unless a positive has already been observed.

Labels use strict publication-before-cutoff eligibility, whereas relationship
replay permits publication exactly at cutoff. The stricter label gate takes
precedence when joining. No equality cases occur in the verified saved labels.
The five saved horizons are mature; their zero censored counts do not permit
future censored records to be treated as negatives. A negative denotes no KEV
addition under the frozen catalog target, not absence of real exploitation.

The established readiness assessment verified all 1,665,890 saved label rows.
The local corpus has 499 valid histories; none of those CVEs is a future KEV
positive at any of the five requested 30-day cutoffs. At 2026-01-01, dated
event-time evidence is usable for 400 CPE, 340 CWE and 323 both-layer CVEs.
These counts do not certify public availability or predictive validity.

Graph-only is partially ready as descriptive infrastructure. Historical CVSS
is not validated and historical EPSS is unavailable; CVSS-only, EPSS-only,
CVSS + EPSS and CVSS + EPSS + Graph predictive comparisons are not supported.
No defensible chronological predictive dataset or metrics were manufactured.
Precision@10/25/50 requires supported rankings/cohorts; Recall@10/25/50 and AUC
are undefined on the local future-outcome cohorts without positives. Lift and
incremental AUC lack valid baselines/common cohorts; the missed-risk definition
is unresolved. See the existing readiness report for the full classification,
not a new evaluation in this handoff.

## Current-snapshot cluster deliverable and missed-risk protocol

`outputs/c_graph_cvss_cluster_exploration_2026-10-16_run3/` contains:

- `cvss_high_critical_candidates.csv`: 165,226 current CVSS HIGH/CRITICAL CVEs.
- `product_weakness_cluster_edges.csv`: 326,076 product/CWE co-occurrences,
  with sorted CVE membership lists; 149,666 CVEs contribute to clusters.
- `cvss_product_weakness_clusters.png`: a descriptive current-record heatmap.
- `analysis_metadata.json`: snapshot, selection rule, counts and interpretation.

The final audit independently checks every saved edge count and membership
against the saved candidate relationships and verifies deterministic edge
ordering. The analysis and image are not regenerated. CVSS severity is impact
severity, not exploitation probability. EPSS and KEV placeholders remain
unavailable, and the severity-filtered population is not a validated high-risk
or missed-risk evaluation cohort. The image shows a limited product/CWE view;
it is not an exhaustive risk ranking. Rendering can vary with environment;
byte-identical image reproduction is not established.
Zero heatmap cells denote no observed co-occurrence within that selected
population; they are aggregate counts, not imputed missing CVE features.

No authoritative missed-risk rule is present in the local project documents.
This is pending protocol clarification, not a broken implementation. Candidate
interpretations for clarification only are: future positives missed by a
baseline top-K ranking; future positives below a CVSS severity threshold;
future positives below an EPSS threshold; or baseline/graph ranking discordance.
These define different populations and denominators. None is selected, no
threshold is invented, and no missed-risk value is calculated. A HIGH/CRITICAL
CVSS cluster is not a substitute for any of these definitions.

## Component D integration guidance

For a scalar component input, use the final percentile adapter; its columns
map to the shared `Score` contract (`component=c_graph`, `score_kind=ranking_score`). The complete
feature provider is a superset and can be joined to another table by
`(cve_id, decision_time)`. Confirm snapshot and graph identity and preserve
`status`, evidence statuses, reasons, and blank numeric values. Do not
zero-fill missing scores or treat missing relationship evidence as a known
empty relationship set. PageRank and degree centrality are structural
indicators, not calibrated exploitation probabilities.

Integration checklist:

1. Check the expected CSV columns and schema version.
2. Require unique `(cve_id, decision_time)` keys and verify the expected
   snapshot and graph scope.
3. Map only the shared Score fields when the consumer expects `Score`; carry
   feature and evidence statuses separately if it needs those fields.
4. Preserve null/blank score and feature values and the accompanying status and
   reason. Do not map them to zero.
5. Test this mapping in the actual Component D loader before claiming
   integration.

No real Component D consumer has been integrated or tested in this repository.
The current handoff is documentation-ready; consumer compatibility beyond the
shared Score dataclass and CSV shape remains unverified.

## Reproduction and verification

Run the focused contract test and current-snapshot provider tests:

The subsequent structural-disagreement extension passed **216 offline tests**
(202 Component C plus 14 shared Score tests), Ruff lint, Ruff format check
(52 files including shared contract tests), and `git diff --check`. Its results
and compatibility boundary are recorded with the new analysis artifacts;
the earlier implementation-audit records below are retained as dated evidence.

```powershell
.venv/Scripts/python.exe -m pytest tests/components/c_graph/test_feature_provider.py -q
.venv/Scripts/python.exe -m pytest tests/components/c_graph/ -q
```

Validate the saved CSV directly without regenerating it:

```powershell
.venv/Scripts/python.exe -c "import pandas as pd; from vesper.components.c_graph.feature_provider import validate_feature_provider; p='outputs/c_graph_feature_provider_2026-10-17_run2/c_graph_feature_provider.csv'; validate_feature_provider(pd.read_csv(p), reference_timestamp='2026-10-15T00:00:00Z')"
```

The release-candidate audit verified 333,178 unique CVE rows and the shared
Score counts above. The expected CSV SHA-256 is
`dd6175aa0961b4aed9ea3533634a29d7ff80320b18f28a8096007b5b265a38fc`; compare
the file hash before using a copy. The existing metadata's `output_sha256`
contains the same value.

Final verification results are recorded in
`outputs/c_graph_final_handoff_audit_2026-10-17_run1/validation_results.json`
and the final audit document: **183 Component C tests passed**; Ruff lint
passed; Ruff format check passed for 48 files; `git diff --check` passed.
The saved CSV is checked directly, including
333,178 unique CVEs, 31 columns, metadata consistency and the SHA-256 above.

Use the existing `.venv` commands for offline validation without dependency
installation or access to uv's global cache. Ruff checks cover the Component C
source package, tests and its scripts. Tests use mocked HTTP and temporary
fixtures; they do not invoke live collection. Test coverage includes parser
normalization, graph construction, hand-calculated degree/PageRank fixtures,
temporal exclusion, replay states, KEV eligibility/censoring, contracts,
cluster aggregation/rendering and durable collection-budget safeguards in the
archived broader suite. Excluded historical/collection tests are not part of
the minimal PR suite.

For an explicitly requested future reproduction, graph and cluster CLI recipes
are available through `python -m vesper.components.c_graph.pipeline --help`,
and
`scripts/analyze_c_graph_cvss_clusters.py --help`. The provider reproduction
recipe is in the schema guide. All write-producing recipes require separate
new output locations; they were not run during this audit. A fixed input
manifest, hashes, snapshot, graph scope and environment are necessary to
compare results. Sorted inputs/rows and a non-random graph calculation do not
guarantee byte-identical floating-point or image output across environments.
The final audit hashes inspected graph/provider/cluster artifacts, without
backfilling missing original generation metadata.

## Limitations and remaining research work

- These are graph structural indicators, not calibrated exploitation
  probabilities; no predictive lift is established.
- The 30-day horizon is an interface field, not an independently learned
  Component C prediction horizon.
- The current graph uses current NVD records and is not a validated
  point-in-time reconstruction for the full research population.
- Historical predictive evaluation is not validated for that population.
- Historical EPSS baselines and independent historical CPE validation remain
  unresolved.
- Historical CVSS is unvalidated, the available history cohort lacks future
  positive cases, and authoritative missed-risk/combined-baseline protocol
  definitions remain unresolved. These are evidence/protocol limitations,
  not reasons to manufacture an evaluation implementation or results.
- Run3's 116 naive event timestamps retain the unverified UTC interpretation.
  Its 20 June 2026 GitHub-linked Affected details are after every evaluated
  cutoff and cannot establish pre-cutoff product relationships. Complete
  retrieval provenance does not prove complete or historically public data.
- The extracted vendor/product abstraction does not preserve all NVD CPE
  version ranges or logical applicability semantics.
- No real Component D consumer has been exercised; downstream integration
  remains an acceptance task for that component's developer.
