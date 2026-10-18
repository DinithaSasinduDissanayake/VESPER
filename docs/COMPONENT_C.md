# Component C: Relationship-aware Structural Graph Features

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

The refined C contribution is relationship-aware structural prioritization,
not exploitation-probability prediction. The remaining current-snapshot
experiment and real downstream adapter are described in
[Structural-Scalar Disagreement Analysis](COMPONENT_C_STRUCTURAL_DISAGREEMENT.md).
The final adapter percentile-ranks the provider raw PageRank; CVSS and KEV do not enter
the C-to-D score. D owns final fusion and predictive ranking.

For final implementation status, verified current-snapshot artifacts and
research limitations, use the final audit (archived external report: `COMPONENT_C_FINAL_AUDIT.md`; excluded from this PR) and
[handoff guide](COMPONENT_C_HANDOFF.md). Historical collection is stopped.
This guide describes both historical replay and current-snapshot capability;
neither establishes historical predictive validation.

Component C builds a directed graph from current NVD records or supported
cutoff-specific reconstruction of NVD CVE change history,
calculates graph features, and can export those features through the shared
`vesper.contracts.score.Score` contract. The implementation is in
`src/vesper/components/c_graph/`.

## Archived population and acquisition context

The research population is defined by NVD `published` timestamps in UTC over
`[2016-01-01T00:00:00Z, 2026-10-15T00:00:00Z)`. The manifest at
`data/processed/c_graph/research_population.csv` has `cve_id,published`
columns. The builder reads the monthly NVD snapshots under `data/raw/nvd/`;
the multi-history pipeline validates the manifest before selecting history
files. CVE ID year is not used as a publication-date filter.

History responses are collected by `scripts/download_nvd_history.py`. The
downloader validates paginated responses, retries retryable failures, supports
resume, writes validated response files atomically, and emits a collection
report. `--limit` bounds CVEs, not HTTP attempts; durable request reservations
govern request-attempt ceilings. Collection is stopped, and the acquisition
description here is reference material only. A missing local file means
history is unavailable locally; it does not mean the CVE has no relationships.
A valid empty response is distinct from missing or invalid history and is not
proof that the CVE has no affected products or weaknesses.

## Retained reconstruction logic and archived research context

`multi_historical_pipeline.py` filters history files through the population
manifest and reconstructs each selected CVE at an explicit timezone-aware
`snapshot_at`. CVEs whose manifest publication timestamp is after that cutoff
are excluded from the graph and recorded as `not_yet_published_at_cutoff`.
Events after that cutoff are excluded. Interpretable
relationships are vendor → product (`offers`), product → CVE (`affected_by`),
and CVE → CWE (`has_weakness`). Affected references without interpretable
vendor/product values are reported as warnings; relationships are not
fabricated.

### Historical relationship evidence

The parser preserves event IDs, timestamps, source identifiers, event names,
and original old/new values for CPE Configuration, CWE, and Affected details.
Legacy CPE Configuration values are parsed as CPE applicability text; the
graph retains only vendor/product pairs while preserving complete original
configuration strings on parsed events. CWE values are parsed for explicit
`CWE-n` identifiers. Added, Changed, and Removed events use their new-value,
old/new-value, and old-value fields respectively. Unknown actions or incomplete
values exclude that CVE at the cutoff.

Embedded Affected JSON is supported only when it is a non-empty JSON array and
every row has explicit vendor and product names plus interpretable version
status evidence. A vendor/product edge is emitted only when at least one
`defaultStatus`, version status, or version change explicitly says `affected`.
Rows that are explicitly unaffected add no edge. Unknown or absent status,
missing vendor/product names, package-only identifiers, and unparseable
payloads are classified as uncertain or unsupported and exclude the CVE.
Affected-derived edges are tracked separately from CPE-derived edges, so a
removal in one evidence stream does not erase a relationship still supported
by the other. Version ranges and status transitions are not represented in the
graph score itself.

NVD's June 2026 update added CVE Record Format Affected data to records and
their histories. Its August 26, 2026 history-format update replaced embedded
Affected JSON in audit entries with a GitHub URL reference. The saved corpus
contains examples such as `New affected value received` with a link to the
`CVEProject/cvelistV5` `main` branch. That link is mutable and does not identify
an immutable revision corresponding to the audit timestamp. The current linked
CVE record therefore cannot establish historical affected state for that
event. The parser does not follow such links or infer products from URLs;
link-only records receive `github_reference_unrecoverable` and
`unsupported_affected_relationship_change` exclusions. This may make later
cutoffs unavailable for CVEs whose affected-data history is link-only, even
when earlier CPE events were interpretable.

These supported events provide a conservative vendor/product graph
abstraction, not a complete reconstruction of affected version ranges or all
historical relationships. A CVE with no interpretable initial state, an
unsupported change, or an unrecoverable Affected reference is excluded; it is
not represented by a zero-valued feature row. `history_complete` remains false
because the event history does not establish that every initial and subsequent
relationship was captured.

Feature inclusion is conservative: a CVE must have interpretable CPE and CWE
event streams by the cutoff, each stream's first relevant event must establish
an addition, and changes must contain interpretable values. When Affected
events exist by the cutoff, they must also be supported embedded data with a
known initial state. A valid empty history response, an unsupported affected
change, an unrecoverable GitHub reference, or an uncertain initial state is
excluded with explicit reason codes; none is treated as an empty relationship
graph. Missing history, invalid responses, and reconstruction failures are
also exclusions, never zero-filled feature rows. This gate means the
relationship state is interpretable under this policy; it does not prove that
NVD captured every original relationship. `history_complete` therefore
remains false.

The graph is built from histories successfully reconstructed at the cutoff;
only feature-eligible CVEs contribute nodes or edges. Features are global to
that graph, so a subset's centrality values can change when the selected
CVE/history population changes.

The feature CSV schema is exactly:

`cve_id,in_degree_centrality,out_degree_centrality,pagerank`

Degree centralities and PageRank are structural graph measurements. They are
not calibrated exploitation probabilities or evidence of model performance.
The feature metadata JSON reports the population size, snapshot cutoff,
history/response/reconstruction/feature counts, graph scope, warnings, and the
separate exclusions CSV. Exclusion reasons distinguish at least missing
history, invalid history, reconstruction failure, and files not processed due
to a limit.

## Archived exploratory CPE/CWE layer metadata (tooling excluded)

`scripts/analyze_c_graph_layer_comparison.py` writes separate exploratory CPE
and CWE outputs. Each layer's `metadata.json` uses schema version `2.0`,
reported as `metadata_schema_version`. This version separates CVEs not yet
published at the requested cutoff from published CVEs whose relationship
evidence is unavailable or unsupported. It does not change the graph,
eligibility policy, or feature CSV schema.

The metadata counts use these denominators:

| Field | Meaning and denominator |
| --- | --- |
| `metadata_schema_version` | Metadata contract version. Consumers should check it before interpreting fields. |
| `population_cves` | All CVEs in the supplied evaluation sample frame. |
| `published_by_cutoff_cves` | Sample-frame CVEs published at or before `snapshot_at`. |
| `not_published_at_cutoff_cves` | Sample-frame CVEs published after `snapshot_at`. |
| `evidence_eligible_cves` | Published CVEs whose relationship state is supported for this layer under its inclusion policy. |
| `evidence_ineligible_cves` | Published CVEs with uncertain or unsupported relationship evidence for this layer. |
| `known_empty_relationship_cves` | Evidence-eligible published CVEs with no active relationships at the cutoff. This is a subset of `evidence_eligible_cves`. |
| `feature_rows` | CVEs with active relationships and numeric feature rows. Known-empty states do not produce rows. |
| `feature_unavailable_published_cves` | Published CVEs without numeric feature rows, including evidence-ineligible and known-empty CVEs. |
| `feature_unavailable_population_cves` | All sample-frame CVEs without numeric feature rows, including not-yet-published CVEs. |
| `feature_status_counts` | Counts of `available`, `known_no_active_relationships`, and `unavailable` across the full sample-frame population. |
| `published_feature_status_counts` | The same status counts, restricted to CVEs published by the cutoff. |
| `evidence_exclusion_reason_counts` | Counts of each evidence exclusion reason among published evidence-ineligible CVEs. |
| `publication_exclusion_reason_counts` | Counts of publication-time exclusion reasons among CVEs not published by the cutoff. |
| `feature_unavailability_reason_counts` | Counts of evidence-related reasons among published evidence-ineligible CVEs plus the known-empty reason. It excludes future-publication reasons, which are reported separately in `publication_exclusion_reason_counts`. |

The CVE-count partitions must satisfy both invariants:

```text
population_cves = published_by_cutoff_cves + not_published_at_cutoff_cves
published_by_cutoff_cves = evidence_eligible_cves + evidence_ineligible_cves
```

Known-empty relationship states are evidence-eligible, but have no numeric
features because no active graph relationship contributes a feature row.
Missing, uncertain, or unsupported evidence is unavailable; it must not be
converted to a numeric zero. Reason counts may overlap when one CVE has more
than one reason, so do not sum them to infer unique-CVE totals. Graph degree
and PageRank values are structural measures within the reported graph scope,
not calibrated exploitation probabilities.

### Migrating saved v1 metadata

Saved v1 layer metadata used `unavailable_cves` and
`exclusion_reason_counts`. Neither has a direct one-to-one alias in v2:
v2 separates publication exclusions, evidence exclusions, and feature
availability. A consumer migrating a saved v1 JSON file must first choose
the intended denominator. For evidence-only counts use
`evidence_exclusion_reason_counts`; for not-yet-published CVEs use
`publication_exclusion_reason_counts`; for feature gaps use the relevant
`feature_unavailable_*_cves` field and `feature_unavailability_reason_counts`.
These categories are not interchangeable. Existing v1 outputs are not
rewritten, and backward compatibility for direct v1-field readers is not
claimed.

Layer `outcomes.csv` records each CVE's `feature_status` and reason. Numeric
feature columns are blank when a feature is unavailable, including for
known-empty states; blanks are not zero scores. The separate
`score_export.py` adapter does not automatically read layer comparison
outcomes or metadata. A downstream caller that needs to distinguish a
known-empty state from other missing features must carry the corresponding
status and reason explicitly when preparing its score inputs.

## Detailed-provider raw PageRank score records

`score_export.py` is a separate adapter from the feature table to the shared
`Score` dataclass. It maps raw PageRank to `component=c_graph` and
`score_kind=ranking_score`. It does not transform PageRank into a probability.
The caller must provide a positive `horizon_days` and timezone-aware
`snapshot_at`; decision time is the UTC-normalized snapshot time, and
`snapshot_date` is its UTC date. `trained_through` is empty because this
structural calculation has no training data. Every target CVE receives one
record; missing feature rows are never zero-filled. Known rejected CVEs can be
marked `not_eligible`, while other unavailable feature rows `abstained`, each
with an explanatory `reason`. Scores are validated by constructing the shared `Score`
records. No separate Component D loader or validator is present in this
repository, so downstream integration should validate against its deployed
consumer as well.

The CSV columns follow the shared contract exactly:

`cve_id,component,decision_time,horizon_days,score,score_kind,status,reason,model_version,trained_through,snapshot_date`

The adjacent `.metadata.json` records score semantics, source feature path,
cutoff, horizon, and available/abstained counts. The detailed-provider model version is
`c_graph-pagerank-structural-0.1`.

### Snapshot graph and archived population-export recipe

When a full single-cutoff dataset is needed without collecting every CVE
change-history response, use the local monthly NVD CVE records. These files
are publication-month partitions of current CVE records, not archived monthly
versions of each CVE. The snapshot pipeline builds global features from all
eligible non-Rejected records and filters exported feature rows through the
research manifest. CVEs outside the research interval can remain as graph
context and affect global centralities. Rejected target CVEs receive
`not_eligible` score records; other targets without features abstain.

This route describes current NVD record state at one cutoff. It does not
restore earlier relationship states for each CVE and must not be described as
per-CVE historical reconstruction. The local copies used for the 2026-10-15
snapshot were downloaded between 2026-10-13 and 2026-10-14. NVD's current
feeds update over time ([NVD data feeds](https://nvd.nist.gov/vuln/data-feeds));
use archived source versions or CVE change histories for historical backtests
at earlier decision times.

Archived recipe from the broader checkout: population export and visualization
tooling below are excluded from this minimal PR. This is not a final pipeline
execution recipe:

```powershell
.venv\Scripts\python.exe -m vesper.components.c_graph.pipeline `
  --nvd-dir data\raw\nvd `
  --snapshot-date 2026-10-15 `
  --output outputs\c_graph_snapshot\all_nvd_graph_features.csv

.venv\Scripts\python.exe scripts\export_c_graph_snapshot_population.py `
  --nvd-dir data\raw\nvd `
  --full-graph-features outputs\c_graph_snapshot\all_nvd_graph_features.csv `
  --manifest data\processed\c_graph\research_population.csv `
  --output-dir outputs\c_graph_snapshot\research_population `
  --snapshot-at 2026-10-15T00:00:00Z `
  --horizon-days 30

.venv\Scripts\python.exe scripts\visualize_c_graph_snapshot.py `
  --graph-metadata outputs\c_graph_snapshot\all_nvd_graph_features.metadata.json `
  --population-metadata outputs\c_graph_snapshot\research_population\research_population_features.metadata.json `
  --output outputs\c_graph_snapshot\research_population\graph_overview.png
```

The PNG is a schema and scale overview with node counts, relationship types,
cutoff, and population coverage. It is not a node-by-node rendering; a layout
of more than half a million nodes and 1.7 million edges would not be readable.

## Archived historical reproduction (tooling excluded)

The following collection and manifest-building commands require excluded
external tooling and are retained solely as research provenance. They are not
steps in the final executable pipeline.

Build or refresh the population manifest only when the destination is
intended to be replaced:

```powershell
.venv\Scripts\python.exe scripts\build_c_graph_research_population.py
```

Collect bounded history into a dedicated directory (the downloader reads
`.env` by default when available; do not place credentials in outputs or Git):

```powershell
.venv\Scripts\python.exe scripts\download_nvd_history.py `
  --input data\raw\nvd\nvd_2024-01.json.gz `
  --output-dir outputs\c_graph_smoke\history `
  --limit 3
```

Build features at a declared historical cutoff:

```powershell
.venv\Scripts\python.exe -m vesper.components.c_graph.multi_historical_pipeline `
  --history-dir outputs\c_graph_smoke\history `
  --snapshot-at 2026-10-15T00:00:00Z `
  --manifest data\processed\c_graph\research_population.csv `
  --output outputs\c_graph_smoke\features.csv
```

Call `export_graph_scores` from
`vesper.components.c_graph.score_export` with the feature DataFrame, target
IDs from the validated manifest, the same snapshot timestamp, and the
interface's chosen horizon. It writes the score CSV and metadata next to it.

## Validation and current smoke result

The Component C suite is run with:

```powershell
.venv\Scripts\python.exe -m pytest tests\components\c_graph\ -q
.venv\Scripts\ruff.exe format --check src\vesper\components\c_graph\ tests\components\c_graph\
.venv\Scripts\ruff.exe check src\vesper\components\c_graph\ tests\components\c_graph\
```

The bounded end-to-end smoke output is in
`outputs/c_graph_e2e_2026-10-15/`. It used three previously collected target
histories: 3 valid responses, 3 reconstructed CVEs, 3 feature rows, 12 graph
nodes, 9 edges, and 3 reconstruction-warning CVEs. Against the 333,178-row
manifest, 333,175 CVEs had no local history in that smoke input directory and
were explicitly excluded from the feature table and abstained in the score
table. This is an execution/contract smoke test, not full-population
collection, representative sampling, historical completeness, or scientific
validation. The three affected events whose payloads lacked interpretable
CPE vendor/product values remain warnings.
