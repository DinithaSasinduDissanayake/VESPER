# Component C Feature Provider Schema and Component D Handoff

## Separate historical abstention panel

The current feature provider and latest percentile adapter remain unchanged.
The separate `scripts/export_c_graph_historical_panel.py` export uses the full
research manifest times 44 monthly UTC-midnight decisions, 2023-01-01 through
2026-09-01 excluding 2024-12-01. It preserves the shared 11 Score columns and
one `(cve_id, decision_time)` row even when the CVE is unpublished or history is
missing. Every score is intentionally blank and every status is `abstained`.
Not-yet-published rows use `cve_not_published_at_decision_time` and do not enter
any graph or percentile population. No current or later score is backfilled.

This is not a historical feature provider containing numerical graph features.
Strict relationship replay supplies specific diagnoses only; incomplete graph
context and unverified historical public availability prevent certified scores.
No graph or scoring calculation occurs. `horizon_days=30` is downstream evaluation
metadata, not a trained exploitation target; `trained_through` remains blank.
Historical rows use `c_graph-pagerank-percentile-historical-structural-0.1`.

The streamed CSV and adjacent `.csv.metadata.json` preserve source/manifest
identity, per-cutoff coverage, all concurrent diagnoses and deterministic primary
reason precedence. See [historical panel handoff](COMPONENT_C_HANDOFF.md#historical-abstention-panel)
for CLI, source conflict rules, and evidence required before numerical historical
scores could be released. Current provider evidence must never be used to fill
this panel's historical missing values.

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

## Purpose and scope

`c_graph_feature_provider.csv` is a versioned, manifest-scoped feature-provider
table for one **current NVD record snapshot**. It reuses the graph and score
outputs produced for the 2026-10-15 snapshot and adds supported relationship
evidence plus source and snapshot provenance. It is not a historical graph
reconstruction, a calibrated exploitation probability, a model-performance
result, or evidence that Component D integration has been completed.

For the concise downstream handoff, integration checklist, and current saved
artifact integrity details, see [`COMPONENT_C_HANDOFF.md`](COMPONENT_C_HANDOFF.md).

The separate [Structural-Scalar Disagreement experiment](COMPONENT_C_STRUCTURAL_DISAGREEMENT.md)
preserves the shared Score fields while percentile-ranking raw PageRank for
the final D-facing CSV. It does
not replace this detailed provider or introduce CVSS/KEV into the structural
score. Analysis percentiles/differences are separate research outputs.

Use the validated run2 artifacts listed in the handoff. The following is an
offline reproduction recipe, not a step to execute during handoff. It reuses
existing graph data; choose a new, unoccupied output directory if reproduction
is explicitly requested:

```powershell
.venv/Scripts/python.exe scripts/export_c_graph_feature_provider.py `
  --nvd-dir data/raw/nvd `
  --full-graph-features outputs/c_graph_full_snapshot_2026-10-15/features.csv `
  --population-features outputs/c_graph_full_snapshot_2026-10-15/research_population/research_population_features.csv `
  --scores outputs/c_graph_full_snapshot_2026-10-15/research_population/c_graph_scores.csv `
  --manifest data/processed/c_graph/research_population.csv `
  --snapshot-at 2026-10-15T00:00:00Z `
  --output-dir outputs/NEW_OFFLINE_PROVIDER_REPRODUCTION
```

The command refuses a non-empty output directory. Choose a new run ID for each
export. It validates and hashes the supplied artifacts and local monthly NVD
files, but does not rebuild the graph or fetch data. The underlying graph scope
includes all eligible non-Rejected NVD CVEs in the local snapshot; the rows are
filtered to the research manifest after graph statistics were calculated.

## Schema v1.0.0

The CSV begins with all columns of the shared `Score` contract, in the same
order, followed by Component C feature and provenance fields. The adjacent
metadata JSON records the schema version, graph scope, counts, input hashes,
and output hash.

| Field | Type | Meaning and missing-value rule |
| --- | --- | --- |
| `cve_id` | string | CVE identifier; one row per CVE in this single-snapshot table. |
| `component` | string | Always `c_graph`, matching the shared score contract. |
| `decision_time` | ISO-8601 UTC timestamp | Score-contract decision time. Must equal `reference_timestamp`. |
| `horizon_days` | positive integer | Interface horizon carried by the existing score export; it does not make C a 30-day predictor. |
| `score` | nullable float in [0,1] | Raw PageRank ranking value in this detailed provider. Blank when the shared score status is not available. Never a calibrated probability. |
| `score_kind` | string | `ranking_score`; shared `ScoreKind`. |
| `status` | enum string | Shared `ScoreStatus`: `available`, `abstained`, `not_eligible`, or `already_exploited`. Non-available statuses require a blank score and a non-empty reason. |
| `reason` | nullable string | Blank/null for available scores; non-empty explanation for non-available statuses. CSV output serializes null as an empty field, which readers may load as null. |
| `model_version` | string | Existing Component C score implementation identifier. |
| `trained_through` | nullable UTC timestamp | Blank for this non-trained structural feature calculation. |
| `snapshot_date` | date | UTC date of the reference timestamp. |
| `reference_timestamp` | ISO-8601 UTC timestamp | Exact reference time for this row; identical across the file. |
| `snapshot_id` | string | Stable identifier such as `nvd-current-snapshot-2026-10-15`. |
| `feature_schema_version` | string | `1.0.0`. |
| `graph_scope_id` | string | Snapshot ID plus hash prefix of the full graph feature file. Use it to avoid comparing values from different graph populations as if they shared a scale. |
| `in_degree_centrality` | nullable dimensionless float in [0,1] | CVE incoming degree divided by `N - 1`, where `N` is the full graph node count. Defined as zero when `N < 2`. |
| `out_degree_centrality` | nullable dimensionless float in [0,1] | CVE outgoing degree divided by `N - 1`, with the same full-graph node count and small-graph behavior. |
| `pagerank` | nullable dimensionless float in [0,1] | NetworkX PageRank on the same full graph and population as the score. It sums to 1 across all graph nodes and must equal `score` when available. |
| `in_degree_status`, `out_degree_status`, `pagerank_status` | enum string | Mirror the shared score status. Non-available rows have blank corresponding numeric values. |
| `vendor_product_evidence_json` | JSON array string or blank | Sorted explicit vendor/product pairs extracted by the existing NVD parser. Blank when no supported pair was extracted; it does not assert a known-empty set. |
| `cpe_evidence_status` | enum string | `supported`, `unavailable`, or `not_evaluated`. `supported` requires a non-empty evidence array; unavailable values remain blank. |
| `cpe_evidence_reason` | nullable string | `no_supported_relationship_extracted_from_record` or `record_not_eligible_in_snapshot` where applicable. |
| `cwe_ids_json` | JSON array string or blank | Sorted explicit CWE IDs extracted by the existing parser. Blank when no supported CWE was extracted. |
| `cwe_evidence_status` | enum string | `supported`, `unavailable`, or `not_evaluated`, with the same blank-value rule as CPE evidence. |
| `cwe_evidence_reason` | nullable string | Explicit explanation when CWE evidence is unavailable or not evaluated. |
| `source_record_published_at` | ISO-8601 UTC timestamp | Publication timestamp from the local NVD record; also checked against the research manifest. |
| `source_record_last_modified_at` | ISO-8601 UTC timestamp | Last-modified timestamp from that record; checked against the snapshot cutoff. |
| `source_nvd_file` | string | Local monthly NVD source filename containing the CVE record. |
| `feature_provenance` | string | Identifies the saved graph plus local NVD record as the source. |

### Status and missingness

The `Score` status describes whether the existing current-snapshot graph export
produced a score row. Layer evidence status describes what the existing parser
could explicitly extract from the current NVD record. These are separate
dimensions: a CVE can have an available structural score and unavailable CPE
or CWE evidence. `unavailable` means no supported relationship value was
extracted; the current parser does not reliably distinguish absent, empty,
malformed, or unsupported source fields for this snapshot export. The export
therefore does not claim a known-empty relationship state. It never fills a
blank score or unavailable score feature with numeric zero. Existing calculated
degree values of zero are retained as calculated graph values, not substituted
for missing values; interpret them alongside evidence status and the parser
limitations above.

### Graph and feature calculation

The graph is a directed `networkx.DiGraph` with namespaced vendor, product,
CVE, and CWE nodes. Its edge types are vendor → product (`offers`), product →
CVE (`affected_by`), and CVE → CWE (`has_weakness`). The builder adds no edge
weight attribute, so PageRank treats every edge as unit weight. A `DiGraph`
does not retain parallel edges between the same node pair.

In-degree and out-degree centrality use NetworkX's directed degree-centrality
functions: the corresponding degree divided by `N - 1`, with `N` the node
count of the full graph. For fewer than two graph nodes, Component C defines
centrality as zero. These dimensionless values are calculated before rows are
filtered to the research population.

PageRank uses `networkx.pagerank` defaults: damping factor `alpha=0.85`,
`max_iter=100`, `tol=1e-6`, uniform default personalization, and the `weight`
edge attribute. Since the graph has no weight attributes, edges have equal
unit weight. PageRank is normalized over every node in the full graph; the
exported CVE subset therefore need not sum to 1. Both PageRank and degree
centralities depend on graph scope and relationship extraction rules.

`horizon_days` is a required field carried by the shared `Score` interface. It
does not mean these structural values were trained to predict an outcome over
that horizon.

The NVD snapshot export's known rejected rows have `status=not_eligible`, blank
score and graph features, blank relationship arrays, and `not_evaluated` layer
evidence. The existing score file currently contains 315,515 available and
17,663 not-eligible rows out of 333,178 manifest CVEs.

Example eligible row (illustrative values):

```csv
CVE-2024-12345,c_graph,2026-10-15T00:00:00+00:00,30,0.012,ranking_score,available,,c_graph-pagerank-structural-0.1,,2026-10-15,2026-10-15T00:00:00+00:00,nvd-current-snapshot-2026-10-15,1.0.0,nvd-current-snapshot-2026-10-15-graph-<hash>,0.2,0.1,0.012,available,available,available,"[[""vendor"",""product""]]",supported,,"[""CWE-79""]",supported,,2024-01-10T00:00:00+00:00,2024-01-15T00:00:00+00:00,nvd_2024-01.json.gz,saved_current_snapshot_graph_and_local_nvd_record
```

Example not-eligible row (numeric feature fields remain blank):

```csv
CVE-2024-23456,c_graph,2026-10-15T00:00:00+00:00,30,,ranking_score,not_eligible,NVD marks this CVE as Rejected at the snapshot cutoff.,c_graph-pagerank-structural-0.1,,2026-10-15,2026-10-15T00:00:00+00:00,nvd-current-snapshot-2026-10-15,1.0.0,nvd-current-snapshot-2026-10-15-graph-<hash>,,,,not_eligible,not_eligible,not_eligible,,not_evaluated,record_not_eligible_in_snapshot,,not_evaluated,record_not_eligible_in_snapshot,2024-01-10T00:00:00+00:00,2024-01-15T00:00:00+00:00,nvd_2024-01.json.gz,saved_current_snapshot_graph_and_local_nvd_record
```

## Component D handoff

For the scalar component input, use
`outputs/c_graph_structural_scalar_disagreement_2026-10-17_run1/c_graph_scores.csv`
as the shared `Score` contract. Its score is the relative PageRank structural
percentile over all available provider rows (average-rank ties), with version
`c_graph-pagerank-percentile-structural-0.2`. Higher means greater relative graph
structural importance, NOT exploitation probability. `horizon_days=30` is shared
interface metadata, not a validated 30-day Component C prediction target.
The provider CSV is a feature/evidence supplement; its original `score` remains
raw PageRank and its version remains unchanged. Do not overwrite the adapter
score/version when joining this supplement.
Join on `(cve_id, decision_time)` and verify `snapshot_id`, `graph_scope_id`,
`component`, `score_kind`, and `status`. Preserve blanks and statuses through
the join. Do not map missing values to zero. Do not interpret PageRank as an
exploitation probability or compare scores from different graph scopes as
though they were calibrated on a common scale.

No Component D consumer is present in this repository, so compatibility has
been validated against the shared `Score` dataclass and the exact saved score
CSV schema, not against a deployed downstream loader. Historical pilot exports
remain exploratory and are not this current-snapshot provider input.

## Limitations

- Local monthly files are current record snapshots partitioned by publication
  month; they are not archived versions of each CVE at prior dates.
- This export reuses the graph built from those current records and does not
  establish historical relationship availability.
- The parser's current snapshot `Vulnerability` interface represents extracted
  relationships as tuples; a missing tuple cannot prove that NVD affirmatively
  reported no relationship.
- Vendor/product evidence is an abstraction from legacy affected data and
  explicitly vulnerable CPE criteria. It does not preserve CPE applicability
  logic, version bounds, or all affected-version semantics in the graph.
- CWE evidence is limited to explicit `CWE-n` values recognized by the parser.
- Degree centrality and PageRank depend on the complete graph population and
  local extraction rules. A population filter is applied after graph
  calculation, so these values are not recomputed within the 333,178 targets.
- No independent historical CPE validation, KEV predictive evaluation,
  Component D execution, or predictive improvement is claimed.
