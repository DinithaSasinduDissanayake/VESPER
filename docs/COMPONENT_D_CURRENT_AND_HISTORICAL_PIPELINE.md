# Component D current ranking and historical experiment

## Current five-signal demo

The current demo is a transparent composite ranking, not a trained D model. It
uses the latest supplied A and B outputs, current C PageRank percentiles, and
the current CVSS/EPSS baseline. The joins use `cve_id` after selecting the
2026-10-01 A snapshot and B's 30-day rows. The assembled cohort is their shared
population also present in the current C and CVSS/EPSS files.

Each available signal is converted to its within-cohort percentile rank, then
the available normalized ranks are averaged with equal weights. Missing or
abstained values are excluded from that row's mean and are reported through
status, reason, signal count, and coverage fields. The score is relative to the
current candidate cohort; it is not a probability or a validated risk estimate.

The handoffs are mixed-date: A's source snapshot is 2026-10-11, B's decision
snapshot is 2026-10-01, current C and CVSS use 2026-10-15, and EPSS uses
2026-10-01. The output records those dates and is labeled as a mixed-snapshot
provisional ranking. The A/B handoff documents possible later-NVD-information
leakage in historical scores. Do not use this current ranking as a historical
test result.

Patch effort is estimated from CVSS severity tiers: Low 2 hours, Medium 4,
High 8, and Critical 16. This is a planning assumption, not measured patch
time. Rows without CVSS have no effort estimate and cannot be scheduled until
an estimate is supplied.

Run from the repository root:

```powershell
uv run python -m vesper.components.d_fusion.provisional_pipeline
```

The default data artifacts are local and ignored by Git:

- `data/raw/component_a_b/VESPER_A_B_scores_full_historical.zip`
- `data/processed/component_c/c_graph_scores.csv`
- `data/processed/d_fusion/historical_cvss_epss_labeled.parquet`
- `outputs/d_fusion/first_version/fused_first_version_dataset.csv` (preferred
  current CVSS/EPSS baseline source)
- `data/processed/d_fusion_baselines.parquet` (fallback CVSS/EPSS baseline)

Current ranking outputs:

- `data/processed/d_fusion/current_five_signal_fused.parquet`
- `outputs/d_fusion/current_provisional/ranked_current_five_signal.csv`
- `outputs/d_fusion/current_provisional/source_and_methodology.json`

## Historical four-signal experiment

The historical panel joins A, B 30-day scores, CVSS, EPSS, and the existing
30-day future KEV labels by `(cve_id, decision_time)`. It keeps Component C's
historical abstention status and reason for audit, with `score_c` blank and
excluded from the feature matrix. The tested feature set is A + B + CVSS + EPSS.

The C handoff is 2.66 GB and is entirely abstained. The pipeline reads it once
and writes only the matching three mature A/B snapshot cohorts to
`data/processed/component_c/c_graph_historical_scores_ab_panel.csv`. The
complete handoff metadata is retained beside it. The October 2026 A/B snapshot
has no matching historical CVSS/EPSS label panel yet and its D 30-day outcome
has not matured as of 2026-10-21, so it is not used for supervised evaluation.

The pipeline trains logistic regression and shallow gradient boosting on the
2025-10-01 and 2026-01-01 rows, then reports one exploratory holdout on
2026-04-01. It also reports EPSS and CVSS baselines. This is not a model
selection procedure: there is one held-out date, only nine KEV positives on
that date, and no independent validation period. The A/B documentation also
reports that historical A text and B CVSS/CWE features may contain later NVD
edits. Treat all metrics as exploratory.

Historical panel and experiment outputs:

- `data/processed/d_fusion/historical_first_version_four_signal.parquet`
- `data/processed/d_fusion/historical_first_version_four_signal.csv`
- `data/processed/d_fusion/historical_first_version_summary.json`
- `outputs/d_fusion/historical_ab_exploratory/exploratory_metrics.json`
- `outputs/d_fusion/historical_ab_exploratory/heldout_test_rankings.csv`

For first-time C panel alignment, pass the source path:

```powershell
uv run python -m vesper.components.d_fusion.provisional_pipeline `
  --historical-c-source D:\Downloads\c_graph_historical_scores.csv
```

## FastAPI and UI

Start the API and frontend separately from the repository root:

```powershell
uv run uvicorn vesper.api.main:app --reload
```

```powershell
cd frontend
bun run dev
```

The backend serves the configured current ranking through `GET
/api/d-fusion/ranking` and its CSV through `GET /api/d-fusion/ranking.csv`.
Set `VESPER_RANKING_CSV` to override the default current ranking path.

The Sprint Planner shows the full paginated ranking and downloads the complete
ranking CSV. It sends planner settings to `POST /api/d-fusion/knapsack`. The
request contains team size, daily hours, planning period, and start date. Daily
plans cover one workday; weekly plans cover five Monday-Friday workdays; monthly
plans cover 22 Monday-Friday workdays. The backend reruns the daily 0/1
knapsack for each workday using remaining candidates and returns scheduled and
deferred CVEs with dates and reasons. Weekly/monthly sequencing is greedy across
days, not a globally optimal multi-bin knapsack. Holidays, task dependencies,
and patcher skill differences are not modeled.

Ranking order and patch selection remain distinct: the ranking orders risk
signals; knapsack selects tasks under estimated person-hour capacity. Business
criticality defaults to 1 unless provided as an override.
