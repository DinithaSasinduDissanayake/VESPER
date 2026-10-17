# Component D ranking and model selection

`ensemble.py` turns the fused CVE table into a high-to-low risk ranking. It
also compares four candidate approaches when a historical, labeled feature
table is available:

- `epss`: EPSS-only reference ranking.
- `cvss`: normalized CVSS-only reference ranking.
- `equal_weight`: arithmetic mean of available EPSS, normalized CVSS, and A/B/C
  scores. This is the provisional pipeline model used with dummy data.
- `logistic_regression`: class-weighted, L2-regularized logistic regression
  trained on point-in-time component and baseline scores, with training-only
  median imputation, standardization, and missingness indicators.

The current 120-row dummy fixture is one decision snapshot and its A/B/C scores
are synthetic. The generator also excludes current KEV CVEs. It can validate
the mechanics of sorting and fusion, but it cannot provide a valid training
target or select the research model. Until real temporal outputs and labels are
available, `equal_weight` is marked provisional.

## Produce a current ranking

After generating the fused fixture, run:

```powershell
uv run python -m vesper.components.d_fusion.ensemble rank
```

By default this reads `dummy_inputs/fused_dummy_dataset.csv`, scores using the
available-signal equal-weight mean, and writes
`outputs/d_fusion/ranked_vulnerabilities.csv`. Rows are sorted by `risk_score`
descending and have a one-based `risk_rank`. Use `--input` and `--output` to
point at other files. To inspect an individual reference ranking:

```powershell
uv run python -m vesper.components.d_fusion.ensemble rank --model epss
uv run python -m vesper.components.d_fusion.ensemble rank --model cvss
```

If a selected-model artifact exists at
`data/processed/d_fusion/selected_ensemble_model.json`, `rank` uses it by
default. Passing `--model` explicitly runs that candidate instead. The artifact
is local generated data and is not committed.

## Select a model after real outputs arrive

Prepare a CSV with one row per `(cve_id, decision_time)` and these columns:

| Column | Meaning |
| --- | --- |
| `cve_id` | Vulnerability key. |
| `data_origin` | Must be `real`; this prevents model selection from dummy fixtures. |
| `decision_time` | Timestamp when the features would have been known. |
| `label_matured_at` | Date the future-window outcome is fully known. |
| `horizon_days` | Forward outcome window, such as 30 days. |
| `kev_within_horizon` | 1 if first KEV inclusion occurs after decision time and within the horizon; otherwise 0, only when the whole window is observed. |
| `epss_score`, `cvss_base_score` | EPSS and CVSS available at that decision time. |
| `score_a`, `score_b`, `score_c` | Actual component outputs available at that decision time; unavailable scores stay empty. |

Do not use current KEV membership as a substitute for the future label. Exclude
CVEs already in KEV at decision time, avoid using information published later,
and do not label an immature observation as a negative. The data must contain
at least five distinct decision snapshots. Label maturity is purged across the
chronological boundaries so a training label cannot use outcomes from the
validation period, and a validation label cannot use outcomes from the test
period. Rows marked synthetic, or carrying synthetic component model versions,
are rejected by the selection command.

Run selection with the date through which held-out test labels are known:

```powershell
uv run python -m vesper.components.d_fusion.ensemble select `
  --labeled-data data/processed/d_fusion/historical_labeled_features.csv `
  --evaluation-as-of 2026-10-01
```

Replace `2026-10-01` with the actual latest date through which the KEV outcome
labels are observed in that historical dataset.

The code assigns earlier snapshots to training, the next period to validation,
and the latest period to a final holdout test. It chooses by macro average
precision across decision dates; NDCG@20 breaks ties, followed by the EPSS
reference. It also reports Precision@20 and Recall@20. The test period is only
reported, not used to select the candidate. The selected algorithm is refit on
the pre-test data and its artifact plus a model-comparison JSON report are
written under `data/processed/d_fusion/` and `outputs/d_fusion/` respectively.
Candidate metrics use the same rows with both EPSS and CVSS present; A/B/C
abstentions remain eligible and are handled as missing features.

This script provides an initial, reproducible comparison. Before research use,
the team should agree on the horizon, point-in-time feature availability,
label maturity, and primary metric. A model should only be called the final
model after the real component outputs and held-out temporal results have been
reviewed. Results on synthetic data are not evidence for model selection.
