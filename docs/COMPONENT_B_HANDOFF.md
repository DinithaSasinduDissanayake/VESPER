# Component B (exploit timing) handoff for Component D

This page tells Component D which files B produces, what each column means,
how to produce them again, and what the scores cannot tell you. The decisions
and numbers behind it are in
[COMPONENT_B_DATA_DECISIONS.md](COMPONENT_B_DATA_DECISIONS.md), sections 16
and 17.

## What the score means

B's model is a Cox proportional-hazards model. For a CVE that is `age` days old
at the decision time and not yet in CISA KEV, it estimates "listed in KEV
within the next 30 days":

```text
raw = 1 - S(age + 30 | x) / S(age | x)
```

`x` is what is known on the publication day: CVSS score and vector parts,
`exploit_at_publication` (an Exploit-DB exploit on or before publication), and
the top 10 CWE IDs of the train set. The model is trained on post_kev CVEs
(published on or after 2021-11-03) published before `trained_through`.

The raw value has the form of a probability, but its calibration has not been
checked on held-out data. **Treat every B score as a ranking score, not a
probability.** `score_kind` is always `ranking_score`.

The D-facing files hold the **percentile rank** of the raw value among the
CVEs available at the same decision time: rank / N, with tied CVEs sharing the
average rank, so the score is in (0, 1] and 1 is the highest. This puts B on
the same scale as C's percentile, so D's mean of 0-1 inputs is fair.

## Files

All files are written to `outputs/b_survival/` (git ignores it). Every CSV has
exactly the 11 Score columns and one row per CVE ID:

`cve_id, component, decision_time, horizon_days, score, score_kind, status,
reason, model_version, trained_through, snapshot_date`

| File | Score | Use |
|---|---|---|
| `b_exploit_timing_scores.csv` | percentile | **D reads this** (current scores) |
| `b_exploit_timing_probability.csv` | raw estimate | reference, same rows and statuses |
| `history/run-NNN/b_exploit_timing_history_<T>.csv` | percentile at T | **D reads these** (one per decision time) |
| `history/run-NNN/b_exploit_timing_probability_history_<T>.csv` | raw estimate at T | reference |

Each CSV has a `.metadata.json` next to it. The history run has one
`history.metadata.json` with the grid, the train rows and events, the counts
per status and the number of zero raw estimates per decision time, the SHA-256
of every file and of the input survival table, the code version (git commit)
and the limits below.

Fixed values:

- `component`: `b_survival`
- `horizon_days`: 30
- `snapshot_date`: 2026-10-01 (the data snapshot), unless set otherwise
- `decision_time`: 00:00 UTC, written as `2026-10-01T00:00:00+00:00`
- `trained_through`: the same as `decision_time` (never later)

## How to run

Run `survival_table` first (see the data-decisions page). Then:

```powershell
# Current scores (decision time 2026-10-01 00:00 UTC)
uv run python -m vesper.components.b_survival.score_export

# Historical scores: 27 monthly decision times, 2024-07-01 to 2026-09-01
uv run python -m vesper.components.b_survival.score_history

# Historical scores at other dates (00:00 UTC each)
uv run python -m vesper.components.b_survival.score_history --decision-times 2025-01-01,2025-07-01
```

`score_export.main()` takes `decision_time` and `snapshot_date`, so B can match
another agreed decision context. `score_history` takes about 3.5 minutes with 3
workers and writes 2.3 GB. Each history run goes to a new `run-NNN` folder; an
existing run is never overwritten.

## Statuses

The status is decided in this order. Every status except `available` has an
empty score and a reason.

| Status | Rule |
|---|---|
| `already_exploited` | listed in KEV before the decision day. **Exclude these** from labels and evaluation. |
| `not_eligible` | published before 2021-11-03, outside B's post_kev cohort |
| `abstained` | no CVSS 3.x score (a model input is missing), or age + 30 days is past the longest train follow-up (the estimate would be extrapolated) |
| `available` | scored |

A CVE listed in KEV on or after the decision day is scored normally: from the
point of view of the decision time it is not listed yet.

## Version rules

- `model_version` is `b_survival-cox-<trained_through>-0.2` (raw) and
  `b_survival-cox-percentile-<trained_through>-0.2` (percentile). Each history
  decision time has its own model, so its own version.
- The last number changes when the features or the method change. 0.2 uses
  a piecewise-constant baseline hazard; 0.1 (history run-001) used lifelines'
  step baseline and gave 17-32% exact zeros. Do not mix 0.1 and 0.2 rows.
- A historical score is never replaced by one computed from newer data. A new
  run is a new folder.

## Labels are D's job

B does not label. D adds `kev_within_horizon` (listed in KEV within 30 days
after the decision time) itself from the KEV table. Every history decision time
is at most 2026-09-01, so every label window ends by the snapshot.

## Limits: what cannot be reconstructed

- **The history is a retrospective replay, not a point-in-time record.** The
  NVD fields (CVSS, CWE) come from the current NVD snapshot. A CVSS score that
  NVD added or changed after a decision time is used at that time, so some
  information from the future leaks into the inputs. The model training, the
  KEV outcome and the exploit dates are cut at the decision time; the NVD
  fields are not.
- **KEV and Exploit-DB dates are used as dated.** Deleted entries are missing,
  and backdated entries cannot be detected.
- **Version 0.1 only: raw estimates of exactly 0.** The 0.1 baseline only
  changed on days when a train CVE was listed, so 17-32% of the available CVEs
  at each decision time scored exactly 0. Version 0.2 has no zeros (section 19
  of the data-decisions page).
- **A KEV listing is not the first attack.** B predicts KEV listing, which can
  come long after the first exploitation.
- **Early decision times are not covered.** Before 2024-07-01 the post_kev
  train sets have too few events for a stable model.
