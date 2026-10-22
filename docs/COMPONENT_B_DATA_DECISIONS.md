# Component B — Data decisions

This file records the decisions made while cleaning the data, and the reason
for each one. Every number was printed by a cleaning module on the raw files
described in [COMPONENT_B_DATA_SNAPSHOT.md](COMPONENT_B_DATA_SNAPSHOT.md) (snapshot date 2026-10-01). "How to check" at
the end gives the commands.

## 1. The study starts in 2016, not 2015

**What I found.** Almost no CVE published in 2015 has a CVSS version 3 score.
Version 3 was new in 2015, so those CVEs only have a version 2 score, which
uses different metrics.

**The number.** 6,260 of the 6,494 CVEs published in 2015 have no CVSS 3.1 or
3.0 score (96.4%). In 2016 it is 218 of 6,449 (3.4%). From 2017 to 2023 it is
13 CVEs in total.

**What I decided.** The study includes CVEs published from 2016-01-01
(`STUDY_START` in `study_design.py`). The cleaning modules keep the 2015 rows;
the survival table step leaves them out.

**Why.** CVSS is the main covariate. A year in which it is missing for nearly
every CVE cannot be used to estimate its effect, and mixing version 2 and
version 3 metrics would make the hazard ratios hard to interpret.

## 2. A non-Primary CVSS score is used when NVD has no Primary one

**What I found.** A CVE can have several CVSS entries. A "Primary" entry is
NVD's own score. Other entries come from another source, usually the
organisation that reported the CVE. Many CVEs have no Primary entry.

**The number.** Of the 316,477 CVEs kept, the score used is Primary for
193,393 and non-Primary for 106,306. The other 16,778 have no CVSS 3.x score.

**What I decided.** Version 3.1 is preferred, then 3.0. Inside a version the
Primary entry is preferred; if there is none, the first entry listed is used.
The column `cvss_is_primary` records which case applies to each CVE.

**Why.** Using only Primary scores would leave about one third of the CVEs
without CVSS. A score from the reporting organisation is still a real CVSS
score that a defender can see. Because the column is kept, the analysis can
be repeated on Primary scores only as a check.

## 3. CVSS and CWE values are not the values on the publication day

**What I found.** NVD gives each record as it is on the day it is downloaded.
It does not give the history of a record. NVD often adds the CVSS score and
the CWE days or weeks after a CVE is published, and can change them later. So
the values in the clean table are the values around the snapshot date, not the
values a defender saw on the publication day.

**The number.** The share of CVEs with no CVSS 3.x score is 0.8% for 2024,
5.7% for 2025 and 9.6% for 2026 (7,198 of 74,612). The most recent CVEs are
the ones still waiting for a score, which shows that scores arrive after
publication.

**What I decided.** All results of Component B are labelled "retrospective":
they use the CVSS and CWE values known at the snapshot, for CVEs published
before it. No result is described as a prediction made on the publication day.

**Why.** It is the honest description of the data. A public source of the
day-by-day history of each NVD record was not part of this study, so this
limit cannot be removed, only stated.

## 4. 3,355 CVEs were edited by NVD after the snapshot date

**What I found.** The snapshot date is 2026-10-01, but 141 of the 142 NVD
files were downloaded on 2026-10-06 (see [COMPONENT_B_DATA_SNAPSHOT.md](COMPONENT_B_DATA_SNAPSHOT.md)). Records that NVD
edited between those days may hold values from after the snapshot.

**The number.** 3,355 of the 316,477 CVEs kept have a last-modified date after
2026-10-01 (1.1%). Of these, 1,409 were also published after the snapshot and
will be left out of the survival table anyway.

**What I decided.** This is accepted as a known limit. The rows are kept and
flagged in the column `modified_after_snapshot`, so the analysis can be
repeated without them as a check.

**Why.** The affected share is small, and NVD does not say what was changed in
each edit, so the earlier values cannot be restored. Flagging keeps the
problem visible and does not hide it.

## 5. 15 mistyped ExploitDB CVE IDs were repaired

**What I found.** In ExploitDB the CVE IDs are typed by hand in the `codes`
column. A few have a typing mistake, so they do not match the CVE ID pattern.

**The number.** 15 CVE IDs were accepted after repair. 10 other codes that
start with "CVE" were not repaired and not used, for example `CVE-n/a`,
`CVE-2017-18344.` and `CVE-2015- 5698`.

**What I decided.** The repair rule (`tidy_code` in `clean_exploitdb.py`)
makes only three changes, then the ID is checked against the pattern again:

1. remove spaces at the start and the end;
2. replace a dash character that only looks like "-" (for example an en dash)
   with a real "-";
3. change small letters to capital letters.

Anything else is not repaired.

**Why.** These three changes cannot turn one CVE ID into a different one, so
no ID is guessed. A code that would need a guess, such as removing a full stop
or a space inside the number, is rejected and printed in the report.

## 6. How the duration and the event are defined

**What I found.** Most CVEs are not in KEV at the snapshot date. That does not
mean they are safe: it only means they were not listed yet.

**The number.** The survival table has 308,574 CVEs (one per study CVE). 1,534
are events (listed in KEV up to the snapshot) and 307,040 are censored.

**What I decided.**

- `duration_days` is the number of calendar days (UTC) from the publication day
  to the KEV day, if the CVE is in KEV, or to the snapshot day (2026-10-01) if
  it is not. This is the same definition as `eda.py`.
- `event` is 1 if the CVE is listed in KEV up to the snapshot, and 0 if it is
  censored.

**Why.** A censored CVE is known to be unexploited up to the snapshot, and the
model should use that time. Counting calendar days (not hours) matches the
source: KEV and ExploitDB give only a day. A CVE published on the snapshot day
that is not in KEV gets duration 0 and stays censored.

## 7. CVEs listed in KEV before their publication date are kept and flagged

**What I found.** For some CVEs the KEV listing day is before the NVD
publication day, so the duration is negative.

**The number.** 65 CVEs. All 65 were published after KEV started.

**What I decided.** The rows stay in the table and the duration is not changed
(not set to 0 and not clipped). The column `already_exploited` is True for
them. They are not removed.

**Why.** Dropping them would hide a real feature of the data: exploitation was
confirmed before NVD published the CVE. Keeping the true value and the flag
lets the analysis be run with and without them, which is the sensitivity
analysis promised in the proposal. The table does not remove them silently, so
the model step must filter on `already_exploited` itself. This matters because
`lifelines` accepted a negative duration without an error or a warning when
tested on a small made-up table (Kaplan–Meier and Cox).

## 8. CVEs listed on the first day of KEV are flagged as a group

**What I found.** KEV started on 2021-11-03 with a large group of CVEs that
had been exploited earlier, sometimes years earlier. For these CVEs the KEV day
means "the catalogue started", not "exploitation was confirmed on this day".

**The number.** 282 CVEs in the study have 2021-11-03 as their KEV day (the KEV
file itself has 287; the rest were published before the study start).

**What I decided.** They stay in the table as events, flagged by
`kev_launch_group`.

**Why.** Their durations are long because the catalogue did not exist, not
because exploitation was slow. This is the reason the median time to KEV is
152 days for all events but only 8 days for the CVEs published after
2021-11-03 (`eda.py`). The flag allows a model without this group.

## 9. Zero-day durations stay as events

**What I found.** Some CVEs are listed in KEV on the same day they are
published.

**The number.** 164 events have a duration of 0 days.

**What I decided.** They stay as events with duration 0. They are not moved to
0.5 days and not removed.

**Why.** Same-day listing is a real result and an important one: these are the
CVEs for which a defender has no time. A duration of 0 is valid for the
methods used (Kaplan–Meier and Cox use the order of the times).

## 10. There is no "has any exploit" column

**What I found.** ExploitDB gives the day an exploit was published. An exploit
can appear before the CVE is published, on the same day, or months afterwards.

**The number.** 334 of the 1,534 KEV CVEs have an ExploitDB exploit at any
time up to the snapshot, but only 68 (4.43%) had one on or before their
publication day. Among all 308,574 CVEs it is 0.75% (`eda.py` and
`survival_table.py`).

**What I decided.**

- The Day-0 input `exploit_at_publication` is True only when the first exploit
  is dated on or before the publication day.
- The date `exploit_first_date` is kept separately, for the time-varying model.
- A plain "has any exploit" column is not created.

**Why.** A column that says "this CVE has an exploit" would be True for CVEs
whose exploit appeared months after publication, and those are mostly CVEs that
were attacked. The model would be learning from the future (look-ahead
leakage). The first exploit date lets a model switch the covariate on only
from the day the exploit appears.

## 11. ExploitDB is the only source of exploit code, and the outcome is never an input

**What I found.** The proposal names ExploitDB as the source of public exploit
code. Other sources exist but are not part of the study yet.

**What I decided.**

- ExploitDB is the only exploit source used now. The function
  `first_exploit_dates` takes a list of exploit tables, so a second source can
  be added to the list later without changing the rest.
- The `verified` column of ExploitDB is never read.
- The KEV date is used only to make `duration_days`, `event`,
  `already_exploited` and `kev_launch_group`. It is not written to the survival
  table, so it cannot become an input by accident. A test changes the KEV dates
  and checks that every input column stays the same.
- Five checks run before the table is saved, and a failed check stops the
  save: no duplicate CVE IDs, `event` only 0 or 1, no publication date after
  the snapshot, no negative duration except for `already_exploited`, and a row
  count equal to the study CVE count of `link_sources.py`. All five found 0
  problems.

**Why.** Keeping outcome and inputs apart is the main protection against
leakage, and it is one of the rules of the project (CONTRIBUTING.md).
## 12. Chronological split

**What I found.** A model must be judged on CVEs that come after the ones it
learned from, and the training data must not know anything from after the
cut-off. The survival table, however, was built at the snapshot date, so on its
own it knows how every CVE ended up.

**The numbers.** The cut-off dates are 2022-01-01, 2022-07-01, 2023-01-01 and
2024-01-01. They are proposed and wait for team agreement (`CUTOFF_DATES` in
`study_design.py`). Printed by `split_data`:

| Cut-off | Train rows | Train events | Test rows | Test events |
|---|---|---|---|---|
| 2022-01-01 | 93,374 | 300 (0.32%) | 25,041 | 99 (0.40%) |
| 2022-07-01 | 105,725 | 610 (0.58%) | 26,790 | 104 (0.39%) |
| 2023-01-01 | 118,415 | 666 (0.56%) | 28,803 | 152 (0.53%) |
| 2024-01-01 | 147,218 | 836 (0.57%) | 39,843 | 153 (0.38%) |

**What I decided.**

- Train is every CVE published before the cut-off. Test is every CVE published
  from the cut-off for 365 days (`MATURITY_DAYS`).
- The cut-off is the start of the cut-off day (00:00 UTC). A KEV listing or an
  exploit dated on the cut-off day itself is therefore treated as not known.
- The train set is re-censored at the cut-off. An event that happened on or
  after the cut-off becomes event = 0 with duration = cut-off minus publication
  day. This turns 404, 157, 137 and 119 train events into censored rows for the
  four cut-offs. A row that was censored at the snapshot is also cut back to
  the cut-off.
- In the train set, an exploit date on or after the cut-off is removed (68,
  69, 107 and 78 rows), and `kev_launch_group` is cleared when its event was
  re-censored.
- The test set keeps its follow-up up to the snapshot date, unchanged.
- CVEs with `already_exploited` = True are removed from both sets (negative
  durations), and `kev_launch_group` stays as a column. 32, 28, 13 and 7 CVEs
  leave the test sets this way.
- Nine leakage checks run for every cut-off, and nothing is saved if one fails.

**Why.**

- *Re-censoring.* At the cut-off a defender could not know that a CVE would be
  listed two years later. If the train set kept that event, the model would
  learn from the future and its test result would look better than it is. A
  CVE that has not been listed by the cut-off is "not exploited yet", which is
  exactly what a censored row says.
- *The cut-off day.* The prediction is made at the start of the cut-off day,
  and test CVEs are published from that day. Counting a listing on the cut-off
  day as known would let one day of the future into training. Only 1 train
  event in the four cut-offs is dated exactly on its cut-off day, so the choice
  changes almost nothing, but the rule is the safe one.
- *The test window of 365 days.* The Brier score is reported at 30, 90 and 365
  days. A test CVE needs at least 365 days of follow-up for the 365-day
  horizon to be settled, and the proposal withholds CVEs whose outcome is not
  settled. With these cut-offs, every test CVE has at least 365 days before the
  snapshot, and a check enforces it. A window that is too long would also make
  the test set drift from the situation at the cut-off.

**Limits.**

- The CVSS and CWE values in the train set are still the values on the
  download days (decision 3). The split cannot restore the values of the
  cut-off date, so results stay "retrospective".
- Test windows of neighbouring cut-offs overlap (2022-01-01 and 2022-07-01
  share half a year), so the four results are not independent.
- Each test set has about 100 to 150 events, so confidence intervals will be
  wide.
## 13. Kaplan–Meier and log-rank

**What I found.** Only 1,469 of the 308,509 CVEs used are events. The
Kaplan–Meier survival curve S(t), the share of CVEs NOT yet listed in KEV,
stays above 99% for every group, so differences between groups cannot be seen
on it.

**The numbers.** Printed by `kaplan_meier` for the main analysis: the
cumulative incidence of KEV listing at 365 days is 0.31% (95% CI 0.29–0.33)
overall, 0.94% (0.85–1.04) for critical CVSS, 0.37% (0.34–0.41) for high and
0.08% (0.07–0.10) for medium. The median time to listing is "not reached" in
every group, because no group reaches 50%.

**What I decided.**

- The figures and tables show the cumulative incidence, 1 − S(t): the share of
  CVEs listed in KEV by day t. It is reported at 30, 90 and 365 days with a 95%
  interval (Greenwood's formula on the log(−log) scale, the `lifelines`
  default), and plotted from 0 to 1,095 days.
- A median that is not reached is reported as "not reached", not estimated.
- If a group had no event up to a day, the incidence is 0 and no interval is
  given ("no events"): Greenwood's formula gives a width of zero then, which
  would look like certainty. After the longest follow-up of a group (for
  example 365 days for CVEs published in 2026) no value is given.
- The 65 `already_exploited` CVEs are dropped before any curve is fitted,
  because `lifelines` accepts negative durations without a warning (decision 7).
- The main analysis uses the other 308,509 CVEs. A sensitivity analysis also
  drops the 280 `kev_launch_group` CVEs (308,229 left).
- Groups: CVSS v3 severity bands (none 0.0, low, medium, high, critical) plus
  missing; attack vector plus missing; `exploit_at_publication` yes or no; the 5
  CWE IDs found in the most CVEs plus other and missing; and publication year.
  A CVE with several CWEs goes to its highest-ranked top-5 CWE, so that every
  CVE is in exactly one group.
- Each grouping gets an overall log-rank test (`multivariate_logrank_test`).
  Groupings with more than two groups also get pairwise tests, corrected with
  Holm's method.

**Why.**

- *Cumulative incidence.* With rare events, 1 − S(t) shows the same
  information as S(t) on a scale where the groups can be told apart.
- *already_exploited and kev_launch_group.* A negative duration has no meaning
  on a survival curve. The launch-group CVEs are kept in the main analysis
  because they really were exploited, but their durations measure the start of
  KEV, not exploitation, so the sensitivity analysis shows whether they drive
  the results. Every log-rank test stays below p = 0.00001 without them.
- *Descriptive only.* CVSS and CWE are the values on the download days, not on
  the publication day (decision 3), and the groups are not compared under equal
  conditions. A difference between curves is not a cause, and these results
  are not predictions. With more than 300,000 CVEs almost any difference gives
  a tiny p-value, so the size of the incidence matters more than the p-value.

**Limits found in this step.**

- *KEV did not exist before 2021-11-03.* A CVE published in 2016–2019 could
  not be listed within 365 days of publication; their incidence at 365 days is
  0.00 (no events). Pooling all years mixes CVEs that could be listed early with
  CVEs that could not. This also explains why `exploit_at_publication` = yes
  has a lower 365-day incidence (0.17%) than no (0.31%) while its log-rank test
  is large: most of those CVEs are old and were listed years later. A curve
  restricted to CVEs published from 2021-11-03 would not have this problem.
- *CVSS missing.* The 10,043 CVEs without a CVSS 3.x score have 0 events. A
  likely reason is that NVD scores a CVE soon after it is listed in KEV, so
  missing CVSS partly reflects the outcome. `cvss_missing` should be treated
  with care as a model input.
- *Crossing curves.* The log-rank test is weakest when curves cross, as the
  year curves do. Its p-values are reported but not used to rank groups.
## 14. Post-KEV cohort

**What I found.** KEV started on 2021-11-03 (`KEV_START_DATE`). A CVE published
before that day could not be listed in KEV until the catalogue existed, so its
time to listing measures the start of KEV as much as exploitation. Section 13
showed the effect: CVEs published in 2016–2019 have 0.00% at 365 days (no
events), and `exploit_at_publication` = yes looked lower than no.

**The numbers.** Printed by `kaplan_meier` and `split_data`:

- The post_kev cohort has 218,492 CVEs (published from 2021-11-03), against
  308,574 in the full cohort. After dropping the 65 `already_exploited` CVEs,
  218,427 are used. None of the remaining post_kev CVEs is in
  `kev_launch_group`, so its sensitivity analysis equals its main analysis.
- Cumulative incidence at 365 days: 0.36% (0.34–0.39) in post_kev against
  0.31% (0.29–0.33) in full.
- `exploit_at_publication` in post_kev: yes is 144 CVEs with 4 events and
  2.19% (0.71–6.66) at 365 days; no is 218,283 CVEs with 784 events and 0.36%
  (0.34–0.39); log-rank p = 9.73e-06. In the full cohort the same comparison
  was 0.17% for yes against 0.31% for no.
- Publication year matters much less in post_kev (log-rank χ² 16.9, p = 0.0048,
  1 of 15 pairs below Holm p < 0.05) than in full (χ² 104.1, 33 of 55 pairs).
- Train events per cut-off in post_kev: 5 (2022-01-01), 47 (2022-07-01), 79
  (2023-01-01) and 216 (2024-01-01). The test sets are the same in both cohorts,
  because every cut-off is after 2021-11-03.

**What I decided.**

- Two cohorts (`COHORTS` in `study_design.py`): **post_kev is the main cohort
  for modelling**, and **full is the comparison**. `KEV_START_DATE` is written
  once, in `study_design.py`; `clean_kev.py` imports it from there.
- `survival_table.filter_cohort` selects a cohort: post_kev keeps CVEs
  published from 00:00 UTC on 2021-11-03 (a CVE from 2021-11-02 23:59:59 is
  out).
- `split_data` makes the splits of both cohorts, in
  `splits/<cohort>/train_<cut-off>.csv` and `test_<cut-off>.csv`, and runs every
  leakage check on both, plus a check that every row belongs to its cohort.
  Nothing is saved if any check fails in either cohort.
- A train set with fewer than 100 events is kept. A warning is printed and
  recorded in `splits/split_summary.csv`. This happens for the post_kev
  cut-offs 2022-01-01, 2022-07-01 and 2023-01-01.
- `kaplan_meier` runs the same groupings for both cohorts, in
  `outputs/b_survival/kaplan_meier/<cohort>/`.

**Why.**

- *post_kev as the main cohort.* In this cohort every CVE could be listed from
  its publication day, so "days to KEV listing" means the same thing for every
  CVE. That is the quantity the research question is about. The full cohort
  mixes it with the start of the catalogue.
- *full as the comparison.* It is larger and was used in the earlier steps, so
  reporting both shows how much the choice of cohort changes the results.
- *Keeping small train sets.* Dropping a cut-off without saying so would hide a
  real limit of the data. With 5 or 47 events a Cox model is not reliable, and
  results for those cut-offs must be read with that in mind.

**Limits.**

- Only one post_kev cut-off (2024-01-01) has at least 100 train events. With a
  365-day test window and 365 days of follow-up after it, the latest possible
  cut-off is about 2024-10-01, so later cut-offs could add at most a few
  months. The cut-off dates are still proposed and wait for team agreement.
- The `exploit_at_publication` = yes group in post_kev has only 144 CVEs and 4
  events, so its interval is wide (0.71–6.66%).
## 15. Cox model and evaluation

**What I found.** The Cox model was fitted on every train set of both cohorts
and measured on the matching test set. post_kev is the main analysis and full
is the comparison (section 14). The numbers below are printed by `evaluate`.

**Features (Day-0 only, `features.py`).** `cvss_base_score` (standardised),
the four CVSS vector parts (one dummy per level, the most common level is the
reference), `exploit_at_publication`, and one dummy for each of the 10 CWE IDs
found in the most train CVEs (every other CWE, and no CWE, is the reference).
Everything is learned on the train set only and then applied unchanged to the
test set. A feature that never changes in a train set is dropped there.

**Excluded columns, and why.**

- `in_kev`, `kev_date_added`: the outcome.
- `exploit_first_date`: the exploit can appear after day 0 (decision 10).
- `kev_launch_group`, `already_exploited`: made from the KEV date.
- `cvss_missing`: CVEs without CVSS had 0 events (section 13), so missing CVSS
  partly reflects the outcome. CVEs without a CVSS score are left out of train
  and test instead: 0 to 231 train rows and 1 to 321 test rows per split, all
  with 0 events.

**Models and baselines.**

- `cox`: Cox model on all features, with a small ridge penalty (0.01). Some
  train sets have very few events and some dummies are rare; without a penalty
  a coefficient can run off to infinity. Because of the penalty the intervals
  of the hazard ratios are approximate.
- `cvss_cox`: Cox model on the CVSS score only.
- `cvss_rank`: test CVEs ranked by the CVSS score itself (current practice).
  It has no "listed by day t" estimate, so no Brier score.
- `km_reference`: the train Kaplan–Meier curve for every CVE (no features), the
  reference for the Brier score.

**Metrics.**

- Harrell's c-index (lifelines), 0.5 = random.
- Brier score at 30, 90 and 365 days with inverse probability of censoring
  weights (IPCW), and the Brier skill at 365 days, 1 − Brier(model) /
  Brier(km_reference).
- P@100: the share of the 100 highest-risk test CVEs listed in KEV within 365
  days. CVEs tied at the 100th place are shared out evenly, because CVSS scores
  have many ties.
- 95% intervals from 1,000 bootstrap resamples of the test set, seed 20261001,
  the same resamples for every model.

**A change from the plan: the censoring weights come from the test set.** The
plan was to fit the censoring Kaplan–Meier on the train set. The split
re-censors every train CVE at the cut-off (section 12), so train censoring is
made by the split and does not describe the test set: for post_kev, G(365) on
the train set is 0.000 at the cut-offs 2022-01-01 and 2022-07-01, which makes
the weights undefined, and 0.496 at 2024-01-01. The test CVEs are only
censored at the snapshot, after at least 365 days, so G(365) on every test set
is 1.000. The censoring curve is therefore taken from the test set being
evaluated, as in Graf et al. (1999). This uses only follow-up lengths, not
model inputs.

**Results.**

- *Ranking (main cohort, latest cut-off).* post_kev 2024-01-01: c-index 0.775
  (0.741–0.808) for `cox` against 0.763 (0.731–0.793) for `cvss_rank`. The
  intervals overlap, so the Cox model has not been shown to rank better than
  CVSS.
- *Earlier post_kev cut-offs* have only 5, 47 and 79 train events, and the Cox
  model ranks worse than CVSS at 2022-01-01 (0.688 against 0.728) and 2022-07-01
  (0.693 against 0.710), and better at 2023-01-01 (0.710 against 0.681).
- *full cohort:* `cox` 0.731, 0.721, 0.710 and 0.759, against 0.728, 0.710,
  0.681 and 0.763 for `cvss_rank`; again with overlapping intervals.
- `cvss_cox` and `cvss_rank` always give the same c-index and P@100: a Cox
  model with one feature only rescales it, so the order is the same.
- *Brier.* Every model, including the no-feature reference, has almost the
  same Brier score, because only 0.32–0.46% of test CVEs are listed within 365
  days. The Brier skill over the reference is at most 0.0020 (post_kev
  2024-01-01), and -0.0001 at post_kev 2022-07-01.
- *P@100* is between 0.00 and 0.03: at best about 2 of the 100 highest-risk
  CVEs are listed within a year, against a base rate of 0.32–0.46%.
- *Hazard ratios* (post_kev, 2024-01-01): `exploit_at_publication` 3.59
  (1.08–11.86); CVSS 1.10 per point (1.06–1.15); CWE-79 0.79 (0.64–0.98) and
  CWE-89 0.75 (0.57–1.00). In full: `exploit_at_publication` 2.10 (1.64–2.68)
  and CVSS 1.15 per point (1.12–1.18).

**Proportional-hazards check.** The Schoenfeld-residual test
(`proportional_hazard_test`, rank time scale) on the post_kev 2024-01-01 train
set finds 1 of 19 features below p = 0.05: `exploit_at_publication`
(p = 0.044). With 19 tests about one such result is expected by chance, so the
evidence is weak, but it is the feature with the largest effect. A stratified or
time-varying model for it is the next step. The check was not run on the full
cohort: lifelines needs more than 10 minutes for its 147,000 train rows
(`PH_CHECK_COHORTS` in `evaluate.py`).

**Limits.**

- At the post_kev cut-offs 2022-01-01 and 2022-07-01 the longest train
  follow-up is shorter than 365 days, so the 365-day estimates are extrapolated
  (marked * in the printed table).
- The logistic-regression baseline of the proposal (same features, same split)
  is not done yet; it is the comparison the research question asks for.
- A paired bootstrap of the difference between `cox` and `cvss_rank` (the same
  resamples are already used for both) would test the difference directly.
## 16. Score export to Component D

**What I did.** `score_export` writes one shared `Score` record per CVE to
`outputs/b_survival/b_exploit_timing_scores.csv`, the file Component D reads.
The numbers below are printed by `score_export`.

**Model and times.** The Cox model of section 15, fitted with the same rules:
post_kev CVEs published before `trained_through`, re-censored at that day, CVEs
without CVSS left out. By default `trained_through` = `decision_time` = 00:00
UTC on the snapshot date (2026-10-01): train 208,290 rows, 788 events.
`model_version` is `b_survival-cox-<trained_through>-0.1`.

**Horizon.** 30 days (`HORIZON_DAYS`), the same as D's fusion.

**Score.** For a CVE that is `age` days old at the decision time and still
unlisted, the score is the model's "listed in KEV within the next 30 days":
1 - S(age + 30 | x) / S(age | x). The plain 1 - S(30 | x) would treat a
three-year-old CVE as if it were published today. `score_kind` is
`ranking_score`, because the calibration of this estimate has not been checked
on held-out data.

**Statuses, in this order.**

| Status | Rule | Rows |
|---|---|---:|
| already_exploited | KEV day before the decision day | 1,534 |
| not_eligible | published before KEV_START_DATE (outside post_kev) | 89,401 |
| abstained | no CVSS 3.x score | 9,745 |
| abstained | age + 30 days is past the longest train follow-up (not extrapolated) | 1,453 |
| available | scored | 206,049 |

**Score distribution (available rows).** Median 0.00003, 90th percentile
0.00026, 99th percentile 0.00079, maximum 0.00233, mean 0.00010. The values are
small because a KEV listing within 30 days is rare: 788 events in 208,290
train CVEs over up to about five years.

**Two files: raw estimate and percentile.** The raw estimates are about
1e-4, while D's fusion takes a plain mean of 0-1 inputs (normalised CVSS,
EPSS, A, B, C). Raw B scores would pull every mean down and hardly change the
order, so B would not count fairly. B therefore follows Component C's pattern
and writes two files with the same CVEs, statuses and reasons:

- `b_exploit_timing_probability.csv`: the raw 30-day estimate,
  `model_version` `b_survival-cox-2026-10-01-0.1`. Its `score_kind` stays
  `ranking_score`, because its calibration is not validated.
- `b_exploit_timing_scores.csv` (the file D reads): the percentile rank of the
  raw estimate among the 206,049 available CVEs only, rank / N with tied CVEs
  sharing the average rank, so it is in (0, 1]. `model_version`
  `b_survival-cox-percentile-2026-10-01-0.1`. Its metadata names the raw file
  and model it came from.

Reason: same scale as C, so D's mean is fair. One difference from C: C uses
(rank - 1) / (N - 1), in [0, 1]; B uses rank / N, in (0, 1], so no available
CVE gets exactly 0.

**Limitation: raw estimates of exactly 0.** 35,525 of the 206,049 available
CVEs (17.2%) have a raw estimate of exactly 0, all tied at percentile 0.086.
The Cox baseline survival S0 is a step function that only drops on days when
a train CVE was listed. For older CVEs there are 30-day stretches of age with
no train listing, so S0 is flat there and the estimate is 0. The true chance is
small but not 0. A smoothed baseline hazard would fix this; it is not done yet.

**How to check.** `uv run python -m vesper.components.b_survival.score_export`
prints the model, the rows per status and the raw score distribution. The
percentile distribution is in `b_exploit_timing_scores.csv.metadata.json`
(min 0.086, median 0.500, max 1.0).

## How to check

Run from the repository root. Each command prints the report that the numbers
above were read from.

```
uv run python -m vesper.components.b_survival.clean_nvd
uv run python -m vesper.components.b_survival.clean_exploitdb
uv run python -m vesper.components.b_survival.eda
uv run python -m vesper.components.b_survival.survival_table
uv run python -m vesper.components.b_survival.split_data
uv run python -m vesper.components.b_survival.kaplan_meier
uv run python -m vesper.components.b_survival.evaluate
```

- Decisions 1 and 3: "CVSS missing by publication year".
- Decision 2: "CVSS score used".
- Decision 4: "Flagged, modified after the snapshot date" and "Flagged,
  published after the snapshot date".
- Decision 5: "CVE IDs accepted after tidying" and "Malformed CVE codes, not
  used".
- Decisions 6, 7, 8 and 9: the "Survival table" block of `survival_table`
  (rows, events, censored, already_exploited, kev_launch_group, events with
  duration 0).
- Decision 10: "Share with exploit_at_publication" in `survival_table`, and
  section 6 of `eda`.
- Decision 11: "Checks" in `survival_table`.
- Decision 12: the table per cut-off and the `check` lines printed by `split_data`.
- Decision 13: the incidence table and the "Log-rank tests" lines printed by `kaplan_meier`.
- Decision 14: the "Overview" and "WARNING" lines of `split_data`, and the
  post_kev block and "exploit_at_publication, post_kev cohort" lines of
  `kaplan_meier`.
- Decision 15: the table and the "left out without CVSS" and "censoring G(365)"
  lines printed by `evaluate`; hazard_ratios.csv and ph_check.csv.

## Possible move to vesper.eval

CONTRIBUTING.md asks that results come from the shared code in `vesper.eval`,
so that every component is measured the same way. `src/vesper/eval/` is still
empty, so Component B's metrics live in `b_survival/evaluate.py`. Nothing has
been moved yet. These functions have no Component B logic and could move to
`vesper.eval` once the team agrees:

- `c_index_fast`: Harrell's c-index, the same definition as lifelines, fast
  enough for the bootstrap.
- `brier_ipcw`, with `censoring_survival` and `km_value`: the Brier score at
  day t with inverse probability of censoring weights (Graf et al. 1999).
- `precision_at_k`: precision of the top k, with ties at the k-th place shared
  out evenly.
- `bootstrap_metrics`: 95% percentile intervals with the same resamples for
  every model, so models can be compared.
- `add_brier_skill`: Brier skill against the Kaplan-Meier reference of the
  same split.

`listed_within` and the per-split code (`evaluate_split`, `run_split`, `main`)
are specific to Component B and would stay in `b_survival`.
