<!-- Explanations for notebooks/00_survival_practice.ipynb (the notebook holds the code only). -->

# 00 — Survival analysis practice (toy dataset)

**Component B (Exploit Timing) — VESPER, J26-DS-344**

Purpose: learn the `lifelines` library on a small built-in dataset *before* touching real CVE data.

Steps in this notebook:
1. Load the Rossi dataset and understand its columns
2. Kaplan–Meier curves (whole dataset, then two groups)
3. Log-rank test between the two groups
4. Cox proportional-hazards model and hazard ratios

## Step 1 — Load the data

The **Rossi recidivism dataset** follows 432 people for one year (52 weeks) after release from prison and records whether, and when, they were arrested again.

Every survival dataset needs two special columns:

| Role | Column here | Meaning |
|---|---|---|
| **duration** | `week` | How long the person was observed (weeks until re-arrest, or until the study ended) |
| **event** | `arrest` | `1` = the event happened (re-arrested), `0` = **censored** (not arrested by the time the study ended) |

The other columns are **covariates** (information about each person that might affect the risk):

- `fin` — received financial aid after release (1 = yes, 0 = no)
- `age` — age in years at release
- `race` — 1 = Black, 0 = other
- `wexp` — had full-time work experience before prison (1 = yes)
- `mar` — married at release (1 = yes)
- `paro` — released on parole (1 = yes)
- `prio` — number of prior convictions

**In my real project:** one row per CVE; `duration` = days from disclosure to KEV listing (or to the snapshot date); `event` = 1 if listed in KEV, 0 if not yet; covariates = CVSS metrics, CWE group, public-exploit availability.

> **Code:** see code cell 1 in `00_survival_practice.ipynb`.

### How many rows are events and how many are censored?

Counting the values in the event column tells us how much of the data is censored. We also look at the largest duration, because that shows when the study stopped observing people.

> **Code:** see code cell 2 in `00_survival_practice.ipynb`.

## Step 2 — Kaplan–Meier curve

The **Kaplan–Meier (KM) estimator** answers: *what share of subjects have still not had the event by time t?* That share is called the **survival probability** S(t).

How it works, in words: at every week where an arrest happens, it calculates

> (people still being followed who were **not** arrested this week) ÷ (people still being followed)

and multiplies these fractions together week after week. Censored people count in the "still being followed" group up to the moment they leave, and then drop out **without** counting as an arrest. That is how KM uses censored rows correctly instead of throwing them away.

`KaplanMeierFitter.fit()` needs just the two special columns: `durations` and `event_observed`.

**In my real project:** the curve will show the share of CVEs still *not* listed in KEV, by days since disclosure.

> **Code:** see code cell 3 in `00_survival_practice.ipynb`.

### Kaplan–Meier curves for two groups

Now we split the data by one yes/no column and fit one KM curve per group, on the same axes. We use `fin` (received financial aid: 1 = yes, 0 = no). If the two curves separate, the groups are being re-arrested at different rates.

**In my real project:** the two groups will be CVEs **with** early public exploit code (ExploitDB) and CVEs **without** it.

> **Code:** see code cell 4 in `00_survival_practice.ipynb`.

## Step 3 — Log-rank test

The two KM curves look different, but their confidence bands overlap. Could the gap be just chance? The **log-rank test** answers that.

- **Null hypothesis:** both groups have the *same* survival curve (financial aid makes no difference).
- At every week where an arrest happens, the test compares the number of arrests **observed** in each group with the number **expected** if the groups were identical, and adds up the differences over the whole follow-up.
- **p-value:** the probability of seeing a gap at least this large *if the null hypothesis were true*. A small p-value (commonly below 0.05) means the gap is unlikely to be chance alone.

Like Kaplan–Meier, the test uses censored rows correctly: they count as "at risk" until they leave.

**In my real project:** this tests whether CVEs with early public exploit code are listed in KEV at a different rate from CVEs without it.

> **Code:** see code cell 5 in `00_survival_practice.ipynb`.

## Step 4 — Cox proportional-hazards model

Kaplan–Meier and the log-rank test compare groups using **one** yes/no column at a time. The **Cox model** uses **all covariates together** and tells us the effect of each one *while holding the others fixed*.

Key ideas:

- **Hazard** = the rate at which the event happens at a given moment, among those who have not had it yet.
- The model estimates one **coefficient** (`coef`) per covariate. Its exponential, `exp(coef)`, is the **hazard ratio (HR)**:
  - HR = 1 → no effect
  - HR > 1 → higher hazard (event tends to happen **sooner**)
  - HR < 1 → lower hazard (event tends to happen **later**)
- For a yes/no covariate, the HR compares "yes" with "no". For a numeric covariate, it is the change per **one unit** increase.
- **Proportional-hazards assumption:** each HR is assumed to stay the same over the whole follow-up time. (I will test this with Schoenfeld residuals on the real data.)

`CoxPHFitter.fit()` takes the whole table and is told which column is the duration and which is the event; every other column is used as a covariate.

**In my real project:** the covariates will be CVSS metrics, CWE group and public-exploit availability; the hazard ratios are the named effects that explain each CVE's urgency score.

> **Code:** see code cell 6 in `00_survival_practice.ipynb`.

> **Code:** see code cell 7 in `00_survival_practice.ipynb`.

## Why I practised on a toy dataset first

Short answer for the panel:

> Before applying survival analysis to my real CVE data, I validated my understanding of the method and of the `lifelines` library on a small, well-documented benchmark dataset where the expected behaviour is known. This separates tool errors from data errors.

Supporting points:

1. **Separate tool errors from data errors.** Rossi is small (432 rows), clean and widely used in survival-analysis teaching. If a result looks wrong there, the mistake is in my code or my understanding. On raw CVE data I could not tell whether a strange result came from my code or from the data (wrong dates, bad links, extreme censoring).
2. **Same pipeline, different table.** The steps and library calls are identical to my real component: `KaplanMeierFitter`, `logrank_test`, `CoxPHFitter`. Only the input table changes (duration = days from disclosure to KEV listing, event = listed in KEV or not).
3. **Learn to interpret the outputs.** I practised reading a survival curve, a log-rank p-value, hazard ratios with confidence intervals and the concordance index, so that I can explain my real results correctly and not overclaim.
4. **Incremental development.** It follows my iterative plan: verify each building block on a simple case before adding the complexity of three linked data sources.

What it is **not**: the toy dataset is not part of my results. No number from it is reported as a finding of Component B.
