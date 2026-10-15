# Component B — Data decisions

This file records the decisions made while cleaning the data, and the reason
for each one. Every number was printed by a cleaning module on the raw files
described in `data_snapshot.md` (snapshot date 2026-10-01). "How to check" at
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
files were downloaded on 2026-10-06 (see `data_snapshot.md`). Records that NVD
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
## How to check

Run from the repository root. Each command prints the report that the numbers
above were read from.

```
uv run python -m vesper.components.b_survival.clean_nvd
uv run python -m vesper.components.b_survival.clean_exploitdb
uv run python -m vesper.components.b_survival.eda
uv run python -m vesper.components.b_survival.survival_table
uv run python -m vesper.components.b_survival.split_data
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
