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

## How to check

Run from the repository root. Each command prints the report that the numbers
above were read from.

```
uv run python -m vesper.components.b_survival.clean_nvd
uv run python -m vesper.components.b_survival.clean_exploitdb
```

- Decisions 1 and 3: "CVSS missing by publication year".
- Decision 2: "CVSS score used".
- Decision 4: "Flagged, modified after the snapshot date" and "Flagged,
  published after the snapshot date".
- Decision 5: "CVE IDs accepted after tidying" and "Malformed CVE codes, not
  used".
