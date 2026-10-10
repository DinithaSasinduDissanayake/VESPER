# Component B — Raw data snapshot

This file records exactly when each raw data source was downloaded and what it
contained. Every number below was counted from the files in
`component_b/data/raw/` (not estimated). The raw files themselves are not in
Git (see `component_b/.gitignore`); use "How to rebuild" to download them again.

All times are Sri Lanka time (UTC+05:30). Download times are the times the
files were written to disk.

> **Status: INCOMPLETE.** The full NVD download has not been run yet. Only the
> one-month test slice (January 2015) is on disk. The NVD section must be
> updated after the full download.

## Snapshot date (censoring date)

**Snapshot date: 2026-10-01** — the day the KEV catalogue was downloaded.

A CVE that is not in this KEV file is treated as *censored* at the snapshot
date: we only know it was not listed in KEV up to then. The KEV file is the
source of the event, so its download date defines the snapshot. The catalogue
itself was released by CISA on 2026-09-30 (`dateReleased`), and its latest
`dateAdded` is 2026-09-30.

ExploitDB and NVD were downloaded one day later (2026-10-02). Any record in
those files dated after the snapshot date must be filtered out when the
survival table is built.

## 1. CISA KEV (Known Exploited Vulnerabilities)

| Item | Value |
|---|---|
| Downloaded | 2026-10-01 19:53:44 (+05:30) |
| Source URL | https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json |
| Raw file | `component_b/data/raw/kev_2026-10-01.json` (1,760,677 bytes, saved unchanged) |
| Records | 1,730 CVEs (1,730 unique `cveID`; the file's own `count` field = 1,730) |
| Catalogue version | 2026.09.30 (`dateReleased` 2026-09-30T16:59:23Z) |
| Date range (`dateAdded`) | 2021-11-03 to 2026-09-30 |

Note: KEV started on 2021-11-03, so no `dateAdded` can be earlier than that,
even for CVEs exploited years before.

## 2. ExploitDB (public exploit code index)

| Item | Value |
|---|---|
| Downloaded | 2026-10-02 15:22:56 (+05:30) |
| Source URL | https://gitlab.com/exploit-database/exploitdb/-/raw/main/files_exploits.csv |
| Raw file | `component_b/data/raw/exploitdb_2026-10-02.csv` (10,182,721 bytes, saved unchanged) |
| Records | 47,170 rows (one row per exploit entry, not per CVE) |
| Date range (`date_published`) | 1988-08-01 to 2026-10-01 (no missing dates) |

## 3. NVD (National Vulnerability Database) — test slice only

| Item | Value |
|---|---|
| Downloaded | 2026-10-02 15:26:07 (+05:30) |
| Source URL | https://services.nvd.nist.gov/rest/json/cves/2.0 (API 2.0, filtered by publication date) |
| Raw files | `component_b/data/raw/nvd/nvd_YYYY-MM.json.gz`, one per publication month. On disk now: 1 file, `nvd_2015-01.json.gz` (303,829 bytes) |
| Records | 737 CVEs (737 unique CVE IDs; equals NVD's `totalResults` for the month) |
| Date range (`published`) | 2015-01-01T02:59:01 to 2015-01-30T11:59:50 |

Planned coverage: CVEs published from `START_YEAR` (currently 2015, set at the
top of `download_nvd.py`) to the download date. Each monthly file stores its own
download time in the field `downloaded_at`.

## How to rebuild

Run from the repository root (`VESPER/`), with the virtual environment
installed from `component_b/requirements.txt`:

```
component_b\.venv\Scripts\python component_b\src\download_kev.py
component_b\.venv\Scripts\python component_b\src\download_exploitdb.py
component_b\.venv\Scripts\python component_b\src\download_nvd.py
```

- The NVD script reads the API key from `component_b/.env`
  (one line: `NVD_API_KEY=...`). Without a key it still works, but more slowly.
- The NVD script can be rerun after an interruption; months already saved are skipped.
- KEV and ExploitDB change every day, so a new download gives a **different
  snapshot** with a new date in the file name. If the data is downloaded again,
  this file must be updated with the new dates and counts.
