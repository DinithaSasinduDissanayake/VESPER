# Component B — Raw data snapshot

This file records exactly when each raw data source was downloaded and what it
contained. Every number below was counted from the files in
`data/raw/` (not estimated). The raw files themselves are not in
Git (see `.gitignore`); use "How to rebuild" to download them again.

All times are Sri Lanka time (UTC+05:30). Download times are the times the
files were written to disk. For NVD they come from the `downloaded_at` field
stored inside each monthly file.

## Snapshot date (censoring date)

**Snapshot date: 2026-10-01** — the day the KEV catalogue was downloaded.

A CVE that is not in this KEV file is treated as *censored* at the snapshot
date: we only know it was not listed in KEV up to then. The KEV file is the
source of the event, so its download date defines the snapshot. The catalogue
itself was released by CISA on 2026-09-30 (`dateReleased`), and its latest
`dateAdded` is 2026-09-30.

ExploitDB was downloaded one day later (2026-10-02). NVD was downloaded on
2026-10-02 (one month) and 2026-10-06 (all other months). Any record in those
files dated after the snapshot date must be filtered out when the survival
table is built.

## 1. CISA KEV (Known Exploited Vulnerabilities)

| Item | Value |
|---|---|
| Downloaded | 2026-10-01 19:53:44 (+05:30) |
| Source URL | https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json |
| Raw file | `data/raw/kev/kev_2026-10-01.json` (1,760,677 bytes, saved unchanged) |
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
| Raw file | `data/raw/exploitdb/exploitdb_2026-10-02.csv` (10,182,721 bytes, saved unchanged) |
| Records | 47,170 rows (one row per exploit entry, not per CVE) |
| Date range (`date_published`) | 1988-08-01 to 2026-10-01 (no missing dates) |

## 3. NVD (National Vulnerability Database)

| Item | Value |
|---|---|
| Downloaded | `nvd_2015-01.json.gz`: 2026-10-02 15:26:07 (+05:30). The other 141 files: 2026-10-06, from 15:10:40 to 16:55:10 (+05:30) |
| Source URL | https://services.nvd.nist.gov/rest/json/cves/2.0 (API 2.0, filtered by publication date) |
| Raw files | `data/raw/nvd/nvd_YYYY-MM.json.gz`, one per publication month: 142 files, 2015-01 to 2026-10, no month missing (166,241,258 bytes in total) |
| Records | 334,192 CVEs (334,192 unique CVE IDs; no CVE appears in two files) |
| Check against NVD | In all 142 files the number of records equals NVD's `totalResults` for the month |
| Date range (`published`) | 2015-01-01T02:59:01.533 to 2026-10-06T11:17:30.020 (UTC, no missing dates) |
| Published after the snapshot date | 1,412 CVEs (published 2026-10-02 to 2026-10-06) |

Coverage: CVEs published from `START_YEAR` (2015, set at the top of
`download_nvd.py`) to the download date. Each monthly file stores its own
download time in the field `downloaded_at` (UTC).

Two things to handle when the survival table is built:

- **CVEs published after the snapshot.** The October 2026 file was downloaded on
  2026-10-06, so it holds 1,809 CVEs: 397 published on 2026-10-01 and 1,412
  published after it. The 1,412 must be left out.
- **Records changed after the snapshot.** NVD returns each record as it was on
  the download day, not on the snapshot date. 3,358 records have a
  `lastModified` date after 2026-10-01; 1,946 of them were published on or
  before the snapshot date. For those, values such as the CVSS score may have
  been added or changed after the snapshot.

## How to rebuild

Run from the repository root (`VESPER/`), after `uv sync --group dev`:

```
uv run python -m vesper.components.b_survival.download_kev
uv run python -m vesper.components.b_survival.download_exploitdb
uv run python -m vesper.components.b_survival.download_nvd
```

- The NVD script reads the API key from the top-level `.env`
  (one line: `NVD_API_KEY=...`). Without a key it still works, but more slowly.
- The NVD script can be rerun after an interruption; months already saved are skipped.
- KEV and ExploitDB change every day, so a new download gives a **different
  snapshot** with a new date in the file name. If the data is downloaded again,
  this file must be updated with the new dates and counts.
