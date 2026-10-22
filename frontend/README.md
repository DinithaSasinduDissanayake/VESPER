# VESPER frontend

React, TypeScript and Vite, with Tailwind CSS and shadcn/ui. Bun is the package manager.

## Run it

```bash
bun install
bun dev          # development server
bun run build    # type check + production build
bun run lint     # Oxlint
```

Update Bun to a recent version (`bun upgrade`) before `bun install`. An old Bun
(for example 1.3.12 on Linux) rewrites `bun.lock` to an older format. Never commit
a `bun.lock` change you did not mean to make.

## Who builds what

| Folder | Owner | What to build |
|---|---|---|
| `src/analyse/` | D.S. Dissanayake | Add / analyse page (`AnalysePage.tsx`) and the Text signal section (`TextSection.tsx`) |
| `src/timing/` | S.S.H. Thennakoon | Exploit timing section (`TimingSection.tsx`): later the survival curve and proof-of-concept timeline |
| `src/exposure/` | H.T.D. Fernando | Exposure page (`ExposurePage.tsx`) and the Exposure section (`ExposureSection.tsx`) |
| `src/plan/` | B.L. Beminiwatte | Sprint plan page (`SprintPlanPage.tsx`) and the Fusion section (`FusionSection.tsx`) |
| `src/queue/`, `src/api/`, `src/scores/`, `App.tsx`, `pages.tsx` | Whole team | Shared: priority queue, CVE detail layout, data access, help page |

Each "section" is one card on the CVE detail view. Text, timing and fusion use
`queue/ScoreSection.tsx`; Structural Relationships has a richer full-width card
inside `exposure/`. Change the shared score card only in a separate small PR.

## Structural Relationships UI

The `exposure/` directory contains the structural summary, bounded SVG relationship
graph, CVSS comparison and evidence/provenance panels. `types.ts` defines the
detail and loading/error states. Presentation receives data through props;
`sampleStructuralDetails.ts` owns all illustrative fixtures and adapts sample
queue items. No API, research CSV loading or backend calculation is connected.

The standalone Structural Relationships page includes a demo scenario selector
for higher/equal/lower comparison, unavailable score with partial evidence,
not-eligible, loading and error states. All displayed measurements and
relationships are sample data, even when the selected CVE identifier is real.
Primary PageRank percentile, raw PageRank and comparison-cohort percentile remain
separate. Missing evidence is not a confirmed empty set.

The graph previews four products and four weaknesses; full evidence is available
through Show more/less controls. It uses a horizontal SVG layout on wide screens
and a vertical layout at narrower widths, without a graph library.

Focused regression checks use the existing Node, Vite and React dependencies:

```bash
node --test src/exposure/structuralDetails.test.mjs
```

For the next phase, map an agreed backend response to `StructuralDetailsState`
at the data boundary and replace the sample adapters. Preserve score/evidence
availability, population definitions and snapshot identity; do not recompute
research percentiles in the browser.

## Data flow

```
backend (src/vesper/contracts/score.py, vulnerability.py)
  -> src/api/queue.ts   getQueue()      the only place that loads data
  -> src/api/useQueue.ts useQueue()     React hook used by pages
  -> pages and sections
```

- `src/queue/types.ts` mirrors the Python contracts. Keep both in sync.
- The Priority queue page loads the current Component D ranking from
  `GET /api/d-fusion/ranking` and displays its top 25 rows. Its CSV button downloads
  the full ranking from `GET /api/d-fusion/ranking.csv`. The separate `getQueue()`
  helper still returns sample data for pages that use the older queue contract.
- To use a real endpoint, change only `getQueue()`:

  ```ts
  const response = await fetch('/api/queue')
  return (await response.json()) as QueueItem[]
  ```

  The response must match the types in `queue/types.ts`.

### Sprint plan optimiser

The Sprint plan page is implemented in `src/plan/SprintPlanPage.tsx`. It loads the
backend ranking and submits team capacity, plan period, and start date through
`src/api/queue.ts`. It shows a paginated risk ranking with a full CSV download,
then displays the scheduled and deferred results returned by FastAPI. The
planner endpoints are:

- `GET /api/d-fusion/ranking` loads the configured ranking.
- `GET /api/d-fusion/ranking.csv` downloads that exact ranking.
- Selecting a CVE in the Priority queue loads its local NVD record from
  `GET /api/d-fusion/cves/{cve_id}`. The endpoint reads
  `data/processed/vulnerabilities.parquet`; if that local NVD dataset is absent,
  the UI reports that details are unavailable instead of substituting sample data.
- `POST /api/d-fusion/knapsack` accepts `{ patchers, hours_per_patcher,
  planning_period, start_date, overrides }` and returns scheduled/deferred
  rows, dates, and daily capacity summaries.

Daily plans cover one workday; weekly plans cover five Monday-Friday workdays;
monthly plans cover 22 Monday-Friday workdays. The backend reruns the daily
knapsack for each workday using remaining candidates. The UI downloads the
complete returned plan as a CSV. This multi-day sequence is greedy across days,
and does not model holidays, dependencies, or patcher skill differences.

## Component D patch planner

The VESPER screen includes the current ranking and daily/weekly/monthly patch
planner under `src/plan/SprintPlanPage.tsx`. Start
the API and frontend in separate terminals from the repository root:

```powershell
uv sync --group dev
uv run uvicorn vesper.api.main:app --reload
```

```powershell
cd frontend
bun install
bun run dev
```

The frontend proxies `/api` requests to the local FastAPI service on port 8000.
FastAPI loads `outputs/d_fusion/current_provisional/ranked_current_five_signal.csv`
by default and serves it to React; users do not select or upload the ranking
file. Generate the current fused dataset and ranking first with
`uv run python -m vesper.components.d_fusion.provisional_pipeline`. The backend
can use another CSV when `VESPER_RANKING_CSV` points to it. The UI shows the
full paginated ranking and can download it as CSV. Patch effort defaults to a
labeled CVSS severity-tier estimate; rows without CVSS remain unscheduled until
an effort estimate is supplied. The backend maximizes
`risk_score × business_criticality` under each day's person-hour limit.
Business criticality defaults to 1 unless an override is provided.

Ranking input must contain unique `cve_id` values and a score column named
`risk_score` or `fusion_score` with values from 0 to 1. Optional signal scores,
statuses, provenance dates, `patch_hours`, and `business_criticality` fields
are displayed or loaded when present. The current provisional ranking uses
within-cohort percentile ranks and is explicitly not a trained or validated
model. The backend does not persist overrides between browser sessions.

## Component D patch planner

The VESPER screen includes a daily patch planner under `src/knapsack/`. Start
the API and frontend in separate terminals from the repository root:

```powershell
uv sync --group dev
uv run uvicorn vesper.api.main:app --reload
```

```powershell
cd frontend
bun install
bun run dev
```

The frontend proxies `/api` requests to the local FastAPI service on port 8000.
FastAPI loads `outputs/d_fusion/ranked_vulnerabilities.csv` on the backend and
serves it to React; users do not select or upload the ranking file. Generate it
first with `uv run python -m vesper.components.d_fusion.ensemble rank` if it is
missing. The backend can use a different CSV when `VESPER_RANKING_CSV` points to
it. In the UI, set patchers and daily hours, then add patch-hour estimates and
business criticality (1 low, 2 medium, 3 high) in **All candidates & inputs**.
React sends only capacity and those per-CVE overrides to
`POST /api/d-fusion/knapsack`; FastAPI reloads the backend ranking, validates
the request, and returns separate `scheduled` and `deferred` lists. CVEs
without an effort estimate remain unscheduled. The backend selects the set
that maximizes `risk_score × business_criticality` under the daily person-hour
limit. The main view shows up to the 25 selected CVEs; **Export full CSV**
downloads the complete scheduled and deferred plan.

Ranking input must contain unique `cve_id` values and a score column named
`risk_score` or `fusion_score` with values from 0 to 1. Optional
`patch_hours` and `business_criticality` columns are loaded when present. If
these fields are absent, enter the values in the UI. The backend does not
persist overrides between browser sessions.

## Adding UI components

Only through the shadcn/ui tool. It writes the component into `src/components/ui/`:

```bash
bunx shadcn@latest add input
```

Do not edit generated files or copy components in by hand.

## Rules

- Never show "Component A/B/C/D" in the UI. Use plain names: Text signal, Exploit timing, Structural Relationships, Fusion.
- No other UI libraries (only shadcn/ui, Tailwind and lucide icons).
- Small pull requests, one topic each.
- Sample data must always be labelled as sample data on screen.
- Import from `src` with the `@/` alias, for example `@/components/ui/button`.
