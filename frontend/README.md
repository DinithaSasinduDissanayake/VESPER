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

Each "section" is one card on the CVE detail view. All four use the shared card in
`queue/ScoreSection.tsx`. Make your section richer inside your own file; change the
shared card only in a separate small PR.

## Data flow

```
backend (src/vesper/contracts/score.py, vulnerability.py)
  -> src/api/queue.ts   getQueue()      the only place that loads data
  -> src/api/useQueue.ts useQueue()     React hook used by pages
  -> pages and sections
```

- `src/queue/types.ts` mirrors the Python contracts. Keep both in sync.
- Today `getQueue()` returns sample data from `queue/sampleQueue.ts`.
- To use a real endpoint, change only `getQueue()`:

  ```ts
  const response = await fetch('/api/queue')
  return (await response.json()) as QueueItem[]
  ```

  The response must match the types in `queue/types.ts`.

### Sprint plan optimiser

The Sprint plan page uses a placeholder (fixed hours per CVE). The real optimiser is
the knapsack API on the `ComponentD` branch:

`POST /api/d-fusion/knapsack`
- request: `{ patchers, hours_per_patcher, overrides }`
- response: `{ used_hours, capacity_hours, scheduled, deferred, ... }`

Capacity is `patchers × hours_per_patcher`. Replace the placeholder with this call.

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

- Never show "Component A/B/C/D" in the UI. Use plain names: Text signal, Exploit timing, Exposure, Fusion.
- No other UI libraries (only shadcn/ui, Tailwind and lucide icons).
- Small pull requests, one topic each.
- Sample data must always be labelled as sample data on screen.
- Import from `src` with the `@/` alias, for example `@/components/ui/button`.
