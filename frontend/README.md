# VESPER frontend

React, TypeScript and Vite, with Tailwind CSS and shadcn/ui. Bun is the package manager.

## Setup

```bash
bun install
bun dev
```

## Commands

| Command | What it does |
|---|---|
| `bun dev` | Starts the development server |
| `bun run build` | Checks the types and builds the production files |
| `bun run lint` | Runs Oxlint |

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

Use the shadcn/ui tool. It reads `components.json` and writes the component into `src/components/ui/`:

```bash
bunx shadcn@latest add table
```

Do not copy component files in by hand, and do not add another UI library. This keeps every screen on the same style.

## Layout

| Path | Contents |
|---|---|
| `src/components/ui/` | shadcn/ui components, added with the tool |
| `src/components/` | Components written for VESPER |
| `src/lib/` | Shared helpers |

Import from `src` with the `@/` alias, for example `@/components/ui/button`.
