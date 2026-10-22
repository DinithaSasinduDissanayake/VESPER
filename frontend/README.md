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
