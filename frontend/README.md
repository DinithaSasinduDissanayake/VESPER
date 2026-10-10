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
