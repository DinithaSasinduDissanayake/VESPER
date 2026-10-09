# Architecture

This page explains how VESPER is divided, who owns which part, and how the parts fit together. Read it before starting work on a component.

## What VESPER predicts

For a published vulnerability (a CVE), VESPER estimates how likely it is to be exploited in the real world, so that a team with limited time can patch the most dangerous ones first.

The outcome we predict is a CVE being added to the CISA Known Exploited Vulnerabilities (KEV) catalogue.

## Components

The project has four components. Each has one owner and one folder.

| Component | Owner | Takes in | Gives out | Folder |
|---|---|---|---|---|
| A: Text risk | D.S. Dissanayake (IT23373952) | CVE description text | A risk score per CVE, with the words that drove it | `src/vesper/components/a_text/` |
| B: Exploit timing | S.S.H. Thennakoon (IT23232990) | Publication, public-exploit and KEV dates | An urgency score per CVE, from survival analysis | `src/vesper/components/b_survival/` |
| C: Knowledge graph | H.T.D. Fernando (IT23177864) | Vendor, product and weakness (CWE) links | Graph scores per CVE | `src/vesper/components/c_graph/` |
| D: Fusion and scheduling | B.L. Beminiwatte (IT23263680) | The scores from A, B and C, with CVSS and EPSS | One combined ranking, and a patch plan under a budget | `src/vesper/components/d_fusion/` |

## How the components connect

A, B and C do not depend on each other. Each one reads the shared data and writes scores in the same shared format. D reads those scores and combines them.

```text
            shared data
          /      |      \
         A       B       C
          \      |      /
        scores in one format
                 |
                 D
                 |
          API  ->  frontend
```

Because of this, A, B and C can be built and tested at the same time, and D can start with sample scores before the real ones exist.

## Shared parts

These folders belong to the whole team. A change here affects everyone, so it goes in its own pull request.

| Folder | Purpose |
|---|---|
| `src/vesper/config.py` | Project paths and settings |
| `src/vesper/contracts/` | The agreed shapes of the data passed between components |
| `src/vesper/data/` | Downloading and preparing the public data |
| `src/vesper/eval/` | Evaluation rules used by every component |
| `src/vesper/api/` | The backend API that the frontend calls |
| `frontend/` | The web application |
| `tests/` | Tests, in folders that mirror `src/vesper/` |

## Data sources

All components use the same public sources.

| Source | Used for |
|---|---|
| NVD | CVE descriptions, dates, CVSS scores, weaknesses and affected products |
| CISA KEV | Which CVEs were exploited, and when they were listed |
| EPSS | A public exploitation score, used as a baseline to compare against |
| Exploit-DB | Dates of public exploit code |

Data files are not stored in this repository. The scripts that download them are.

## Technology

| Part | Choice |
|---|---|
| Backend language | Python 3.11 |
| Python environment and dependencies | `uv` with `pyproject.toml` and `uv.lock` |
| Tests | `pytest` |
| Frontend | React, TypeScript and Vite |
| Frontend packages | Bun |
| Frontend styling and UI parts | Tailwind CSS and shadcn/ui |

Every component uses these choices, so that the parts fit together and look the same.
