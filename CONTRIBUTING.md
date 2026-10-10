# Contributing

These are the working rules for the VESPER team. They keep four people's work compatible, so that merging stays easy. Read [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) first.

## Before you start

```bash
uv sync --group dev
uv run pytest
```

All tests must pass on a fresh clone before you change anything. If they do not, tell the team before going further.

Before you commit, format and check the Python code:

```bash
uv run ruff format .
uv run ruff check .
```

## Who owns what

| Part | Owner | Folders |
|---|---|---|
| Component A | D.S. Dissanayake (IT23373952) | `src/vesper/components/a_text/`, `tests/components/a_text/` |
| Component B | S.S.H. Thennakoon (IT23232990) | `src/vesper/components/b_survival/`, `tests/components/b_survival/` |
| Component C | H.T.D. Fernando (IT23177864) | `src/vesper/components/c_graph/`, `tests/components/c_graph/` |
| Component D | B.L. Beminiwatte (IT23263680) | `src/vesper/components/d_fusion/`, `tests/components/d_fusion/` |
| Shared parts | The whole team | Everything else |

- Work inside your own folders. A change to anything else is a change to a shared part.
- A component does not import from another component. Components exchange data only through the shared records.
- Do not create a second project inside the repository. There is one `pyproject.toml`, one `uv.lock`, one `.env` and one `data/` folder, all at the top level.
- Do not add new top-level folders. Code that you run from the command line is a module inside your component, not a loose script.

## Shared parts

`src/vesper/contracts/`, `src/vesper/data/`, `src/vesper/eval/`, `src/vesper/api/`, `src/vesper/config.py`, `frontend/`, `pyproject.toml` and the documents at the top level belong to the whole team.

- Change a shared part on its own `shared/...` branch, in a small pull request, and tell the team. Do not mix it with component work.
- Use the shared records in `contracts/` to pass data between components. Do not define your own version of a vulnerability or a score.
- Take paths and keys from `vesper.config`. Do not build a path yourself, and do not hard-code one.

## Branches

- `master` is the stable branch. Nobody commits to it directly.
- Create a new branch from `master` for each piece of work, and keep it short-lived: one feature or fix, merged within a few days.
- Name it `<area>/<what-it-does>`. The area is `a-text`, `b-survival`, `c-graph`, `d-fusion` or `shared`. For example: `c-graph/build-vendor-graph`, `shared/add-evidence-record`.
- Delete the branch after it is merged, and start the next piece of work from the updated `master`.
- If a branch lives longer than a few days, bring `master` into it (`git merge origin/master`) so that differences stay small.
- Never force-push a branch that someone else may have pulled.

## Commits

- Keep each commit small and about one thing. A reviewer should be able to read it in a few minutes.
- Write the message as `type: what changed`, in the present tense. Add the area in brackets when it helps.

| Type | Use for |
|---|---|
| `feat` | New behaviour |
| `fix` | A bug fix |
| `docs` | Documentation only |
| `test` | Tests only |
| `refactor` | Restructuring without changing behaviour |
| `chore` | Tooling and dependencies |

Examples: `feat(contracts): add score record`, `fix(c_graph): handle a CVE with no vendor`.

- Commit under your own name and university-registered GitHub account.

## Pull requests

- Open a pull request from your branch into `master`.
- Say what changed, why, and how you tested it. Include the command you ran and its output.
- All tests must pass.
- One other team member reads and approves it before it is merged.
- Merge with a merge commit. Do not squash, so that every member's commits stay in the history.

## Tests

- New code comes with tests in the same pull request.
- Do not delete, skip or weaken a test to make the test run pass. If a test is wrong, fix it and explain why in the pull request.

## Dependencies

- Add a package with `uv add <package>`, in the same commit as the first code that uses it. Commit `pyproject.toml` and `uv.lock` together.
- Do not use `pip install` or a `requirements.txt` file.
- Keep a pull request that adds a package small and merge it soon, because everyone shares `pyproject.toml` and `uv.lock`.
- If `uv.lock` or `bun.lock` has a merge conflict, do not edit it by hand. Take the version from `master` and run `uv lock` or `bun install` again.

## Data and secrets

- Data files are not stored in this repository. They go in `data/`, which git ignores. Each source has its own folder under `data/raw/`; get it from `load_settings().raw_source("nvd")`.
- Generated files are not stored either: no trained models, result tables, figures or PDFs. They go in `outputs/`, which git ignores, and a command in the repository must be able to produce them again.
- Keys go in `.env`, which git ignores. `.env.example` lists the names without the values.
- This repository is public. Never commit a key, a password or personal data.

## Preventing data leakage

VESPER predicts future exploitation, so a model must only see what was known at the decision time.

- Features come from the vulnerability record. Outcomes, such as the date a CVE was added to KEV, are kept in separate records and are never used as features.
- Train only on data from before the test period.
- Do not call a score a probability until it has been validated.
- Report only results that the shared code in `vesper.eval` produced, so that every component is measured the same way.
