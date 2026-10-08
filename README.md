# VESPER

**Vulnerability Evidence Synthesis for Prioritized Exploitation Risk**

SLIIT IT4010 research project **J26-DS-344**: machine-learning-based prioritization of software vulnerabilities for patching.

## Development setup

This project uses Python 3.11 and `uv` for Python environment and dependency management.

```bash
uv sync --group dev
uv run pytest
```

The first command creates or updates the local development environment. The second command runs the test suite.
