# Synthetic A/B inputs for Component D

This folder contains only the synthetic Component A and B score fixtures.
They use the shared `Score` contract and support pipeline development; they
are not model predictions or research results. Component C is supplied by its
real handoff at `data/processed/component_c/c_graph_scores.csv` and is no longer
generated as a dummy input here.

Regenerate A/B and then rebuild the fused dataset and ranking with:

```powershell
uv run python -m vesper.components.d_fusion.generate_dummy_inputs
uv run python -m vesper.components.d_fusion.fusion
uv run python -m vesper.components.d_fusion.ensemble rank --model equal_weight
```

The A/B fixture generator uses local processed NVD, KEV, CVSS, and EPSS data.
It selects 120 CVEs stratified across CVSS and EPSS bands, with a stable hash
order. The same source snapshots produce repeatable IDs and scores.

## Component A: text risk fixture

The score is generated from NVD descriptions with a transparent phrase-based
heuristic. It adds weight for descriptions involving code execution, command
or code injection, memory corruption, authentication bypass, remote access,
missing authentication, and sensitive data exposure. It subtracts weight for
denial-of-service language. The score is clipped to 0.05–0.99. CVSS, EPSS,
and KEV labels are not used to calculate this score.

## Component B: exploit timing fixture

The generator makes hypothetical public PoC scenarios using description cues
for network access and code execution. A stable CVE-derived hash makes each
scenario repeatable. Simulated PoC lead time is shorter for more accessible
flaws, and the score is `exp(-lag_days / 30)`. Scenarios without a simulated
indicator have status `abstained` and a blank score. No real Exploit-DB or
GitHub Advisory evidence is asserted.

## Component C: real handoff

The D fusion command reads the Component C handoff from
`data/processed/component_c/c_graph_scores.csv` and verifies its SHA-256 when
the accompanying metadata JSON is present. The score is Component C's
PageRank percentile structural ranking; it is not an exploitation
probability. Rows marked unavailable stay blank and are omitted from the
available-input mean rather than treated as zero.

## Fusion meaning

The current pipeline uses the equal-weight arithmetic mean of available
normalized inputs:

```text
normalized CVSS = CVSS base score / 10
fusion score = mean(EPSS, normalized CVSS, A, B, C) over available inputs
```

The fused output records the per-component scores, statuses, model versions,
and source dates. Because A and B are still synthetic, the result is marked
`mixed_real_c_synthetic_ab`; it is a pipeline demonstration and not a
validated research ranking.
