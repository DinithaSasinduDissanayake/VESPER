# Synthetic A/B/C score inputs for Component D

These three CSVs contain 120 synthetic score rows apiece in the shared `Score`
contract shape. They are fixtures for developing D's joins and missing-score
handling; none of the component scores is a model prediction or research result.

Each file has one row per CVE and no duplicate IDs. The same 120 CVE IDs appear
in A, B, C, and the local CVSS/EPSS baseline so D can join them by `cve_id`.
They are real CVE IDs drawn from the repository's NVD, CVSS, and EPSS snapshots;
the generator excludes CVEs currently listed in the local KEV table. Selection
is stratified across CVSS severity bands (low, moderate, high, critical) and
EPSS probability bands (low, guarded, elevated, high), with a stable hash order
to make the selected sample repeatable. Their shared decision time and
snapshot date match the NVD snapshot (2026-10-11); their horizon is 30 days.

Regenerate the three component fixtures, then the fused output, with:

```powershell
uv run python -m vesper.components.d_fusion.generate_dummy_inputs
uv run python -m vesper.components.d_fusion.fusion
```

The generator uses the local processed NVD, KEV, CVSS, and EPSS datasets. The
same inputs and snapshot produce the same selected CVEs and scores.

## Component A: text risk

Scores are generated from NVD description text only. The lightweight heuristic
adds points for phrases describing code execution, command/code injection,
memory corruption, authentication bypass, remote access, missing authentication,
and sensitive data exposure; it subtracts points for denial-of-service language.
The result is clipped to 0.05-0.99. CVSS, EPSS, and KEV labels do not enter the
text score calculation. This makes the larger fixture repeatable and text-led,
while remaining a stand-in for the eventual TF-IDF/logistic-regression or
transformer model.

## Component B: exploit-code timing

The generator creates explicitly hypothetical public-PoC indicator scenarios.
It uses remote/network and code-execution cues from NVD descriptions to set a
simulated chance of an indicator. A stable CVE-derived hash makes each
scenario repeatable; simulated disclosure-to-PoC lag is shorter for more
accessible flaws, and the score is `exp(-lag_days / 30)`. Scenarios without an
indicator produce an `abstained` row with an empty score. This exercises B's
timing and missing-evidence behavior without claiming any actual PoC dates.

No Exploit-DB or GitHub Advisory evidence was downloaded or asserted. All B
scores and abstentions are simulation data and must be replaced by Component
B's actual output.

## Component C: relationship graph

Scores use a graph-degree proxy computed from the full local NVD table. The
generator counts how many CVEs connect to each vendor, vendor/product pair, and
CWE node, averages the log degrees for a CVE's connected nodes, then maps that
value to a percentile across the NVD CVEs. This follows the component's
relationship-analysis idea and yields a repeatable 0-1 ranking score. It is a
degree-based proxy, not PageRank; it is not a trained or evaluated component C
model.

## Fused sample and formula

Run `uv run python -m vesper.components.d_fusion.fusion` to create
`fused_dummy_dataset.csv` from these three score files and
`data/processed/d_fusion_baselines.parquet`. The current output has 120 rows,
one per CVE ID, and retains the individual scores, score statuses, and baseline
fields.

The sample's transparent starting rule is an equal-weight arithmetic mean:

```text
normalized CVSS = CVSS base score / 10
fusion score = mean(EPSS, normalized CVSS, A, B, C) over available inputs
```

EPSS is already in [0, 1], as are the illustrative A/B/C ranking scores.
An abstained or missing score is omitted from that CVE's mean, not treated as
zero. `signals_used` and `signal_coverage` show how many of the five inputs
contributed. For example, `CVE-2024-21473` has no B score, so its index is the
mean of normalized CVSS (0.98), EPSS (0.00663), A (0.78), and C (0.86), which
is 0.656658 after rounding.

This result is a **ranking index**, not an exploitation probability. Equal
weights and the linear CVSS normalization are explicit demo choices, not
validated research findings. They should be evaluated and justified before
using D's fusion method in the research results.
