"""Generate a larger, reproducible set of synthetic A/B/C score inputs."""

import argparse
import hashlib
import math
import re
from collections import Counter
from datetime import date, datetime, time, timezone
from pathlib import Path

import pandas as pd

from vesper.config import load_settings

TARGET_ROWS = 120
BASE_QUOTA_PER_STRATUM = 8
CVSS_BANDS = ("low", "moderate", "high", "critical")
EPSS_BANDS = ("low", "guarded", "elevated", "high")
COMPONENTS = (
    ("a_text", "synthetic-a-text-heuristic-0.2"),
    ("b_survival", "synthetic-b-poc-simulation-0.2"),
    ("c_graph", "synthetic-c-degree-proxy-0.2"),
)

TEXT_PATTERNS = {
    "direct_code_execution": (
        re.compile(r"\b(remote code execution|arbitrary code execution|code execution)\b"),
        0.26,
    ),
    "command_or_code_injection": (
        re.compile(r"\b(command injection|code injection|command execution|shell command)\b"),
        0.22,
    ),
    "memory_corruption": (
        re.compile(r"\b(memory corruption|buffer overflow|use.after.free|heap corruption)\b"),
        0.16,
    ),
    "authentication_bypass": (
        re.compile(r"\b(authentication bypass|bypass authentication|unauthorized access)\b"),
        0.14,
    ),
    "remote_access": (re.compile(r"\b(remote|network)\b"), 0.08),
    "no_authentication": (
        re.compile(r"\b(unauthenticated|without authentication|pre.authentication|pre.auth)\b"),
        0.10,
    ),
    "sensitive_data": (
        re.compile(r"\b(disclosure|sensitive information|information leak)\b"),
        0.05,
    ),
    "cross_site_scripting": (re.compile(r"\b(cross.site scripting|\bxss\b)"), 0.04),
}
DOS_PATTERN = re.compile(r"\b(denial.of.service|\bdos\b|service disruption)\b")


def _as_values(value: object) -> list:
    if value is None:
        return []
    if hasattr(value, "tolist"):
        value = value.tolist()
    if isinstance(value, (list, tuple)):
        return list(value)
    return []


def _pairs(value: object) -> list[tuple[str, str]]:
    pairs = []
    for pair in _as_values(value):
        parts = _as_values(pair)
        if len(parts) >= 2 and parts[0] and parts[1]:
            pairs.append((str(parts[0]).strip().lower(), str(parts[1]).strip().lower()))
    return pairs


def _cvss_band(score: float) -> str:
    if score < 4.0:
        return "low"
    if score < 7.0:
        return "moderate"
    if score < 9.0:
        return "high"
    return "critical"


def _epss_band(score: float) -> str:
    if score < 0.01:
        return "low"
    if score < 0.1:
        return "guarded"
    if score < 0.5:
        return "elevated"
    return "high"


def _stable_order(cve_id: str) -> bytes:
    """A stable pseudo-random order avoids selecting only alphabetic IDs."""
    return hashlib.sha256(f"vesper-dummy-sample-v2:{cve_id}".encode()).digest()


def _select_sample(candidates: pd.DataFrame) -> pd.DataFrame:
    candidates = candidates.copy()
    candidates["cvss_band"] = candidates["cvss_base_score"].map(_cvss_band)
    candidates["epss_band"] = candidates["epss_score"].map(_epss_band)
    buckets = {
        (cvss_band, epss_band): group
        for (cvss_band, epss_band), group in candidates.groupby(
            ["cvss_band", "epss_band"], sort=True
        )
    }
    if not buckets:
        raise ValueError("No CVEs have both CVSS and EPSS values")

    quotas = {
        key: min(BASE_QUOTA_PER_STRATUM, len(group)) for key, group in buckets.items()
    }
    remaining = TARGET_ROWS - sum(quotas.values())
    if remaining < 0:
        raise ValueError("The configured base quota exceeds the requested sample size")
    while remaining:
        expandable = sorted(
            (key for key, group in buckets.items() if quotas[key] < len(group)),
            key=lambda key: (-len(buckets[key]) + quotas[key], key),
        )
        if not expandable:
            raise ValueError(
                f"Only {TARGET_ROWS - remaining} eligible CVEs are available; "
                f"cannot build {TARGET_ROWS} rows"
            )
        for key in expandable:
            if not remaining:
                break
            quotas[key] += 1
            remaining -= 1

    selected = []
    for key in sorted(buckets):
        group = buckets[key].copy()
        group["_stable_order"] = group["cve_id"].map(_stable_order)
        selected.append(group.sort_values("_stable_order").head(quotas[key]))
    sample = pd.concat(selected, ignore_index=True)
    return sample.drop(columns=["cvss_band", "epss_band", "_stable_order"])


def _text_score(description: str) -> float:
    text = description.lower()
    score = 0.18
    for pattern, weight in TEXT_PATTERNS.values():
        if pattern.search(text):
            score += weight
    if DOS_PATTERN.search(text):
        score -= 0.12
    return round(min(0.99, max(0.05, score)), 6)


def _hash_unit(cve_id: str, suffix: str) -> tuple[float, int]:
    digest = hashlib.sha256(f"{suffix}:{cve_id}".encode()).digest()
    unit = int.from_bytes(digest[:8], "big") / (2**64 - 1)
    return unit, digest[8]


def _poc_scenario(cve_id: str, description: str) -> tuple[float | None, str | None]:
    """Simulate PoC presence and lead time; this is explicitly not source data."""
    text = description.lower()
    network_access = bool(
        re.search(r"\b(remote|network|internet|unauthenticated|pre.auth)\b", text)
    )
    code_execution = bool(
        re.search(
            r"\b(code execution|command injection|code injection|arbitrary command|rce)\b",
            text,
        )
    )
    accessibility = (0.45 if network_access else 0.12) + (0.40 if code_execution else 0.0)
    availability_chance = min(0.92, 0.25 + 0.65 * accessibility)
    draw, offset = _hash_unit(cve_id, "synthetic-poc-v2")
    if draw >= availability_chance:
        return None, "No matched public PoC indicator in the synthetic scenario"

    # Easier to reach flaws receive shorter simulated disclosure-to-PoC lags.
    lag_days = 1 + int((1.0 - accessibility) * 24) + (offset % 7)
    urgency = math.exp(-lag_days / 30.0)
    return round(urgency, 6), None


def _graph_scores(nvd: pd.DataFrame) -> dict[str, float]:
    """Use NVD vendor/product/CWE node degree as a graph centrality proxy."""
    records = []
    vendor_degree: Counter[str] = Counter()
    product_degree: Counter[tuple[str, str]] = Counter()
    cwe_degree: Counter[str] = Counter()

    for row in nvd.itertuples(index=False):
        vendors_and_products = set(_pairs(row.affected))
        vendors = {vendor for vendor, _ in vendors_and_products}
        cwes = {str(cwe).strip().upper() for cwe in _as_values(row.cwe_ids) if cwe}
        records.append((str(row.cve_id), vendors, vendors_and_products, cwes))
        vendor_degree.update(vendors)
        product_degree.update(vendors_and_products)
        cwe_degree.update(cwes)

    centrality = []
    cve_order = []
    for cve_id, vendors, products, cwes in records:
        node_degrees = (
            [vendor_degree[node] for node in vendors]
            + [product_degree[node] for node in products]
            + [cwe_degree[node] for node in cwes]
        )
        value = (
            sum(math.log1p(degree) for degree in node_degrees) / len(node_degrees)
            if node_degrees
            else 0.0
        )
        cve_order.append(cve_id)
        centrality.append(value)

    percentiles = pd.Series(centrality).rank(method="average", pct=True).to_numpy()
    return {cve_id: round(float(score), 6) for cve_id, score in zip(cve_order, percentiles)}


def _score_row(
    cve_id: str,
    component: str,
    score: float | None,
    snapshot_date: date,
    decision_time: str,
    reason: str | None = None,
) -> dict:
    model_versions = dict(COMPONENTS)
    return {
        "cve_id": cve_id,
        "component": component,
        "decision_time": decision_time,
        "horizon_days": 30,
        "score": score,
        "score_kind": "ranking_score",
        "status": "available" if score is not None else "abstained",
        "reason": reason,
        "model_version": model_versions[component],
        "trained_through": None,
        "snapshot_date": snapshot_date.isoformat(),
    }


def generate(settings, dummy_dir: Path, rows: int = TARGET_ROWS) -> None:
    baseline_path = settings.data_processed / "d_fusion_baselines.parquet"
    nvd_path = settings.data_processed / "vulnerabilities.parquet"
    kev_path = settings.data_processed / "kev.parquet"
    for path in (baseline_path, nvd_path, kev_path):
        if not path.is_file():
            raise FileNotFoundError(f"Required local shared dataset not found: {path}")

    baseline = pd.read_parquet(baseline_path)
    nvd = pd.read_parquet(nvd_path)
    kev_ids = set(pd.read_parquet(kev_path, columns=["cve_id"])["cve_id"].astype(str))
    if baseline["cve_id"].duplicated().any() or nvd["cve_id"].duplicated().any():
        raise ValueError("NVD and CVSS/EPSS baseline tables must have unique CVE IDs")
    nvd_snapshot_dates = pd.to_datetime(nvd["snapshot_date"]).dt.date.unique()
    if len(nvd_snapshot_dates) != 1:
        raise ValueError("Dummy inputs require one shared NVD snapshot date")
    snapshot_date = nvd_snapshot_dates[0]
    decision_time = datetime.combine(
        snapshot_date, time(23, 59, 59), tzinfo=timezone.utc
    ).isoformat()

    feature_columns = ["cve_id", "description", "cwe_ids", "affected"]
    candidates = baseline.merge(nvd[feature_columns], on="cve_id", how="inner", validate="one_to_one")
    candidates = candidates[
        candidates["cvss_base_score"].notna()
        & candidates["epss_score"].notna()
        & candidates["description"].notna()
        & candidates["description"].astype(str).str.strip().ne("")
        & ~candidates["cve_id"].astype(str).isin(kev_ids)
    ].copy()
    if rows != TARGET_ROWS:
        raise ValueError(f"This fixture generator is configured for exactly {TARGET_ROWS} rows")
    sample = _select_sample(candidates)
    if len(sample) != rows:
        raise ValueError(f"Expected {rows} selected CVEs, found {len(sample)}")

    graph_scores = _graph_scores(nvd)
    outputs = {component: [] for component, _ in COMPONENTS}
    for row in sample.itertuples(index=False):
        cve_id = str(row.cve_id)
        outputs["a_text"].append(
            _score_row(
                cve_id,
                "a_text",
                _text_score(str(row.description)),
                snapshot_date,
                decision_time,
            )
        )
        poc_score, reason = _poc_scenario(cve_id, str(row.description))
        outputs["b_survival"].append(
            _score_row(
                cve_id,
                "b_survival",
                poc_score,
                snapshot_date,
                decision_time,
                reason,
            )
        )
        outputs["c_graph"].append(
            _score_row(
                cve_id,
                "c_graph",
                graph_scores[cve_id],
                snapshot_date,
                decision_time,
            )
        )

    dummy_dir.mkdir(parents=True, exist_ok=True)
    filenames = {
        "a_text": "a_text_scores.csv",
        "b_survival": "b_exploit_timing_scores.csv",
        "c_graph": "c_graph_scores.csv",
    }
    for component, component_rows in outputs.items():
        pd.DataFrame(component_rows).to_csv(dummy_dir / filenames[component], index=False)
    print(f"Generated {rows} synthetic CVE score rows for each of A, B, and C")
    print(f"Shared snapshot: {snapshot_date}; decision time: {decision_time}")
    print(f"B abstentions: {sum(row['status'] == 'abstained' for row in outputs['b_survival'])}")


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Regenerate stratified synthetic A/B/C score inputs for Component D"
    )
    parser.add_argument("--rows", type=int, default=TARGET_ROWS)
    args = parser.parse_args()
    dummy_dir = Path(__file__).resolve().parent / "dummy_inputs"
    generate(load_settings(), dummy_dir, args.rows)


if __name__ == "__main__":
    main()
