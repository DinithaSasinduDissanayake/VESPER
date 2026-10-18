"""Parse NVD CVE records into VESPER's shared vulnerability contract."""

import re
from datetime import UTC, date, datetime
from typing import Any

from vesper.contracts.vulnerability import Vulnerability

CWE_PATTERN = re.compile(r"^CWE-\d+$")
INVALID_PRODUCT_VALUES = {"", "n/a", "na", "unknown", "*", "-"}


def _parse_timestamp(value: str) -> datetime:
    """Parse an NVD timestamp and return a timezone-aware datetime."""
    if not isinstance(value, str) or not value.strip():
        raise ValueError("NVD timestamp must be a non-empty string")

    normalized = value.strip()
    if normalized.endswith("Z"):
        normalized = normalized[:-1] + "+00:00"

    parsed = datetime.fromisoformat(normalized)

    # Interpret timestamps without a timezone suffix as UTC.
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=UTC)

    return parsed.astimezone(UTC)


def _valid_identifier(value: Any) -> bool:
    """Return whether a vendor or product identifier is meaningful."""
    if not isinstance(value, str):
        return False

    cleaned = value.strip()
    return bool(cleaned) and cleaned.casefold() not in INVALID_PRODUCT_VALUES


def _extract_affected(cve: dict[str, Any]) -> tuple[tuple[str, str], ...]:
    """Extract vendor/product pairs from legacy affected data and CPE criteria."""
    pairs: set[tuple[str, str]] = set()

    def add_pair(vendor: Any, product: Any) -> None:
        """Validate and normalize a vendor/product pair."""
        if _valid_identifier(vendor) and _valid_identifier(product):
            pairs.add((vendor.strip().casefold(), product.strip().casefold()))

    # 1. Extract pairs from the legacy NVD affectedData format.
    affected_groups = cve.get("affected", [])

    if isinstance(affected_groups, list):
        for group in affected_groups:
            if not isinstance(group, dict):
                continue

            entries = group.get("affectedData", [])
            if not isinstance(entries, list):
                continue

            for entry in entries:
                if not isinstance(entry, dict):
                    continue

                add_pair(entry.get("vendor"), entry.get("product"))

    # 2. Extract pairs from CPE criteria in NVD configurations.
    # CPE 2.3 format:
    # cpe:2.3:<part>:<vendor>:<product>:<version>:...
    configurations = cve.get("configurations", [])

    def visit_node(node: Any) -> None:
        """Recursively inspect configuration nodes and their CPE matches."""
        if not isinstance(node, dict):
            return

        matches = node.get("cpeMatch", [])
        if isinstance(matches, list):
            for match in matches:
                if not isinstance(match, dict):
                    continue

                # Only include CPEs explicitly marked as vulnerable.
                if match.get("vulnerable") is not True:
                    continue

                criteria = match.get("criteria")
                if not isinstance(criteria, str):
                    continue

                parts = criteria.split(":")

                # Require a complete CPE 2.3 string with the expected prefix.
                if len(parts) != 13 or parts[:2] != ["cpe", "2.3"]:
                    continue

                part_type, vendor, product = parts[2:5]

                # CPE part type is normally a (application), h (hardware),
                # or o (operating system). Reject malformed values.
                if part_type not in {"a", "h", "o", "*", "-"}:
                    continue

                add_pair(vendor, product)

        # Some configurations contain nested AND/OR nodes.
        children = node.get("children", [])
        if isinstance(children, list):
            for child in children:
                visit_node(child)

    if isinstance(configurations, list):
        for configuration in configurations:
            if not isinstance(configuration, dict):
                continue

            nodes = configuration.get("nodes", [])
            if isinstance(nodes, list):
                for node in nodes:
                    visit_node(node)

    return tuple(sorted(pairs))


def _extract_cwes(cve: dict[str, Any]) -> tuple[str, ...]:
    """Extract distinct CWE identifiers from NVD weakness descriptions."""
    identifiers: set[str] = set()
    weaknesses = cve.get("weaknesses", [])

    if not isinstance(weaknesses, list):
        return ()

    for weakness in weaknesses:
        if not isinstance(weakness, dict):
            continue

        descriptions = weakness.get("description", [])
        if not isinstance(descriptions, list):
            continue

        for description in descriptions:
            if not isinstance(description, dict):
                continue

            value = description.get("value")
            if isinstance(value, str):
                candidate = value.strip().upper()
                if CWE_PATTERN.fullmatch(candidate):
                    identifiers.add(candidate)

    return tuple(sorted(identifiers))


def _extract_cvss(cve: dict[str, Any]) -> tuple[float | None, str | None, str | None]:
    """Return the highest available CVSS base score and its version/vector."""
    metrics = cve.get("metrics", {})
    if not isinstance(metrics, dict):
        return None, None, None

    candidates: list[tuple[float, str, str | None]] = []

    for metric_key, version in (
        ("cvssMetricV40", "4.0"),
        ("cvssMetricV31", "3.1"),
        ("cvssMetricV30", "3.0"),
        ("cvssMetricV2", "2.0"),
    ):
        entries = metrics.get(metric_key, [])
        if not isinstance(entries, list):
            continue

        for entry in entries:
            if not isinstance(entry, dict):
                continue

            data = entry.get("cvssData", {})
            if not isinstance(data, dict):
                continue

            score = data.get("baseScore")
            if isinstance(score, (int, float)) and not isinstance(score, bool):
                if 0.0 <= score <= 10.0:
                    vector = data.get("vectorString")
                    candidates.append(
                        (
                            float(score),
                            version,
                            vector if isinstance(vector, str) else None,
                        )
                    )

    if not candidates:
        return None, None, None

    # One score is stored in the shared contract. This selects the highest
    # available base score, even when scores come from different CVSS versions.
    score, version, vector = max(candidates, key=lambda item: item[0])
    return score, version, vector


def parse_nvd_record(
    record: dict[str, Any],
    snapshot_date: date,
) -> Vulnerability:
    """Convert one downloaded NVD vulnerability record into the shared contract."""
    if not isinstance(record, dict):
        raise ValueError("NVD vulnerability record must be an object")

    cve = record.get("cve")
    if not isinstance(cve, dict):
        raise ValueError("NVD record is missing its cve object")

    cve_id = cve.get("id")
    published_at = _parse_timestamp(cve.get("published"))
    last_modified_at = _parse_timestamp(cve.get("lastModified"))

    descriptions = cve.get("descriptions", [])
    description_text = ""

    if isinstance(descriptions, list):
        for item in descriptions:
            if (
                isinstance(item, dict)
                and item.get("lang") == "en"
                and isinstance(item.get("value"), str)
            ):
                description_text = item["value"].strip()
                break

    cvss_score, cvss_version, cvss_vector = _extract_cvss(cve)

    status = cve.get("vulnStatus")
    if not isinstance(status, str):
        status = "UNKNOWN"

    return Vulnerability(
        cve_id=cve_id,
        published_at=published_at,
        last_modified_at=last_modified_at,
        description=description_text,
        cvss_base_score=cvss_score,
        cvss_version=cvss_version,
        cvss_vector=cvss_vector,
        cwe_ids=_extract_cwes(cve),
        affected=_extract_affected(cve),
        nvd_status=status,
        snapshot_date=snapshot_date,
    )
