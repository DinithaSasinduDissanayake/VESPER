
"""Parse NVD CVE API records into VESPER vulnerability contracts."""

from datetime import UTC, date, datetime
from typing import Any

from vesper.contracts.vulnerability import Vulnerability


class SnapshotDateError(ValueError):
    """Raised when an NVD record was modified after the requested snapshot."""


def _parse_timestamp(value: str) -> datetime:
    """Parse an ISO 8601 timestamp and ensure it is timezone-aware."""
    parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=UTC)
    return parsed


def _extract_affected(cve: dict[str, Any]) -> tuple[tuple[str, str], ...]:
    """Extract unique vendor/product pairs from NVD CPE criteria."""
    affected: set[tuple[str, str]] = set()

    for configuration in cve.get("configurations", []):
        for node in configuration.get("nodes", []):
            for match in node.get("cpeMatch", []):
                if not match.get("vulnerable", False):
                    continue

                criteria = match.get("criteria", "")
                parts = criteria.split(":")
                if len(parts) < 6 or not criteria.startswith("cpe:2.3:"):
                    continue

                vendor, product = parts[3], parts[4]
                if vendor not in {"*", "-", "n/a"} and product not in {
                    "*",
                    "-",
                    "n/a",
                }:
                    affected.add((vendor, product))

            for child in node.get("children", []):
                for match in child.get("cpeMatch", []):
                    if not match.get("vulnerable", False):
                        continue

                    criteria = match.get("criteria", "")
                    parts = criteria.split(":")
                    if len(parts) < 6 or not criteria.startswith("cpe:2.3:"):
                        continue

                    vendor, product = parts[3], parts[4]
                    if vendor not in {"*", "-", "n/a"} and product not in {
                        "*",
                        "-",
                        "n/a",
                    }:
                        affected.add((vendor, product))

    return tuple(sorted(affected))


def _extract_cwes(cve: dict[str, Any]) -> tuple[str, ...]:
    """Extract specific CWE IDs, excluding generic NVD classifications."""
    cwe_ids: set[str] = set()

    for weakness in cve.get("weaknesses", []):
        for description in weakness.get("description", []):
            value = description.get("value", "")
            if value.startswith("CWE-") and value != "NVD-CWE-Other":
                cwe_ids.add(value)

    return tuple(sorted(cwe_ids))


def _extract_cvss(
    cve: dict[str, Any],
) -> tuple[float | None, str | None, str | None]:
    """Extract the first available CVSS base score, version, and vector."""
    for metric_name in (
        "cvssMetricV40",
        "cvssMetricV31",
        "cvssMetricV30",
        "cvssMetricV2",
    ):
        metrics = cve.get("metrics", {}).get(metric_name, [])
        if not metrics:
            continue

        cvss = metrics[0].get("cvssData", {})
        return (
            cvss.get("baseScore"),
            cvss.get("version"),
            cvss.get("vectorString"),
        )

    return None, None, None


def parse_nvd_record(
    record: dict[str, Any], snapshot_date: date
) -> Vulnerability:
    """Convert one NVD API vulnerability wrapper into a VESPER contract.

    Reject records whose last-modified date is later than the requested
    snapshot date. This is a conservative safeguard; it does not reconstruct
    historical field values for records modified on or before the cutoff.
    """
    cve = record["cve"]

    last_modified_at = _parse_timestamp(cve["lastModified"])

    if last_modified_at.date() > snapshot_date:
        raise SnapshotDateError(
            f"{cve['id']} was modified after snapshot date "
            f"{snapshot_date}; historical state cannot be guaranteed"
        )

    descriptions = cve.get("descriptions", [])
    description = next(
        (
            item.get("value", "")
            for item in descriptions
            if item.get("lang") == "en"
        ),
        "",
    )

    cvss_score, cvss_version, cvss_vector = _extract_cvss(cve)

    return Vulnerability(
        cve_id=cve["id"],
        published_at=_parse_timestamp(cve["published"]),
        last_modified_at=last_modified_at,
        description=description,
        cvss_base_score=cvss_score,
        cvss_version=cvss_version,
        cvss_vector=cvss_vector,
        cwe_ids=_extract_cwes(cve),
        affected=_extract_affected(cve),
        nvd_status=cve.get("vulnStatus", "Unknown"),
        snapshot_date=snapshot_date,
    )
