
"""Reconstruct historically documented CVE relationships from NVD history."""

from dataclasses import dataclass
from datetime import date
from typing import Any


@dataclass(frozen=True)
class HistoricalRelationships:
    """Relationships explicitly documented by NVD history before a cutoff."""

    cve_id: str
    snapshot_date: date
    cwe_ids: tuple[str, ...]
    affected: tuple[tuple[str, str], ...]
    evidence_events: int


def reconstruct_relationships(
    cve_id: str,
    history: dict[str, Any],
    snapshot_date: date,
) -> HistoricalRelationships:
    """Extract CWE and CPE relationships added by the cutoff date.

    This prototype accepts explicit 'Added' events only. It does not
    guarantee complete historical state if changes or removals are missing.
    """
    cwe_ids: set[str] = set()
    affected: set[tuple[str, str]] = set()
    evidence_events = 0

    for item in history.get("cveChanges", []):
        change = item.get("change", {})
        created = change.get("created", "")

        if not created:
            continue

        try:
            event_date = date.fromisoformat(created[:10])
        except ValueError:
            continue

        if event_date > snapshot_date:
            continue

        for detail in change.get("details", []):
            action = detail.get("action", "")
            detail_type = detail.get("type", "")
            new_value = detail.get("newValue", "")

            if action != "Added":
                continue

            if detail_type == "CWE":
                value = new_value.strip()
                cwe_id = value.split()[-1] if value else ""

                # NVD may prefix the CWE ID with a source name.
                if cwe_id.startswith("CWE-"):
                    cwe_ids.add(cwe_id)
                    evidence_events += 1

            elif detail_type == "CPE Configuration":
                for line in new_value.splitlines():
                    value = line.strip()

                    if value.startswith("*"):
                        value = value.lstrip("*").strip()

                    if not value.startswith("cpe:2.3:"):
                        continue

                    parts = value.split(":")
                    if len(parts) < 6:
                        continue

                    vendor, product = parts[3], parts[4]

                    if (
                        vendor not in {"", "*", "-", "n/a"}
                        and product not in {"", "*", "-", "n/a"}
                    ):
                        affected.add((vendor, product))
                        evidence_events += 1

    return HistoricalRelationships(
        cve_id=cve_id,
        snapshot_date=snapshot_date,
        cwe_ids=tuple(sorted(cwe_ids)),
        affected=tuple(sorted(affected)),
        evidence_events=evidence_events,
    )
