
"""Reconstruct historically documented CVE relationships from NVD history."""

from dataclasses import dataclass
from datetime import date, datetime
from typing import Any


@dataclass(frozen=True)
class HistoricalRelationships:
    """Relationships documented by NVD history before a cutoff."""

    cve_id: str
    snapshot_date: date
    cwe_ids: tuple[str, ...]
    affected: tuple[tuple[str, str], ...]
    evidence_events: int
    history_complete: bool = False
    limitations: tuple[str, ...] = (
        "History completeness has not been independently verified.",
        "Only explicitly documented CWE and CPE changes are reconstructed.",
        "CVSS, description, status, and other fields are not reconstructed.",
    )


def _event_date(change: dict[str, Any]) -> date | None:
    """Return the date of a history event, or None if invalid."""
    created = change.get("created", "")
    if not created:
        return None

    try:
        return datetime.fromisoformat(
            created.replace("Z", "+00:00")
        ).date()
    except ValueError:
        return None


def _extract_cwe_id(value: str) -> str | None:
    """Extract a CWE identifier from values such as 'NIST CWE-79'."""
    parts = value.strip().split()
    if not parts:
        return None

    candidate = parts[-1]
    if candidate.startswith("CWE-"):
        return candidate

    return None


def _extract_cpe_pairs(value: str) -> set[tuple[str, str]]:
    """Extract vendor/product pairs from CPE configuration text."""
    pairs: set[tuple[str, str]] = set()

    for line in value.splitlines():
        candidate = line.strip()

        if candidate.startswith("*"):
            candidate = candidate.lstrip("*").strip()

        if not candidate.startswith("cpe:2.3:"):
            continue

        parts = candidate.split(":")
        if len(parts) < 6:
            continue

        vendor, product = parts[3], parts[4]
        if (
            vendor not in {"", "*", "-", "n/a"}
            and product not in {"", "*", "-", "n/a"}
        ):
            pairs.add((vendor, product))

    return pairs


def reconstruct_relationships(
    cve_id: str,
    history: dict[str, Any],
    snapshot_date: date,
) -> HistoricalRelationships:
    """Reconstruct documented CWE/CPE changes through the cutoff date.

    This processes explicit additions, removals, and CPE configuration
    changes. It does not guarantee that the supplied history is complete.
    """
    cwe_ids: set[str] = set()
    affected: set[tuple[str, str]] = set()
    evidence_events = 0

    events = []
    for item in history.get("cveChanges", []):
        change = item.get("change", {})
        event_date = _event_date(change)

        if event_date is not None and event_date <= snapshot_date:
            events.append((event_date, change))

    # Preserve source order for events on the same date.
    events.sort(key=lambda event: event[0])

    for _, change in events:
        for detail in change.get("details", []):
            action = detail.get("action", "")
            detail_type = detail.get("type", "")
            new_value = detail.get("newValue", "")
            old_value = detail.get("oldValue", "")

            if detail_type == "CWE":
                if action == "Added":
                    cwe_id = _extract_cwe_id(new_value)
                    if cwe_id:
                        cwe_ids.add(cwe_id)
                        evidence_events += 1

                elif action == "Removed":
                    cwe_id = _extract_cwe_id(old_value or new_value)
                    if cwe_id:
                        cwe_ids.discard(cwe_id)
                        evidence_events += 1

            elif detail_type == "CPE Configuration":
                if action == "Added":
                    pairs = _extract_cpe_pairs(new_value)
                    affected.update(pairs)
                    evidence_events += len(pairs)

                elif action == "Removed":
                    pairs = _extract_cpe_pairs(old_value or new_value)
                    affected.difference_update(pairs)
                    evidence_events += len(pairs)

                elif action == "Changed":
                    old_pairs = _extract_cpe_pairs(old_value)
                    new_pairs = _extract_cpe_pairs(new_value)

                    affected.difference_update(old_pairs)
                    affected.update(new_pairs)
                    evidence_events += len(old_pairs) + len(new_pairs)

    return HistoricalRelationships(
        cve_id=cve_id,
        snapshot_date=snapshot_date,
        cwe_ids=tuple(sorted(cwe_ids)),
        affected=tuple(sorted(affected)),
        evidence_events=evidence_events,
    )
