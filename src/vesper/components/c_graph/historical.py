"""Reconstruct vendor/product and CWE relationships from NVD history."""

from __future__ import annotations

import re
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any

import networkx as nx

CPE_PATTERN = re.compile(r"cpe:2\.3:([^:\s]+):([^:\s]+):([^:\s]+)")
CWE_PATTERN = re.compile(r"\bCWE-\d+\b", re.IGNORECASE)
CVE_PATTERN = re.compile(r"^CVE-\d{4}-\d{4,}$")
INVALID_IDENTIFIERS = {"", "n/a", "na", "unknown", "*", "-"}


@dataclass(frozen=True)
class CPEEvent:
    """One timestamped change to a CVE's CPE relationships."""

    cve_id: str
    created_at: datetime
    action: str
    old_pairs: tuple[tuple[str, str], ...]
    new_pairs: tuple[tuple[str, str], ...]
    event_id: str
    old_configurations: tuple[str, ...] = ()
    new_configurations: tuple[str, ...] = ()


@dataclass(frozen=True)
class CWEEvent:
    """One timestamped change to a CVE's weakness relationships."""

    cve_id: str
    created_at: datetime
    action: str
    old_cwes: tuple[str, ...]
    new_cwes: tuple[str, ...]
    event_id: str


@dataclass(frozen=True)
class HistoricalRelationships:
    """Relationships reconstructed at a requested cutoff time."""

    cve_id: str
    snapshot_at: datetime
    affected: tuple[tuple[str, str], ...]
    cwe_ids: tuple[str, ...]
    history_available: bool
    history_complete: bool
    warnings: tuple[str, ...]


def _parse_timestamp(value: Any) -> datetime:
    """Parse an NVD timestamp, treating timestamps without offsets as UTC."""
    if not isinstance(value, str) or not value.strip():
        raise ValueError("History event timestamp must be a non-empty string")

    normalized = value.strip()
    if normalized.endswith("Z"):
        normalized = normalized[:-1] + "+00:00"

    parsed = datetime.fromisoformat(normalized)

    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=UTC)

    return parsed.astimezone(UTC)


def _history_cve_id(history: dict[str, Any]) -> str:
    """Require exactly one valid CVE ID in a history response."""
    raw_changes = history.get("cveChanges")

    if not isinstance(raw_changes, list):
        raise ValueError("History response is missing its cveChanges list")

    cve_ids = {
        change["cveId"]
        for item in raw_changes
        if isinstance(item, dict)
        and isinstance((change := item.get("change")), dict)
        and isinstance(change.get("cveId"), str)
        and CVE_PATTERN.fullmatch(change["cveId"])
    }

    if len(cve_ids) != 1:
        raise ValueError("History response must contain events for exactly one valid CVE")

    return next(iter(cve_ids))


def _extract_cpe_pairs(value: Any) -> tuple[tuple[str, str], ...]:
    """Extract normalized vendor/product pairs from CPE configuration text."""
    if not isinstance(value, str):
        return ()

    pairs: set[tuple[str, str]] = set()

    for _part_type, vendor, product in CPE_PATTERN.findall(value):
        vendor = vendor.strip().casefold()
        product = product.strip().casefold()

        if vendor in INVALID_IDENTIFIERS or product in INVALID_IDENTIFIERS:
            continue

        pairs.add((vendor, product))

    return tuple(sorted(pairs))


def _extract_cwe_ids(value: Any) -> tuple[str, ...]:
    """Extract normalized CWE IDs from an NVD history value."""
    if not isinstance(value, str):
        return ()

    return tuple(sorted({item.upper() for item in CWE_PATTERN.findall(value)}))


def _iter_details(history: dict[str, Any]):
    """Yield timestamped history details in chronological order."""
    if not isinstance(history, dict):
        raise ValueError("History response must be a JSON object")

    raw_changes = history.get("cveChanges")
    if not isinstance(raw_changes, list):
        raise ValueError("History response is missing its cveChanges list")

    rows = []

    for item in raw_changes:
        if not isinstance(item, dict):
            continue

        change = item.get("change")
        if not isinstance(change, dict):
            continue

        cve_id = change.get("cveId")
        created = change.get("created")

        if not isinstance(cve_id, str) or not CVE_PATTERN.fullmatch(cve_id):
            continue
        if not isinstance(created, str):
            continue

        created_at = _parse_timestamp(created)

        event_id = change.get("cveChangeId")
        if not isinstance(event_id, str):
            event_id = ""

        details = change.get("details")
        if not isinstance(details, list):
            continue

        for detail in details:
            if isinstance(detail, dict):
                rows.append((created_at, event_id, cve_id, detail))

    yield from sorted(rows, key=lambda row: (row[0], row[1]))


def parse_cpe_events(history: dict[str, Any]) -> tuple[CPEEvent, ...]:
    """Parse CPE changes and preserve their original configuration values."""
    events: list[CPEEvent] = []

    for created_at, event_id, cve_id, detail in _iter_details(history):
        if detail.get("type") != "CPE Configuration":
            continue

        action = detail.get("action")
        if action not in {"Added", "Removed", "Changed"}:
            continue

        old_value = detail.get("oldValue", detail.get("previousValue"))
        new_value = detail.get("newValue")

        old_pairs = _extract_cpe_pairs(old_value)
        new_pairs = _extract_cpe_pairs(new_value)

        old_configurations = (
            (old_value.strip(),) if isinstance(old_value, str) and old_value.strip() else ()
        )
        new_configurations = (
            (new_value.strip(),) if isinstance(new_value, str) and new_value.strip() else ()
        )

        if action == "Added" and not new_pairs:
            continue
        if action == "Removed" and not old_pairs:
            continue
        if action == "Changed" and not old_pairs and not new_pairs:
            continue

        events.append(
            CPEEvent(
                cve_id=cve_id,
                created_at=created_at,
                action=action,
                old_pairs=old_pairs,
                new_pairs=new_pairs,
                event_id=event_id,
                old_configurations=old_configurations,
                new_configurations=new_configurations,
            )
        )

    return tuple(events)


def parse_cwe_events(history: dict[str, Any]) -> tuple[CWEEvent, ...]:
    """Parse CWE additions, removals, and changes from NVD history."""
    events: list[CWEEvent] = []

    for created_at, event_id, cve_id, detail in _iter_details(history):
        if detail.get("type") != "CWE":
            continue

        action = detail.get("action")
        if action not in {"Added", "Removed", "Changed"}:
            continue

        old_cwes = _extract_cwe_ids(detail.get("oldValue", detail.get("previousValue")))
        new_cwes = _extract_cwe_ids(detail.get("newValue"))

        if action == "Added" and not new_cwes:
            continue
        if action == "Removed" and not old_cwes:
            continue
        if action == "Changed" and not old_cwes and not new_cwes:
            continue

        events.append(
            CWEEvent(
                cve_id=cve_id,
                created_at=created_at,
                action=action,
                old_cwes=old_cwes,
                new_cwes=new_cwes,
                event_id=event_id,
            )
        )

    return tuple(events)


def reconstruct_relationships(
    history: dict[str, Any],
    snapshot_at: datetime,
) -> HistoricalRelationships:
    """Apply recorded CPE and CWE events up to a requested UTC cutoff.

    This is a partial reconstruction. NVD history alone does not prove that
    every historical relationship or the original state was captured.
    """
    if snapshot_at.tzinfo is None:
        raise ValueError("snapshot_at must be timezone-aware")

    snapshot_at = snapshot_at.astimezone(UTC)
    cve_id = _history_cve_id(history)
    raw_changes = history["cveChanges"]

    cpe_events = [
        event
        for event in parse_cpe_events(history)
        if event.cve_id == cve_id and event.created_at <= snapshot_at
    ]
    cwe_events = [
        event
        for event in parse_cwe_events(history)
        if event.cve_id == cve_id and event.created_at <= snapshot_at
    ]

    warnings: list[str] = []
    affected: set[tuple[str, str]] = set()
    cwe_ids: set[str] = set()

    # NVD history may reference external affected-product data without
    # including the actual CPE values. Report this limitation explicitly.
    for created_at, event_id, detail_cve_id, detail in _iter_details(history):
        if detail_cve_id != cve_id or created_at > snapshot_at:
            continue

        if detail.get("type") != "Affected":
            continue

        if detail.get("action") not in {"Added", "Removed", "Changed"}:
            continue

        old_value = detail.get("oldValue", detail.get("previousValue"))
        new_value = detail.get("newValue")

        if not _extract_cpe_pairs(old_value) and not _extract_cpe_pairs(new_value):
            warnings.append(
                f"Affected event {event_id or '(unknown ID)'} "
                "cannot be reconstructed from the history payload because "
                "it contains no interpretable CPE vendor/product values."
            )

    if not cpe_events:
        warnings.append("No interpretable CPE events exist by the cutoff.")
    else:
        if cpe_events[0].action != "Added":
            warnings.append(
                "The earliest CPE event is not an addition; the starting state is uncertain."
            )

        for event in cpe_events:
            if event.action == "Added":
                affected.update(event.new_pairs)
            elif event.action == "Removed":
                affected.difference_update(event.old_pairs)
            else:
                affected.difference_update(event.old_pairs)
                affected.update(event.new_pairs)

                if not event.old_pairs or not event.new_pairs:
                    warnings.append(
                        f"CPE change {event.event_id or '(unknown ID)'} "
                        "has incomplete old/new values."
                    )

    if not cwe_events:
        warnings.append("No interpretable CWE events exist by the cutoff.")
    else:
        if cwe_events[0].action != "Added":
            warnings.append(
                "The earliest CWE event is not an addition; "
                "the starting weakness state is uncertain."
            )

        for event in cwe_events:
            if event.action == "Added":
                cwe_ids.update(event.new_cwes)
            elif event.action == "Removed":
                cwe_ids.difference_update(event.old_cwes)
            else:
                cwe_ids.difference_update(event.old_cwes)
                cwe_ids.update(event.new_cwes)

                if not event.old_cwes or not event.new_cwes:
                    warnings.append(
                        f"CWE change {event.event_id or '(unknown ID)'} "
                        "has incomplete old/new values."
                    )

    warnings.append(
        "NVD history alone does not prove that the original state or every "
        "historical relationship is represented."
    )

    return HistoricalRelationships(
        cve_id=cve_id,
        snapshot_at=snapshot_at,
        affected=tuple(sorted(affected)),
        cwe_ids=tuple(sorted(cwe_ids)),
        history_available=bool(raw_changes),
        history_complete=False,
        warnings=tuple(warnings),
    )


def build_historical_graph(
    relationships: HistoricalRelationships,
) -> nx.DiGraph:
    """Build a graph from reconstructed historical relationships.

    This graph contains only relationships represented in the reconstruction.
    It does not imply that the snapshot is complete.
    """
    graph = nx.DiGraph()

    cve_id = relationships.cve_id
    cve_node = f"cve:{cve_id}"

    graph.add_node(
        cve_node,
        node_type="cve",
        cve_id=cve_id,
        snapshot_at=relationships.snapshot_at.isoformat(),
        history_available=relationships.history_available,
        history_complete=relationships.history_complete,
        warnings=list(relationships.warnings),
    )

    for vendor, product in relationships.affected:
        vendor_node = f"vendor:{vendor}"
        product_node = f"product:{vendor}:{product}"

        graph.add_node(
            vendor_node,
            node_type="vendor",
            name=vendor,
        )
        graph.add_node(
            product_node,
            node_type="product",
            vendor=vendor,
            name=product,
        )

        graph.add_edge(
            vendor_node,
            product_node,
            relation="offers",
        )
        graph.add_edge(
            product_node,
            cve_node,
            relation="affected_by",
        )

    for cwe_id in relationships.cwe_ids:
        cwe_node = f"cwe:{cwe_id}"

        graph.add_node(
            cwe_node,
            node_type="cwe",
            cwe_id=cwe_id,
        )
        graph.add_edge(
            cve_node,
            cwe_node,
            relation="has_weakness",
        )

    return graph


def build_multi_cve_historical_graph(
    relationships_list: list[HistoricalRelationships],
) -> nx.DiGraph:
    """Build one shared graph from multiple reconstructed CVE relationships."""
    graph = nx.DiGraph()
    seen_cves: set[str] = set()

    for relationships in relationships_list:
        if relationships.cve_id in seen_cves:
            raise ValueError(f"Duplicate CVE history supplied: {relationships.cve_id}")

        seen_cves.add(relationships.cve_id)

        cve_node = f"cve:{relationships.cve_id}"
        graph.add_node(
            cve_node,
            node_type="cve",
            cve_id=relationships.cve_id,
            snapshot_at=relationships.snapshot_at.isoformat(),
            history_available=relationships.history_available,
            history_complete=relationships.history_complete,
            warnings=list(relationships.warnings),
        )

        for vendor, product in relationships.affected:
            vendor_node = f"vendor:{vendor}"
            product_node = f"product:{vendor}:{product}"

            graph.add_node(
                vendor_node,
                node_type="vendor",
                name=vendor,
            )
            graph.add_node(
                product_node,
                node_type="product",
                vendor=vendor,
                name=product,
            )

            graph.add_edge(
                vendor_node,
                product_node,
                relation="offers",
            )
            graph.add_edge(
                product_node,
                cve_node,
                relation="affected_by",
            )

        for cwe_id in relationships.cwe_ids:
            cwe_node = f"cwe:{cwe_id}"
            graph.add_node(
                cwe_node,
                node_type="cwe",
                cwe_id=cwe_id,
            )
            graph.add_edge(
                cve_node,
                cwe_node,
                relation="has_weakness",
            )

    return graph
