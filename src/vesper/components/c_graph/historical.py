"""Reconstruct vendor/product and CWE relationships from NVD history."""

from __future__ import annotations

import json
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
    source_identifier: str = ""
    event_name: str = ""
    original_old_value: Any = None
    original_new_value: Any = None


@dataclass(frozen=True)
class CWEEvent:
    """One timestamped change to a CVE's weakness relationships."""

    cve_id: str
    created_at: datetime
    action: str
    old_cwes: tuple[str, ...]
    new_cwes: tuple[str, ...]
    event_id: str
    source_identifier: str = ""
    event_name: str = ""
    original_old_value: Any = None
    original_new_value: Any = None


@dataclass(frozen=True)
class AffectedEvent:
    """An embedded CVE Record Format affected-data event."""

    cve_id: str
    created_at: datetime
    action: str
    old_pairs: tuple[tuple[str, str], ...]
    new_pairs: tuple[tuple[str, str], ...]
    event_id: str
    source_identifier: str
    event_name: str
    original_old_value: Any
    original_new_value: Any
    evidence_state: str


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
    feature_eligible: bool
    exclusion_reasons: tuple[str, ...]


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


def validate_history_response(history: Any, expected_cve_id: str | None = None) -> int:
    """Validate a complete aggregated NVD history response envelope.

    A valid empty response is accepted when the expected CVE ID comes from its
    filename; the empty response has no event from which to infer an ID.
    """
    if not isinstance(history, dict):
        raise ValueError("History response must be a JSON object")
    if history.get("format") != "NVD_CVEHistory" or history.get("version") != "2.0":
        raise ValueError("History response has an unexpected format or version")
    _parse_timestamp(history.get("timestamp"))

    changes = history.get("cveChanges")
    if not isinstance(changes, list):
        raise ValueError("History response is missing its cveChanges list")
    for key in ("resultsPerPage", "startIndex", "totalResults"):
        if type(history.get(key)) is not int:
            raise ValueError(f"History response is missing integer {key}")
    if (
        history["startIndex"] != 0
        or history["resultsPerPage"] != len(changes)
        or history["totalResults"] != len(changes)
    ):
        raise ValueError("History response is incomplete or has inconsistent pagination metadata")

    if expected_cve_id is not None and not CVE_PATTERN.fullmatch(expected_cve_id):
        raise ValueError(f"Invalid expected CVE ID: {expected_cve_id!r}")
    if changes:
        response_cve_id = _history_cve_id(history)
        if expected_cve_id is not None and response_cve_id != expected_cve_id:
            raise ValueError(
                f"History CVE ID {response_cve_id} does not match expected {expected_cve_id}"
            )
    elif expected_cve_id is None:
        raise ValueError("An empty history response requires a valid CVE ID from its filename")

    for item in changes:
        if not isinstance(item, dict) or not isinstance(item.get("change"), dict):
            raise ValueError("History response contains a malformed change record")
        change = item["change"]
        event_cve_id = change.get("cveId")
        if not isinstance(event_cve_id, str) or not CVE_PATTERN.fullmatch(event_cve_id):
            raise ValueError("History response contains an invalid event CVE ID")
        if expected_cve_id is not None and event_cve_id != expected_cve_id:
            raise ValueError(
                f"History CVE ID {event_cve_id} does not match expected {expected_cve_id}"
            )
        _parse_timestamp(change.get("created"))
        details = change.get("details")
        if not isinstance(details, list) or any(not isinstance(detail, dict) for detail in details):
            raise ValueError("History response contains malformed change details")
    return len(changes)


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

        source_identifier = change.get("sourceIdentifier")
        event_name = change.get("eventName")
        for detail in details:
            if isinstance(detail, dict):
                rows.append(
                    (
                        created_at,
                        event_id,
                        cve_id,
                        source_identifier if isinstance(source_identifier, str) else "",
                        event_name if isinstance(event_name, str) else "",
                        detail,
                    )
                )

    yield from sorted(rows, key=lambda row: (row[0], row[1]))


def parse_cpe_events(history: dict[str, Any]) -> tuple[CPEEvent, ...]:
    """Parse CPE changes and preserve their original configuration values."""
    events: list[CPEEvent] = []

    for created_at, event_id, cve_id, source_identifier, event_name, detail in _iter_details(
        history
    ):
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
                source_identifier=source_identifier,
                event_name=event_name,
                original_old_value=old_value,
                original_new_value=new_value,
            )
        )

    return tuple(events)


def parse_cwe_events(history: dict[str, Any]) -> tuple[CWEEvent, ...]:
    """Parse CWE additions, removals, and changes from NVD history."""
    events: list[CWEEvent] = []

    for created_at, event_id, cve_id, source_identifier, event_name, detail in _iter_details(
        history
    ):
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
                source_identifier=source_identifier,
                event_name=event_name,
                original_old_value=detail.get("oldValue", detail.get("previousValue")),
                original_new_value=detail.get("newValue"),
            )
        )

    return tuple(events)


def _parse_affected_value(value: Any) -> tuple[tuple[tuple[str, str], ...], str]:
    """Read explicit vendor/product pairs from an embedded affected JSON value.

    GitHub references and package-only values are intentionally not converted to
    vendor/product names. Their relationship state is unrecoverable here.
    """
    if isinstance(value, str):
        if "<a href=" in value.casefold() or "github.com/cveproject/cvelistv5" in value.casefold():
            return (), "github_reference_unrecoverable"
        try:
            value = json.loads(value)
        except json.JSONDecodeError:
            return (), "unsupported_affected_payload"
    if not isinstance(value, list) or not value:
        return (), "unsupported_affected_payload"

    pairs: set[tuple[str, str]] = set()
    for record in value:
        if not isinstance(record, dict):
            return (), "unsupported_affected_payload"
        vendor = record.get("vendor")
        product = record.get("product")
        if not isinstance(vendor, str) or not isinstance(product, str):
            return (), "affected_vendor_product_unavailable"
        normalized_vendor = vendor.strip().casefold()
        normalized_product = product.strip().casefold()
        if normalized_vendor in INVALID_IDENTIFIERS or normalized_product in INVALID_IDENTIFIERS:
            return (), "affected_vendor_product_unavailable"
        statuses: list[str] = []
        default_status = record.get("defaultStatus")
        if default_status is not None:
            statuses.append(default_status)
        versions = record.get("versions")
        if versions is not None:
            if not isinstance(versions, list):
                return (), "unsupported_affected_payload"
            for version in versions:
                if not isinstance(version, dict):
                    return (), "unsupported_affected_payload"
                status = version.get("status")
                if status is not None:
                    statuses.append(status)
                changes = version.get("changes", [])
                if not isinstance(changes, list):
                    return (), "unsupported_affected_payload"
                for change in changes:
                    if not isinstance(change, dict):
                        return (), "unsupported_affected_payload"
                    change_status = change.get("status")
                    if change_status is not None:
                        statuses.append(change_status)
        if not statuses or any(
            status not in {"affected", "unaffected", "unknown"} for status in statuses
        ):
            return (), "affected_status_uncertain"
        if "affected" in statuses:
            pairs.add((normalized_vendor, normalized_product))
        elif "unknown" in statuses:
            return (), "affected_status_uncertain"
    return tuple(sorted(pairs)), "supported_embedded_affected_data"


def parse_affected_events(history: dict[str, Any]) -> tuple[AffectedEvent, ...]:
    """Parse embedded affected JSON while retaining raw values and provenance."""
    events: list[AffectedEvent] = []
    for (
        created_at,
        event_id,
        cve_id,
        source_identifier,
        event_name,
        detail,
    ) in _iter_details(history):
        if detail.get("type") != "Affected":
            continue
        action = detail.get("action")
        original_old = detail.get("oldValue", detail.get("previousValue"))
        original_new = detail.get("newValue")
        old_pairs, old_state = (
            _parse_affected_value(original_old) if original_old is not None else ((), "")
        )
        new_pairs, new_state = (
            _parse_affected_value(original_new) if original_new is not None else ((), "")
        )

        if action == "Added" and new_state == "supported_embedded_affected_data":
            state = new_state
        elif action == "Removed" and old_state == "supported_embedded_affected_data":
            state = old_state
        elif (
            action == "Changed"
            and old_state == "supported_embedded_affected_data"
            and new_state == "supported_embedded_affected_data"
        ):
            state = new_state
        else:
            state = next(
                (
                    item
                    for item in (old_state, new_state)
                    if item and item != "supported_embedded_affected_data"
                ),
                "unsupported_affected_payload",
            )

        events.append(
            AffectedEvent(
                cve_id=cve_id,
                created_at=created_at,
                action=action if isinstance(action, str) else "",
                old_pairs=old_pairs,
                new_pairs=new_pairs,
                event_id=event_id,
                source_identifier=source_identifier,
                event_name=event_name,
                original_old_value=original_old,
                original_new_value=original_new,
                evidence_state=state,
            )
        )
    return tuple(events)


def reconstruct_relationships(
    history: dict[str, Any],
    snapshot_at: datetime,
    cve_id: str | None = None,
) -> HistoricalRelationships:
    """Reconstruct CPE and CWE relationships up to a UTC cutoff.

    This is a partial reconstruction. NVD history alone does not prove
    that every historical relationship or the original state was captured.
    """
    if snapshot_at.tzinfo is None:
        raise ValueError("snapshot_at must be timezone-aware")

    snapshot_at = snapshot_at.astimezone(UTC)

    event_count = validate_history_response(history, cve_id)
    raw_changes = history["cveChanges"]
    if raw_changes:
        cve_id = _history_cve_id(history)

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
    affected_events = [
        event
        for event in parse_affected_events(history)
        if event.cve_id == cve_id and event.created_at <= snapshot_at
    ]

    warnings: list[str] = []
    exclusion_reasons: list[str] = []
    affected: set[tuple[str, str]] = set()
    affected_json_pairs: set[tuple[str, str]] = set()
    cwe_ids: set[str] = set()

    for (
        created_at,
        event_id,
        detail_cve_id,
        _source_identifier,
        _event_name,
        detail,
    ) in _iter_details(history):
        if detail_cve_id != cve_id or created_at > snapshot_at:
            continue

        detail_type = detail.get("type")
        action = detail.get("action")
        old_value = detail.get("oldValue", detail.get("previousValue"))
        new_value = detail.get("newValue")

        old_cpe_pairs = _extract_cpe_pairs(old_value)
        new_cpe_pairs = _extract_cpe_pairs(new_value)
        old_cwes = _extract_cwe_ids(old_value)
        new_cwes = _extract_cwe_ids(new_value)

        if detail_type == "CPE Configuration" and (
            action not in {"Added", "Removed", "Changed"}
            or (action == "Added" and not new_cpe_pairs)
            or (action == "Removed" and not old_cpe_pairs)
            or (action == "Changed" and not old_cpe_pairs and not new_cpe_pairs)
        ):
            warnings.append(
                f"CPE Configuration event {event_id or '(unknown ID)'} "
                "has an unsupported action or uninterpretable relationship values."
            )
            exclusion_reasons.append("unsupported_cpe_configuration_change")
        elif detail_type == "CWE" and (
            action not in {"Added", "Removed", "Changed"}
            or (action == "Added" and not new_cwes)
            or (action == "Removed" and not old_cwes)
            or (action == "Changed" and not old_cwes and not new_cwes)
        ):
            warnings.append(
                f"CWE event {event_id or '(unknown ID)'} "
                "has an unsupported action or uninterpretable relationship values."
            )
            exclusion_reasons.append("unsupported_cwe_change")

    if not cpe_events:
        warnings.append("No interpretable CPE events exist by the cutoff.")
        exclusion_reasons.append("no_interpretable_cpe_events_by_cutoff")
    else:
        if cpe_events[0].action != "Added":
            warnings.append(
                "The earliest CPE event is not an addition; the starting state is uncertain."
            )
            exclusion_reasons.append("uncertain_initial_cpe_state")

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
                    exclusion_reasons.append("incomplete_cpe_change_values")

    if affected_events:
        if affected_events[0].action != "Added":
            warnings.append(
                "The earliest affected-data event is not an addition; "
                "the affected-data starting state is uncertain."
            )
            exclusion_reasons.append("uncertain_initial_affected_state")
        for event in affected_events:
            if event.evidence_state != "supported_embedded_affected_data":
                warnings.append(
                    f"Affected event {event.event_id or '(unknown ID)'} is unsupported: "
                    f"{event.evidence_state}."
                )
                exclusion_reasons.extend(
                    (
                        "unsupported_affected_relationship_change",
                        event.evidence_state,
                    )
                )
                continue
            if event.action == "Added":
                affected_json_pairs.update(event.new_pairs)
            elif event.action == "Removed":
                affected_json_pairs.difference_update(event.old_pairs)
            elif event.action == "Changed":
                affected_json_pairs.difference_update(event.old_pairs)
                affected_json_pairs.update(event.new_pairs)
            else:
                warnings.append(
                    f"Affected event {event.event_id or '(unknown ID)'} has unsupported action."
                )
                exclusion_reasons.extend(
                    ("unsupported_affected_relationship_change", "unsupported_affected_action")
                )
    affected.update(affected_json_pairs)

    if not cwe_events:
        warnings.append("No interpretable CWE events exist by the cutoff.")
        exclusion_reasons.append("no_interpretable_cwe_events_by_cutoff")
    else:
        if cwe_events[0].action != "Added":
            warnings.append(
                "The earliest CWE event is not an addition; "
                "the starting weakness state is uncertain."
            )
            exclusion_reasons.append("uncertain_initial_cwe_state")

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
                    exclusion_reasons.append("incomplete_cwe_change_values")

    if event_count == 0:
        warnings.append("The history response contains no recorded events.")
        exclusion_reasons = ["valid_empty_history_response"]

    warnings.append(
        "NVD history alone does not prove that the original state or every "
        "historical relationship is represented."
    )

    return HistoricalRelationships(
        cve_id=cve_id,
        snapshot_at=snapshot_at,
        affected=tuple(sorted(affected)),
        cwe_ids=tuple(sorted(cwe_ids)),
        history_available=True,
        history_complete=False,
        warnings=tuple(warnings),
        feature_eligible=not exclusion_reasons,
        exclusion_reasons=tuple(dict.fromkeys(exclusion_reasons)),
    )


def build_historical_graph(
    relationships: HistoricalRelationships,
) -> nx.DiGraph:
    """Build a graph from reconstructed historical relationships.

    This graph contains only relationships represented in the reconstruction.
    It does not imply that the snapshot is complete.
    """
    graph = nx.DiGraph()

    if not relationships.feature_eligible:
        return graph

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

        if not relationships.feature_eligible:
            continue

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
