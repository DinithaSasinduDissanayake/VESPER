"""Exploratory, source-separated graph analysis for historical CPE and CWE evidence."""

from __future__ import annotations

import csv
import json
from collections import Counter
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import networkx as nx
import pandas as pd

from vesper.components.c_graph.historical import (
    CPEEvent,
    CWEEvent,
    parse_cpe_events,
    parse_cwe_events,
    reconstruct_relationships,
    validate_history_response,
)


@dataclass(frozen=True)
class LayerRelationships:
    """One CVE's independently reconstructed relationship state for a graph layer."""

    cve_id: str
    snapshot_at: datetime
    layer: str
    relationships: tuple[Any, ...]
    eligible: bool
    exclusion_reasons: tuple[str, ...]


def _replay_cpe(events: tuple[CPEEvent, ...]) -> tuple[tuple[str, str], ...]:
    state: set[tuple[str, str]] = set()
    for event in events:
        if event.action == "Added":
            state.update(event.new_pairs)
        elif event.action == "Removed":
            state.difference_update(event.old_pairs)
        else:
            state.difference_update(event.old_pairs)
            state.update(event.new_pairs)
    return tuple(sorted(state))


def _replay_cwe(events: tuple[CWEEvent, ...]) -> tuple[str, ...]:
    state: set[str] = set()
    for event in events:
        if event.action == "Added":
            state.update(event.new_cwes)
        elif event.action == "Removed":
            state.difference_update(event.old_cwes)
        else:
            state.difference_update(event.old_cwes)
            state.update(event.new_cwes)
    return tuple(sorted(state))


def reconstruct_relationship_layers(
    history: dict[str, Any], snapshot_at: datetime, cve_id: str
) -> dict[str, LayerRelationships]:
    """Reconstruct CPE and CWE independently at a cutoff.

    The production combined eligibility result is consulted only for each
    layer's own uncertainty/error reason codes. Affected and other-layer
    exclusions do not suppress this layer's independently supported evidence.
    """
    if snapshot_at.tzinfo is None:
        raise ValueError("snapshot_at must be timezone-aware")
    snapshot_at = snapshot_at.astimezone(UTC)
    validate_history_response(history, cve_id)
    combined = reconstruct_relationships(history, snapshot_at, cve_id=cve_id)

    layer_codes = {
        "cpe": {
            "no_interpretable_cpe_events_by_cutoff",
            "uncertain_initial_cpe_state",
            "incomplete_cpe_change_values",
            "unsupported_cpe_configuration_change",
        },
        "cwe": {
            "no_interpretable_cwe_events_by_cutoff",
            "uncertain_initial_cwe_state",
            "incomplete_cwe_change_values",
            "unsupported_cwe_change",
        },
    }
    if "valid_empty_history_response" in combined.exclusion_reasons:
        layer_codes["cpe"].add("valid_empty_history_response")
        layer_codes["cwe"].add("valid_empty_history_response")

    cpe_events = tuple(
        event
        for event in parse_cpe_events(history)
        if event.cve_id == cve_id and event.created_at <= snapshot_at
    )
    cwe_events = tuple(
        event
        for event in parse_cwe_events(history)
        if event.cve_id == cve_id and event.created_at <= snapshot_at
    )
    exclusions = set(combined.exclusion_reasons)

    cpe_reasons = tuple(sorted(exclusions.intersection(layer_codes["cpe"])))
    cwe_reasons = tuple(sorted(exclusions.intersection(layer_codes["cwe"])))
    return {
        "cpe": LayerRelationships(
            cve_id,
            snapshot_at,
            "cpe",
            _replay_cpe(cpe_events),
            not cpe_reasons,
            cpe_reasons,
        ),
        "cwe": LayerRelationships(
            cve_id,
            snapshot_at,
            "cwe",
            _replay_cwe(cwe_events),
            not cwe_reasons,
            cwe_reasons,
        ),
    }


def _layer_graph(records: list[LayerRelationships]) -> nx.DiGraph:
    graph = nx.DiGraph()
    for record in sorted(records, key=lambda item: item.cve_id):
        if not record.eligible or not record.relationships:
            continue
        cve_node = f"cve:{record.cve_id}"
        graph.add_node(cve_node, node_type="cve", cve_id=record.cve_id)
        if record.layer == "cpe":
            for vendor, product in record.relationships:
                vendor_node = f"vendor:{vendor}"
                product_node = f"product:{vendor}:{product}"
                graph.add_node(vendor_node, node_type="vendor", name=vendor)
                graph.add_node(product_node, node_type="product", vendor=vendor, name=product)
                graph.add_edge(vendor_node, product_node, relation="offers")
                graph.add_edge(product_node, cve_node, relation="affected_by")
        else:
            for cwe_id in record.relationships:
                cwe_node = f"cwe:{cwe_id}"
                graph.add_node(cwe_node, node_type="cwe", cwe_id=cwe_id)
                graph.add_edge(cve_node, cwe_node, relation="has_weakness")
    return graph


def analyze_layer(
    records: list[LayerRelationships],
) -> tuple[pd.DataFrame, pd.DataFrame, dict[str, Any]]:
    """Return feature rows, one outcome per CVE, and layer-specific metadata."""
    if not records:
        raise ValueError("At least one reconstructed CVE is required")
    layer = records[0].layer
    if layer not in {"cpe", "cwe"} or any(record.layer != layer for record in records):
        raise ValueError("All records must belong to the same supported graph layer")

    graph = _layer_graph(records)
    if layer == "cpe":
        degree_column = "product_degree"
        degree_direction = "in_degree_centrality"
    else:
        degree_column = "cwe_degree"
        degree_direction = "out_degree_centrality"

    cve_nodes = sorted(
        (node for node, data in graph.nodes(data=True) if data.get("node_type") == "cve")
    )
    if cve_nodes:
        ordered_nodes = sorted(graph.nodes)
        pagerank = nx.pagerank(
            graph,
            nstart={node: 1 / graph.number_of_nodes() for node in ordered_nodes},
            max_iter=200,
            tol=1e-12,
        )
        if graph.number_of_nodes() > 1:
            in_degree = nx.in_degree_centrality(graph)
            out_degree = nx.out_degree_centrality(graph)
        else:
            in_degree = {node: 0.0 for node in graph}
            out_degree = {node: 0.0 for node in graph}
    else:
        pagerank, in_degree, out_degree = {}, {}, {}

    feature_rows: list[dict[str, Any]] = []
    feature_by_id: dict[str, dict[str, Any]] = {}
    for node in cve_nodes:
        record_id = node.removeprefix("cve:")
        record = next(item for item in records if item.cve_id == record_id)
        row = {
            "cve_id": record_id,
            degree_column: len(record.relationships),
            degree_direction: float((in_degree if layer == "cpe" else out_degree).get(node, 0.0)),
            "pagerank": float(pagerank[node]),
        }
        feature_rows.append(row)
        feature_by_id[record_id] = row

    outcome_rows = []
    for record in sorted(records, key=lambda item: item.cve_id):
        row = {
            "cve_id": record.cve_id,
            "layer": layer,
            "evidence_eligible": record.eligible,
            "relationship_count": len(record.relationships),
            "feature_status": "unavailable",
            "reason": ";".join(record.exclusion_reasons),
        }
        if record.eligible and record.cve_id in feature_by_id:
            row["feature_status"] = "available"
            row["reason"] = ""
            row.update(feature_by_id[record.cve_id])
        elif record.eligible:
            row["feature_status"] = "known_no_active_relationships"
            row["reason"] = "no_active_relationships_at_cutoff"
            row[degree_column] = pd.NA
            row[degree_direction] = pd.NA
            row["pagerank"] = pd.NA
        else:
            row[degree_column] = pd.NA
            row[degree_direction] = pd.NA
            row["pagerank"] = pd.NA
        outcome_rows.append(row)

    features = pd.DataFrame(
        feature_rows,
        columns=["cve_id", degree_column, degree_direction, "pagerank"],
    )
    outcomes = pd.DataFrame(outcome_rows)
    all_nodes = {
        node_type: sum(data.get("node_type") == node_type for _, data in graph.nodes(data=True))
        for node_type in ("vendor", "product", "cve", "cwe")
    }
    unpublished_records = [
        record for record in records if "not_published_at_cutoff" in record.exclusion_reasons
    ]
    published_records = [
        record for record in records if "not_published_at_cutoff" not in record.exclusion_reasons
    ]
    evidence_eligible_records = [record for record in published_records if record.eligible]
    evidence_ineligible_records = [record for record in published_records if not record.eligible]
    known_empty_records = [
        record for record in evidence_eligible_records if not record.relationships
    ]

    evidence_exclusion_reason_counts = Counter(
        reason for record in evidence_ineligible_records for reason in record.exclusion_reasons
    )
    publication_exclusion_reason_counts = Counter(
        reason for record in unpublished_records for reason in record.exclusion_reasons
    )
    feature_unavailability_reason_counts = Counter(
        reason for record in evidence_ineligible_records for reason in record.exclusion_reasons
    )
    feature_unavailability_reason_counts.update(
        {"no_active_relationships_at_cutoff": len(known_empty_records)}
    )

    def feature_status(record: LayerRelationships) -> str:
        if record.eligible and record.relationships:
            return "available"
        if record.eligible:
            return "known_no_active_relationships"
        return "unavailable"

    feature_status_counts = Counter(feature_status(record) for record in records)
    published_feature_status_counts = Counter(
        feature_status(record) for record in published_records
    )
    population_cves = len(records)
    published_by_cutoff_cves = len(published_records)
    not_published_at_cutoff_cves = len(unpublished_records)
    evidence_eligible_cves = len(evidence_eligible_records)
    evidence_ineligible_cves = len(evidence_ineligible_records)
    known_empty_relationship_cves = len(known_empty_records)
    feature_unavailable_published_cves = evidence_ineligible_cves + known_empty_relationship_cves
    feature_unavailable_population_cves = population_cves - len(features)

    metadata = {
        "metadata_schema_version": "2.0",
        "analysis_type": "exploratory_offline_probability_pilot_layer_comparison",
        "validated_production_output": False,
        "population_wide_coverage_estimate": False,
        "layer": layer,
        "snapshot_at": records[0].snapshot_at.isoformat(),
        "population_cves": population_cves,
        "published_by_cutoff_cves": published_by_cutoff_cves,
        "not_published_at_cutoff_cves": not_published_at_cutoff_cves,
        "evidence_eligible_cves": evidence_eligible_cves,
        "evidence_ineligible_cves": evidence_ineligible_cves,
        "known_empty_relationship_cves": known_empty_relationship_cves,
        "feature_rows": len(features),
        "feature_unavailable_published_cves": feature_unavailable_published_cves,
        "feature_unavailable_population_cves": feature_unavailable_population_cves,
        "feature_status_counts": dict(sorted(feature_status_counts.items())),
        "published_feature_status_counts": dict(sorted(published_feature_status_counts.items())),
        "evidence_exclusion_reason_counts": dict(sorted(evidence_exclusion_reason_counts.items())),
        "publication_exclusion_reason_counts": dict(
            sorted(publication_exclusion_reason_counts.items())
        ),
        "feature_unavailability_reason_counts": dict(
            sorted(feature_unavailability_reason_counts.items())
        ),
        "reason_counts_are_overlapping": True,
        "count_definitions": {
            "population_cves": "All CVEs supplied in the evaluation sample frame.",
            "published_by_cutoff_cves": "Population CVEs published at or before snapshot_at.",
            "not_published_at_cutoff_cves": "Population CVEs published after snapshot_at.",
            "evidence_eligible_cves": "Published CVEs with supported layer-specific evidence.",
            "evidence_ineligible_cves": (
                "Published CVEs with uncertain or unsupported layer evidence."
            ),
            "known_empty_relationship_cves": (
                "Evidence-eligible published CVEs with no active layer relationships; included "
                "in evidence_eligible_cves, not evidence_ineligible_cves."
            ),
            "feature_rows": "CVEs with active graph relationships and numeric feature rows.",
            "feature_unavailable_published_cves": (
                "Published CVEs without numeric feature rows, including evidence-ineligible "
                "and known-empty states."
            ),
            "feature_unavailable_population_cves": (
                "All population CVEs without numeric feature rows, including "
                "not-yet-published CVEs."
            ),
            "feature_unavailability_reason_counts": (
                "Per-reason counts among published CVEs with unavailable features: "
                "evidence-ineligible and known-empty records. Future-publication reasons "
                "are excluded and reported separately in publication_exclusion_reason_counts."
            ),
            "reason_counts": (
                "Counts are per reason and may overlap across CVEs; do not sum them to obtain "
                "unique-CVE totals."
            ),
        },
        # Compatibility aliases. evidence_ineligible_cves now has its corrected,
        # published-only meaning; this field preserves the old population-wide total.
        "eligible_cves": evidence_eligible_cves,
        "evidence_ineligible_population_legacy_cves": (population_cves - evidence_eligible_cves),
        "feature_unavailable_cves": feature_unavailable_population_cves,
        "known_no_active_relationships": known_empty_relationship_cves,
        "graph_nodes_by_type": all_nodes,
        "graph_edges": graph.number_of_edges(),
        "graph_scope": (
            "Only CVEs with supported, layer-specific relationship state and at least one "
            "active relationship at the cutoff; unknown or unsupported CVEs are omitted, "
            "not inserted as isolated nodes."
        ),
        "degree_feature": degree_column,
        "degree_centrality_feature": degree_direction,
        "pagerank_interpretation": (
            "Structural ranking within this layer's eligible pilot graph; not an "
            "exploitation probability. Values depend on the graph population."
        ),
    }
    return features, outcomes, metadata


def run_layer_comparison(
    history_dir: Path,
    sample_frame_path: Path,
    output_dir: Path,
    snapshot_at: datetime,
) -> dict[str, dict[str, Any]]:
    """Run both source-separated analyses from local history files only."""
    output_dir = Path(output_dir)
    if output_dir.exists():
        raise FileExistsError(f"Refusing to overwrite existing analysis directory: {output_dir}")
    if snapshot_at.tzinfo is None:
        raise ValueError("snapshot_at must be timezone-aware")
    snapshot_at = snapshot_at.astimezone(UTC)

    with Path(sample_frame_path).open("r", encoding="utf-8-sig", newline="") as file:
        sample_rows = list(csv.DictReader(file))
    if not sample_rows:
        raise ValueError("Sample frame contains no CVEs")

    records: dict[str, list[LayerRelationships]] = {"cpe": [], "cwe": []}
    for row in sample_rows:
        cve_id = row["cve_id"]
        published = datetime.fromisoformat(row["published"].replace("Z", "+00:00"))
        if published.tzinfo is None:
            raise ValueError(f"Publication timestamp must be timezone-aware for {cve_id}")
        if published.astimezone(UTC) > snapshot_at:
            for layer in records:
                records[layer].append(
                    LayerRelationships(
                        cve_id,
                        snapshot_at,
                        layer,
                        (),
                        False,
                        ("not_published_at_cutoff",),
                    )
                )
            continue
        history_path = Path(history_dir) / f"{cve_id}.json"
        with history_path.open("r", encoding="utf-8") as file:
            history = json.load(file)
        layers = reconstruct_relationship_layers(history, snapshot_at, cve_id)
        for layer in records:
            records[layer].append(layers[layer])

    output_dir.mkdir(parents=True)
    results: dict[str, dict[str, Any]] = {}
    for layer in ("cpe", "cwe"):
        features, outcomes, metadata = analyze_layer(records[layer])
        layer_dir = output_dir / layer
        layer_dir.mkdir()
        features.to_csv(layer_dir / "features.csv", index=False)
        outcomes.to_csv(layer_dir / "outcomes.csv", index=False)
        metadata["input_history_directory"] = str(Path(history_dir))
        metadata["sample_frame"] = str(Path(sample_frame_path))
        with (layer_dir / "metadata.json").open("w", encoding="utf-8", newline="\n") as file:
            json.dump(metadata, file, indent=2)
            file.write("\n")
        results[layer] = metadata

    report_lines = [
        "# Exploratory Component C layer comparison",
        "",
        "Offline analysis of the saved 130-CVE probability pilot histories.",
        "These are exploratory structural features, not validated production output,",
        "not a population-wide coverage estimate, and not exploitation probabilities.",
        "The strict combined-policy outputs were not changed.",
        "Reason counts are overlapping CVE counts and must not be summed as unique CVEs.",
        "",
    ]
    for layer in ("cpe", "cwe"):
        metadata = results[layer]
        report_lines.extend(
            [
                f"## {layer.upper()} layer",
                "",
                f"- Evaluation population CVEs: {metadata['population_cves']}",
                f"- Published by cutoff: {metadata['published_by_cutoff_cves']}",
                f"- Not yet published: {metadata['not_published_at_cutoff_cves']}",
                f"- Evidence-eligible among published: {metadata['evidence_eligible_cves']}",
                f"- Evidence-ineligible among published: {metadata['evidence_ineligible_cves']}",
                (
                    "- Known-empty states among published: "
                    f"{metadata['known_empty_relationship_cves']}"
                ),
                f"- Feature rows: {metadata['feature_rows']}",
                (
                    "- Feature-unavailable among published: "
                    f"{metadata['feature_unavailable_published_cves']}"
                ),
                f"- Feature status counts (population): {metadata['feature_status_counts']}",
                "- Evidence exclusion reasons (overlapping; evidence-ineligible published CVEs): "
                + (
                    ", ".join(
                        f"`{reason}`: {count}"
                        for reason, count in metadata["evidence_exclusion_reason_counts"].items()
                    )
                    or "none"
                ),
                "- Publication exclusion reasons: "
                + (
                    ", ".join(
                        f"`{reason}`: {count}"
                        for reason, count in metadata["publication_exclusion_reason_counts"].items()
                    )
                    or "none"
                ),
                "- Feature unavailability reasons (overlapping; published CVEs only): "
                + (
                    ", ".join(
                        f"`{reason}`: {count}"
                        for reason, count in metadata[
                            "feature_unavailability_reason_counts"
                        ].items()
                    )
                    or "none"
                ),
                f"- Graph nodes: {metadata['graph_nodes_by_type']}",
                f"- Graph edges: {metadata['graph_edges']}",
                "- See the layer's `outcomes.csv` for per-CVE status and explicit reasons.",
                "",
            ]
        )
    (output_dir / "report.md").write_text("\n".join(report_lines), encoding="utf-8")
    return results
