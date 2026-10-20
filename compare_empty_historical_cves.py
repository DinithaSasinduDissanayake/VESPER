
"""Diagnose empty Component C historical reconstructions.

Read-only diagnostic. Does not modify source files or downloaded datasets.
Reports event timing, usable NVD relationships, and missing evidence.
"""

import gzip
import json
import re
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path

from vesper.components.c_graph.historical import (
    parse_cpe_events,
    parse_cwe_events,
    reconstruct_relationships,
)

HISTORY_DIR = Path("data/raw/nvd/history")
NVD_DIR = Path("data/raw/nvd")
REPORT_PATH = Path("outputs/c_graph_empty_history_diagnostic.json")
CUTOFF = datetime(2025, 1, 1, tzinfo=timezone.utc)

INVALID_IDENTIFIERS = {"", "n/a", "na", "unknown", "*", "-"}


def parse_timestamp(value):
    """Parse an ISO timestamp into a timezone-aware UTC datetime."""
    if not value:
        return None

    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))

        if parsed.tzinfo is None:
            parsed = parsed.replace(tzinfo=timezone.utc)

        return parsed.astimezone(timezone.utc)
    except (TypeError, ValueError):
        return None


def find_empty_historical_cves():
    """Return history records with neither reconstructed relationship."""
    targets = {}

    for path in sorted(HISTORY_DIR.glob("CVE-*.json")):
        try:
            history = json.loads(path.read_text(encoding="utf-8"))
            relationships = reconstruct_relationships(history, CUTOFF)
        except (OSError, json.JSONDecodeError, ValueError) as error:
            print(f"Could not reconstruct {path.name}: {error}")
            continue

        if not relationships.affected and not relationships.cwe_ids:
            targets[relationships.cve_id] = {
                "history_path": str(path),
                "history": history,
                "relationships": relationships,
            }

    return targets


def extract_nvd_relationships(cve):
    """Extract usable vulnerable vendor/product pairs and CWE identifiers."""
    products = set()
    cwes = set()

    def visit_nodes(nodes):
        for node in nodes or []:
            for match in node.get("cpeMatch", []):
                if match.get("vulnerable") is not True:
                    continue

                criteria = match.get("criteria", "")
                parts = criteria.split(":")

                # A CPE 2.3 name has 13 colon-separated fields.
                if len(parts) != 13 or parts[:2] != ["cpe", "2.3"]:
                    continue

                vendor, product = parts[3].lower(), parts[4].lower()

                if (
                    parts[2] not in {"a", "h", "o"}
                    or vendor in INVALID_IDENTIFIERS
                    or product in INVALID_IDENTIFIERS
                ):
                    continue

                products.add((vendor, product))

            visit_nodes(node.get("children", []))

    for configuration in cve.get("configurations", []):
        visit_nodes(configuration.get("nodes", []))

    for weakness in cve.get("weaknesses", []):
        for description in weakness.get("description", []):
            value = description.get("value", "")

            if re.fullmatch(r"CWE-\d+", value, flags=re.IGNORECASE):
                cwes.add(value.upper())

    return sorted(products), sorted(cwes)


def scan_nvd_records(target_ids):
    """Find matching records, retaining source and modification timestamps."""
    records = {cve_id: [] for cve_id in target_ids}
    unreadable_files = []
    files_scanned = 0

    for path in sorted(NVD_DIR.glob("nvd_*.json.gz")):
        files_scanned += 1

        try:
            with gzip.open(path, "rt", encoding="utf-8") as file:
                document = json.load(file)
        except (OSError, EOFError, json.JSONDecodeError) as error:
            unreadable_files.append(
                {"file": path.name, "error": str(error)}
            )
            continue

        for item in document.get("vulnerabilities", []):
            cve = item.get("cve", {})
            cve_id = cve.get("id")

            if cve_id not in target_ids:
                continue

            products, cwes = extract_nvd_relationships(cve)

            records[cve_id].append(
                {
                    "source_file": path.name,
                    "published": cve.get("published"),
                    "last_modified": cve.get("lastModified"),
                    "products": [
                        {"vendor": vendor, "product": product}
                        for vendor, product in products
                    ],
                    "cwes": cwes,
                    "usable_product_count": len(products),
                    "usable_cwe_count": len(cwes),
                }
            )

    return records, files_scanned, unreadable_files


def summarize_history(history):
    """Classify interpretable CPE/CWE events by the cutoff."""
    cpe_events = parse_cpe_events(history)
    cwe_events = parse_cwe_events(history)

    def event_counts(events):
        before = sum(event.created_at <= CUTOFF for event in events)
        after = sum(event.created_at > CUTOFF for event in events)

        return {
            "total_interpretable": len(events),
            "on_or_before_cutoff": before,
            "after_cutoff": after,
        }

    raw_events = history.get("cveChanges", [])
    raw_cpe_dates = []
    raw_cwe_dates = []
    malformed_relevant_dates = 0

    # Also inspect raw event types. This detects relevant event types
    # that the current parser may not have interpreted.
    for item in raw_events:
        change = item.get("change", {})
        created = parse_timestamp(change.get("created"))

        for detail in change.get("details", []):
            detail_type = detail.get("type", "").strip().lower()

            if detail_type not in {"cpe configuration", "cwe"}:
                continue

            if created is None:
                malformed_relevant_dates += 1
            elif detail_type == "cpe configuration":
                raw_cpe_dates.append(created)
            else:
                raw_cwe_dates.append(created)

    return {
        "raw_history_event_count": len(raw_events),
        "interpretable_cpe_events": event_counts(cpe_events),
        "interpretable_cwe_events": event_counts(cwe_events),
        "raw_cpe_detail_count": len(raw_cpe_dates),
        "raw_cwe_detail_count": len(raw_cwe_dates),
        "raw_cpe_details_on_or_before_cutoff": sum(
            value <= CUTOFF for value in raw_cpe_dates
        ),
        "raw_cwe_details_on_or_before_cutoff": sum(
            value <= CUTOFF for value in raw_cwe_dates
        ),
        "raw_cpe_details_after_cutoff": sum(
            value > CUTOFF for value in raw_cpe_dates
        ),
        "raw_cwe_details_after_cutoff": sum(
            value > CUTOFF for value in raw_cwe_dates
        ),
        "relevant_details_with_unparseable_dates": malformed_relevant_dates,
    }


def classify_case(history_summary, nvd_records):
    """Assign a diagnostic category without claiming historical truth."""
    raw_before = (
        history_summary["raw_cpe_details_on_or_before_cutoff"]
        + history_summary["raw_cwe_details_on_or_before_cutoff"]
    )
    raw_after = (
        history_summary["raw_cpe_details_after_cutoff"]
        + history_summary["raw_cwe_details_after_cutoff"]
    )
    interpreted_before = (
        history_summary["interpretable_cpe_events"]["on_or_before_cutoff"]
        + history_summary["interpretable_cwe_events"]["on_or_before_cutoff"]
    )

    if interpreted_before:
        return "interpretable_events_before_cutoff_but_empty_result"

    if raw_before:
        return "raw_relationship_events_before_cutoff_not_interpreted"

    if raw_after:
        return "relationship_details_only_after_cutoff"

    if history_summary["relevant_details_with_unparseable_dates"]:
        return "relationship_events_with_unparseable_dates"

    if not nvd_records:
        return "no_matching_nvd_record"

    has_current_products = any(
        record["usable_product_count"] > 0 for record in nvd_records
    )
    has_current_cwes = any(
        record["usable_cwe_count"] > 0 for record in nvd_records
    )

    if has_current_products or has_current_cwes:
        return "nvd_relationships_exist_but_history_has_no_relevant_events"

    return "no_usable_relationships_found_in_scanned_records"


def main():
    targets = find_empty_historical_cves()
    target_ids = set(targets)

    print(f"Cutoff: {CUTOFF.isoformat()}")
    print(f"CVEs with neither reconstructed relationship: {len(target_ids)}")

    nvd_records, files_scanned, unreadable_files = scan_nvd_records(
        target_ids
    )

    summary = Counter()
    report_cases = []

    for cve_id in sorted(target_ids):
        target = targets[cve_id]
        history = target["history"]

        history_summary = summarize_history(history)
        records = nvd_records.get(cve_id, [])

        category = classify_case(history_summary, records)
        summary[category] += 1

        case = {
            "cve_id": cve_id,
            "classification": category,
            "history_file": target["history_path"],
            "history_summary": history_summary,
            "nvd_records_found": len(records),
            "nvd_records": records,
            "reconstruction_warnings": list(
                target["relationships"].warnings
            ),
        }
        report_cases.append(case)

        print(f"\n{cve_id}")
        print("  Classification:", category)
        print("  Matching NVD monthly records:", len(records))

        print(
            "  Raw CPE details before/at cutoff:",
            history_summary["raw_cpe_details_on_or_before_cutoff"],
        )
        print(
            "  Raw CPE details after cutoff:",
            history_summary["raw_cpe_details_after_cutoff"],
        )
        print(
            "  Raw CWE details before/at cutoff:",
            history_summary["raw_cwe_details_on_or_before_cutoff"],
        )
        print(
            "  Raw CWE details after cutoff:",
            history_summary["raw_cwe_details_after_cutoff"],
        )

        if records:
            # Monthly NVD files are not necessarily successive snapshots.
            # Display all matches instead of assuming the last file is latest.
            for record in records:
                print("  Source:", record["source_file"])
                print("    Published:", record["published"])
                print("    Last modified:", record["last_modified"])
                print(
                    "    Usable products:",
                    record["usable_product_count"],
                )
                print("    Usable CWEs:", record["usable_cwe_count"])

    report = {
        "cutoff": CUTOFF.isoformat(),
        "history_directory": str(HISTORY_DIR),
        "nvd_directory": str(NVD_DIR),
        "empty_reconstruction_count": len(target_ids),
        "nvd_monthly_files_scanned": files_scanned,
        "unreadable_nvd_files": unreadable_files,
        "classification_counts": dict(sorted(summary.items())),
        "cases": report_cases,
        "interpretation_note": (
            "NVD publication records describe their recorded state and are "
            "not proof of the state at the historical cutoff. Raw history "
            "events after the cutoff must not be used to build that cutoff's "
            "graph. Missing events do not prove that relationships did not "
            "exist."
        ),
    }

    REPORT_PATH.parent.mkdir(parents=True, exist_ok=True)
    REPORT_PATH.write_text(
        json.dumps(report, indent=2, ensure_ascii=False),
        encoding="utf-8",
    )

    print("\nClassification summary:")
    for category, count in sorted(summary.items()):
        print(f"  {category}: {count}")

    print(f"\nNVD monthly files scanned: {files_scanned}")
    print(f"Unreadable NVD files: {len(unreadable_files)}")
    print(f"Diagnostic report saved to: {REPORT_PATH}")


if __name__ == "__main__":
    main()
