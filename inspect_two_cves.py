
"""Inspect two Component C CVEs and their raw NVD history."""

import gzip
import json
from pathlib import Path
from datetime import datetime, timezone

from vesper.components.c_graph.historical import (
    parse_cpe_events,
    parse_cwe_events,
    reconstruct_relationships,
)

TARGETS = {"CVE-2023-22512", "CVE-2023-22514"}
NVD_DIR = Path("data/raw/nvd")
HISTORY_DIR = Path("data/raw/nvd/history")
CUTOFF = datetime(2025, 1, 1, tzinfo=timezone.utc)


def main():
    # Locate the CVEs in the monthly NVD publication files.
    current_records = {}

    for path in sorted(NVD_DIR.glob("nvd_*.json.gz")):
        with gzip.open(path, "rt", encoding="utf-8") as file:
            document = json.load(file)

        for item in document.get("vulnerabilities", []):
            cve = item.get("cve", {})
            cve_id = cve.get("id")

            if cve_id in TARGETS:
                current_records[cve_id] = (path.name, cve)

        if TARGETS.issubset(current_records):
            break

    # Inspect each CVE and its historical changes.
    for cve_id in sorted(TARGETS):
        print(f"\n{'=' * 60}\n{cve_id}")

        if cve_id not in current_records:
            print("NVD record not found in the monthly files.")
            continue

        source_file, cve = current_records[cve_id]

        print("Source file:", source_file)
        print("Published:", cve.get("published"))
        print("Last modified:", cve.get("lastModified"))

        print("\nNVD weaknesses in the publication record:")
        for weakness in cve.get("weaknesses", []):
            for description in weakness.get("description", []):
                print(" ", description.get("value"))

        print("\nNVD vulnerable CPE criteria in the publication record:")
        for configuration in cve.get("configurations", []):
            stack = list(configuration.get("nodes", []))

            while stack:
                node = stack.pop()

                for match in node.get("cpeMatch", []):
                    if match.get("vulnerable"):
                        print(" ", match.get("criteria"))

                stack.extend(node.get("children", []))

        history_path = HISTORY_DIR / f"{cve_id}.json"

        if not history_path.exists():
            print("\nHistory file not found:", history_path)
            continue

        history = json.loads(
            history_path.read_text(encoding="utf-8")
        )

        # Print raw events so we can inspect the format used by NVD.
        print("\nRaw history event types and details:")

        raw_events = history.get("cveChanges", [])
        print("Total raw history events:", len(raw_events))

        for item in raw_events:
            change = item.get("change", {})
            created = change.get("created")

            print(f"\nCreated: {created}")

            for detail in change.get("details", []):
                print(
                    "  Type:", detail.get("type"),
                    "| Action:", detail.get("action"),
                    "| Old:", detail.get(
                        "oldValue",
                        detail.get("previousValue"),
                    ),
                    "| New:", detail.get("newValue"),
                )

        # Run the existing Component C reconstruction.
        cpe_events = parse_cpe_events(history)
        cwe_events = parse_cwe_events(history)
        reconstructed = reconstruct_relationships(history, CUTOFF)

        print("\nHistorical events on or before cutoff:")
        print(
            "CPE events:",
            sum(event.created_at <= CUTOFF for event in cpe_events),
        )
        print(
            "CWE events:",
            sum(event.created_at <= CUTOFF for event in cwe_events),
        )

        print("\nReconstructed products:", reconstructed.affected)
        print("Reconstructed CWEs:", reconstructed.cwe_ids)
        print("History available:", reconstructed.history_available)
        print("History complete:", reconstructed.history_complete)
        print("Warnings:", reconstructed.warnings)


if __name__ == "__main__":
    main()
