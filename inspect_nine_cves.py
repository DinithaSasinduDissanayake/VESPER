
"""Inspect NVD status and relationship fields for nine Component C CVEs."""

import gzip
import json
from pathlib import Path

TARGETS = {
    "CVE-2022-29409",
    "CVE-2022-43375",
    "CVE-2022-45791",
    "CVE-2022-45795",
    "CVE-2023-22502",
    "CVE-2023-22507",
    "CVE-2023-22510",
    "CVE-2023-22520",
    "CVE-2023-22525",
}

NVD_DIR = Path("data/raw/nvd")


def main():
    found = {}

    for path in sorted(NVD_DIR.glob("nvd_*.json.gz")):
        try:
            with gzip.open(path, "rt", encoding="utf-8") as file:
                document = json.load(file)
        except (OSError, EOFError, json.JSONDecodeError) as error:
            print(f"Could not read {path.name}: {error}")
            continue

        for item in document.get("vulnerabilities", []):
            cve = item.get("cve", {})
            cve_id = cve.get("id")

            if cve_id in TARGETS:
                found.setdefault(cve_id, {
                    "source_file": path.name,
                    "cve": cve,
                })

        if TARGETS.issubset(found):
            break

    for cve_id in sorted(TARGETS):
        print(f"\n{'=' * 60}\n{cve_id}")

        entry = found.get(cve_id)
        if entry is None:
            print("No matching record found.")
            continue

        cve = entry["cve"]
        print("Source file:", entry["source_file"])
        print("Published:", cve.get("published"))
        print("Last modified:", cve.get("lastModified"))
        print("NVD vulnStatus:", cve.get("vulnStatus"))

        descriptions = cve.get("descriptions", [])
        print("\nDescriptions:")
        for description in descriptions:
            print(
                " ",
                description.get("lang"),
                ":",
                description.get("value"),
            )

        print("\nWeakness entries:")
        for weakness in cve.get("weaknesses", []):
            values = [
                description.get("value")
                for description in weakness.get("description", [])
            ]
            print(" ", values)

        print("\nConfiguration entries:")
        for configuration in cve.get("configurations", []):
            print("  Nodes:", len(configuration.get("nodes", [])))

            for node in configuration.get("nodes", []):
                print("   Node operator:", node.get("operator"))
                print("   CPE matches:", len(node.get("cpeMatch", [])))

                for match in node.get("cpeMatch", []):
                    print(
                        "    ",
                        match.get("criteria"),
                        "| vulnerable:",
                        match.get("vulnerable"),
                    )

        print("\nReferences:")
        for reference in cve.get("references", []):
            print(" ", reference.get("url"))


if __name__ == "__main__":
    main()
