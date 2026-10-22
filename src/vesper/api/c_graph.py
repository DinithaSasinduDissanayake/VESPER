"""Read-only current Component C artifact lookup; no graph or score computation."""

from __future__ import annotations

import csv
import hashlib
import json
import math
import os
import re
import sqlite3
import tempfile
from collections import Counter
from contextlib import closing
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from threading import RLock
from typing import Annotated, Literal

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel, Field, StringConstraints

from vesper.config import load_settings

router = APIRouter(prefix="/api/c-graph", tags=["Structural relationships"])
CveId = Annotated[str, StringConstraints(pattern=r"^CVE-[0-9]{4}-[0-9]{4,}$")]
Status = Literal["available", "abstained", "not_eligible", "already_exploited"]
EvidenceStatus = Literal["supported", "unavailable", "not_evaluated"]
ADAPTER_VERSION = "c_graph-pagerank-percentile-structural-0.2"
PROVIDER_VERSION = "c_graph-pagerank-structural-0.1"
# A single validated CVE may have a large JSON relationship field.
csv.field_size_limit(max(csv.field_size_limit(), 16 * 1024 * 1024))
IDENTITY = ("snapshot_id", "graph_scope_id", "reference_timestamp")
ANALYSIS_COLUMNS = {
    "cve_id",
    *IDENTITY,
    "degree",
    "pagerank",
    "P_pagerank",
    "P_cvss",
    "pagerank_cvss_disagreement",
    "analysis_status",
    "analysis_reason",
}


class ProductRelationship(BaseModel):
    vendor: str
    product: str


class StructuralProvenance(BaseModel):
    snapshot_id: str
    graph_scope_id: str
    feature_schema_version: str
    provider_model_version: str
    source_record_published_at: str
    source_record_last_modified_at: str
    source_nvd_file: str
    feature_provenance: str
    provider_sha256: str
    scores_sha256: str
    analysis_sha256: str | None


class StructuralResponse(BaseModel):
    cve_id: str
    structural_score: float | None = Field(ge=0, le=1)
    score_kind: Literal["ranking_score"]
    score_status: Status
    score_reason: str | None
    raw_pagerank: float | None = Field(ge=0, le=1)
    degree: int | None = Field(ge=0)
    pagerank_comparison_percentile: float | None = Field(ge=0, le=1)
    cvss_percentile: float | None = Field(ge=0, le=1)
    pagerank_cvss_disagreement: float | None = Field(ge=-1, le=1)
    comparison_status: str
    comparison_reason: str | None
    scoring_population: int
    comparison_population: int | None
    vendor_product_relationships: list[ProductRelationship]
    cwe_ids: list[str]
    cpe_evidence_status: EvidenceStatus
    cpe_evidence_reason: str | None
    cwe_evidence_status: EvidenceStatus
    cwe_evidence_reason: str | None
    snapshot_date: str
    reference_time: str
    model_version: str
    provenance: StructuralProvenance


def _time(value: str) -> datetime:
    if not isinstance(value, str):
        raise ValueError("Artifact timestamps must be strings")
    result = datetime.fromisoformat(value.replace("Z", "+00:00"))
    if result.tzinfo is None:
        raise ValueError("Artifact timestamps must include a timezone")
    return result.astimezone(UTC)


def _number(value: str, *, minimum: float = 0, maximum: float = 1) -> float | None:
    if not value.strip():
        return None
    result = float(value)
    if not math.isfinite(result) or not minimum <= result <= maximum:
        raise ValueError("Artifact contains an invalid numeric value")
    return result


def _digest(path: Path) -> str:
    with path.open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def _paths() -> tuple[Path, Path, Path | None]:
    settings = load_settings()

    def configured(name: str, default: Path | None) -> Path | None:
        value = os.getenv(name, "").strip()
        path = Path(value) if value else default
        if path is None:
            return None
        return (path if path.is_absolute() else settings.project_root / path).resolve()

    provider = configured(
        "VESPER_C_FEATURE_PROVIDER_CSV",
        settings.outputs / "c_graph_feature_provider_2026-10-17_run2/c_graph_feature_provider.csv",
    )
    scores = configured(
        "VESPER_C_SCORES_CSV",
        settings.outputs
        / "c_graph_structural_scalar_disagreement_2026-10-17_run1/c_graph_scores.csv",
    )
    return provider, scores, configured("VESPER_C_DISAGREEMENT_CSV", None)


def _signature(paths: tuple[Path, ...]) -> tuple:
    return tuple((str(p), p.stat().st_size, p.stat().st_mtime_ns) for p in paths)


@dataclass
class ArtifactIndex:
    directory: tempfile.TemporaryDirectory
    database: Path
    provider_meta: dict
    score_meta: dict
    hashes: dict[str, str]
    comparison_population: int | None
    signature: tuple

    def row(self, table: str, cve_id: str) -> dict | None:
        # table is an internal constant; request identifiers remain bound parameters.
        with closing(sqlite3.connect(f"{self.database.as_uri()}?mode=ro", uri=True)) as connection:
            found = connection.execute(
                f"SELECT payload FROM {table} WHERE cve_id = ?", (cve_id,)
            ).fetchone()
        return json.loads(found[0]) if found else None


_lock = RLock()
_index: ArtifactIndex | None = None


def _build_index(
    provider: Path, scores: Path, analysis: Path | None, signature: tuple
) -> ArtifactIndex:
    provider_meta = json.loads(provider.with_suffix(".metadata.json").read_text(encoding="utf-8"))
    score_meta = json.loads(Path(str(scores) + ".metadata.json").read_text(encoding="utf-8"))
    if not isinstance(provider_meta, dict) or not isinstance(score_meta, dict):
        raise ValueError("Artifact metadata must contain JSON objects")
    for key in IDENTITY:
        if (
            not isinstance(provider_meta.get(key), str)
            or not provider_meta[key]
            or provider_meta[key] != score_meta.get(key)
        ):
            raise ValueError(f"Provider and score metadata disagree on {key}")
    if provider_meta.get("historical_reconstruction") != "not_performed":
        raise ValueError("Only the validated current-snapshot provider is supported")
    if score_meta.get("model_version") != [ADAPTER_VERSION]:
        raise ValueError("Expected the current PageRank percentile adapter")
    if provider_meta.get("feature_schema_version") != "1.0.0":
        raise ValueError("Unsupported provider schema version")
    hashes = {"provider": _digest(provider), "scores": _digest(scores)}
    if hashes["provider"] != provider_meta.get("output_sha256"):
        raise ValueError("Provider checksum does not match its metadata")
    if hashes["scores"] != score_meta.get("output_sha256"):
        raise ValueError("Score checksum does not match its metadata")
    if hashes["provider"] != score_meta.get("source_provider_sha256"):
        raise ValueError("Score metadata identifies another provider")
    if analysis:
        hashes["analysis"] = _digest(analysis)

    directory = tempfile.TemporaryDirectory(prefix="vesper-c-graph-")
    database = Path(directory.name) / "lookup.sqlite3"
    counts: dict[str, Counter] = {}
    try:
        with closing(sqlite3.connect(database)) as connection, connection:
            connection.execute("PRAGMA cache_size = -8192")
            for table, path in (("provider", provider), ("scores", scores), ("analysis", analysis)):
                connection.execute(f"CREATE TABLE {table} (cve_id TEXT PRIMARY KEY, payload TEXT)")
                counts[table] = Counter()
                if path is None:
                    continue
                with path.open(encoding="utf-8-sig", newline="") as stream:
                    reader = csv.DictReader(stream)
                    required = (
                        ANALYSIS_COLUMNS
                        if table == "analysis"
                        else {
                            "cve_id",
                            "component",
                            "score",
                            "score_kind",
                            "status",
                            "reason",
                            "model_version",
                            "decision_time",
                            "snapshot_date",
                            "horizon_days",
                            "trained_through",
                        }
                    )
                    if table == "provider":
                        required = required | {
                            *IDENTITY,
                            "pagerank",
                            "pagerank_status",
                            "feature_schema_version",
                            "vendor_product_evidence_json",
                            "cwe_ids_json",
                            "cpe_evidence_status",
                            "cpe_evidence_reason",
                            "cwe_evidence_status",
                            "cwe_evidence_reason",
                            "source_record_published_at",
                            "source_record_last_modified_at",
                            "source_nvd_file",
                            "feature_provenance",
                        }
                    if not required.issubset(reader.fieldnames or []):
                        raise ValueError(f"{table} CSV is missing required columns")
                    for row in reader:
                        if None in row or any(value is None for value in row.values()):
                            raise ValueError(f"Malformed {table} CSV row")
                        cve_id = row["cve_id"]
                        if not re.fullmatch(r"CVE-[0-9]{4}-[0-9]{4,}", cve_id):
                            raise ValueError(f"Invalid CVE ID in {table}")
                        if table != "scores":
                            for key in IDENTITY:
                                if row[key] != provider_meta[key]:
                                    raise ValueError(f"{table} row disagrees on {key}")
                        if table != "analysis":
                            _validate_score(row, provider_meta, table)
                        counts[table][row.get("analysis_status", row.get("status"))] += 1
                        # Keep only the analysis fields used by the API, never outcome annotations.
                        payload = (
                            {key: row[key] for key in ANALYSIS_COLUMNS}
                            if table == "analysis"
                            else row
                        )
                        connection.execute(
                            f"INSERT INTO {table} VALUES (?, ?)",
                            (cve_id, json.dumps(payload, separators=(",", ":"))),
                        )
                connection.commit()
            expected = provider_meta["counts"]["population_cves"]
            if (
                sum(counts["provider"].values()) != expected
                or sum(counts["scores"].values()) != expected
            ):
                raise ValueError("Artifact row counts disagree with the declared population")
            if counts["provider"] != Counter(provider_meta["counts"]["shared_score_status_counts"]):
                raise ValueError("Provider status counts disagree with metadata")
            if (
                counts["scores"] != Counter(score_meta["status_counts"])
                or counts["scores"] != counts["provider"]
            ):
                raise ValueError("Score status counts disagree with provider/metadata")
            if (
                score_meta["rows"] != expected
                or score_meta["percentile_population"] != counts["scores"]["available"]
            ):
                raise ValueError("Score population metadata is inconsistent")
            for table in ("scores", "analysis") if analysis else ("scores",):
                if (
                    connection.execute(
                        f"SELECT cve_id FROM provider EXCEPT SELECT cve_id FROM {table}"
                    ).fetchone()
                    or connection.execute(
                        f"SELECT cve_id FROM {table} EXCEPT SELECT cve_id FROM provider"
                    ).fetchone()
                ):
                    raise ValueError(f"{table} CVE population differs from provider")
        return ArtifactIndex(
            directory,
            database,
            provider_meta,
            score_meta,
            hashes,
            counts["analysis"]["available"] if analysis else None,
            signature,
        )
    except BaseException:
        directory.cleanup()
        raise


def _validate_score(row: dict, meta: dict, table: str) -> None:
    if row["component"] != "c_graph" or row["score_kind"] != "ranking_score":
        raise ValueError("Unexpected score component or kind")
    version = PROVIDER_VERSION if table == "provider" else ADAPTER_VERSION
    if row["model_version"] != version or row["trained_through"].strip():
        raise ValueError("Unexpected current structural model/training metadata")
    reference = _time(meta["reference_timestamp"])
    if (
        _time(row["decision_time"]) != reference
        or row["snapshot_date"] != reference.date().isoformat()
    ):
        raise ValueError("Score time differs from the current snapshot")
    if int(row["horizon_days"]) <= 0:
        raise ValueError("Invalid shared horizon metadata")
    value = _number(row["score"])
    if row["status"] == "available":
        if value is None:
            raise ValueError("Available score must be numeric")
    elif (
        row["status"] not in {"abstained", "not_eligible", "already_exploited"}
        or value is not None
        or not row["reason"].strip()
    ):
        raise ValueError("Unavailable score must be blank with an explicit reason")


def _get_index() -> ArtifactIndex:
    global _index
    provider, scores, analysis = _paths()
    paths = (
        provider,
        provider.with_suffix(".metadata.json"),
        scores,
        Path(str(scores) + ".metadata.json"),
    )
    if analysis:
        paths += (analysis,)
    try:
        signature = _signature(paths)
    except OSError as error:
        raise HTTPException(
            status_code=503,
            detail="Component C artifacts unavailable. Configure VESPER_C_FEATURE_PROVIDER_CSV, "
            "VESPER_C_SCORES_CSV and their metadata sidecars; disagreement CSV is optional.",
        ) from error
    with _lock:
        if _index is None or _index.signature != signature:
            try:
                candidate = _build_index(provider, scores, analysis, signature)
                if _signature(paths) != signature:
                    candidate.directory.cleanup()
                    raise ValueError("Artifacts changed while building the lookup index")
                previous, _index = _index, candidate
                if previous:
                    previous.directory.cleanup()
            except (OSError, ValueError, KeyError, TypeError, csv.Error, sqlite3.Error) as error:
                raise HTTPException(
                    status_code=422, detail=f"Invalid Component C artifacts: {error}"
                ) from error
        return _index


def _evidence(row: dict, layer: str) -> tuple[list, str, str | None]:
    status = row[f"{layer}_evidence_status"]
    reason = row[f"{layer}_evidence_reason"].strip() or None
    raw = row["vendor_product_evidence_json" if layer == "cpe" else "cwe_ids_json"]
    if status not in {"supported", "unavailable", "not_evaluated"}:
        raise ValueError("Unknown relationship evidence status")
    if status != "supported":
        if raw.strip() or reason is None:
            raise ValueError("Unavailable evidence must be blank with an explicit reason")
        return [], status, reason
    values = json.loads(raw)
    if not isinstance(values, list) or not values:
        raise ValueError("Supported evidence must contain a non-empty JSON list")
    if layer == "cpe":
        if any(
            not isinstance(v, list)
            or len(v) != 2
            or any(not isinstance(p, str) or not p.strip() for p in v)
            for v in values
        ):
            raise ValueError("Invalid vendor/product relationship")
        return sorted({tuple(part.strip() for part in value) for value in values}), status, reason
    if any(not isinstance(v, str) or not re.fullmatch(r"CWE-[0-9]+", v) for v in values):
        raise ValueError("Invalid CWE identifier")
    return sorted(set(values)), status, reason


def _response(index: ArtifactIndex, cve_id: str) -> StructuralResponse:
    provider = index.row("provider", cve_id)
    if provider is None:
        raise HTTPException(
            status_code=404, detail="CVE is not in the configured Component C population."
        )
    score = index.row("scores", cve_id)
    analysis = index.row("analysis", cve_id)
    if score["status"] != provider["status"] or score["horizon_days"] != provider["horizon_days"]:
        raise ValueError("Provider and adapter row states disagree")
    raw = _number(provider["pagerank"])
    if raw != _number(provider["score"]) or provider["pagerank_status"] != provider["status"]:
        raise ValueError("Provider raw PageRank and provider score/status disagree")
    if (raw is not None) != (score["status"] == "available"):
        raise ValueError("PageRank availability disagrees with score status")
    products, cpe_status, cpe_reason = _evidence(provider, "cpe")
    cwes, cwe_status, cwe_reason = _evidence(provider, "cwe")
    degree = comparison = cvss = difference = None
    comparison_status, comparison_reason = "unavailable", "Disagreement analysis is not configured."
    if analysis:
        if _number(analysis["pagerank"]) != raw:
            raise ValueError("Analysis raw PageRank differs from provider")
        degree_value = _number(analysis["degree"], maximum=float("inf"))
        if degree_value is not None:
            if not degree_value.is_integer():
                raise ValueError("Degree must be a raw integer count")
            degree = int(degree_value)
        comparison_status = analysis["analysis_status"]
        comparison_reason = analysis["analysis_reason"].strip() or None
        if comparison_status not in {
            "available",
            "unavailable",
            "abstained",
            "not_eligible",
            "already_exploited",
        }:
            raise ValueError("Unknown comparison availability status")
        comparison = _number(analysis["P_pagerank"])
        cvss = _number(analysis["P_cvss"])
        difference = _number(analysis["pagerank_cvss_disagreement"], minimum=-1)
        if comparison_status == "available":
            if None in (comparison, cvss, difference) or not math.isclose(
                comparison - cvss, difference, abs_tol=1e-12
            ):
                raise ValueError("Incomplete or inconsistent comparison values")
            if (
                score["status"] != "available"
                or cpe_status != "supported"
                or cwe_status != "supported"
            ):
                raise ValueError("Comparison requires available score and both evidence layers")
        elif (
            any(value is not None for value in (comparison, cvss, difference))
            or not comparison_reason
        ):
            raise ValueError("Unavailable comparison must be blank with a reason")
    if score["status"] != "available" and degree is not None:
        raise ValueError("Unavailable graph score cannot claim an observed Degree")
    return StructuralResponse(
        cve_id=cve_id,
        structural_score=_number(score["score"]),
        score_kind="ranking_score",
        score_status=score["status"],
        score_reason=score["reason"].strip() or None,
        raw_pagerank=raw,
        degree=degree,
        pagerank_comparison_percentile=comparison,
        cvss_percentile=cvss,
        pagerank_cvss_disagreement=difference,
        comparison_status=comparison_status,
        comparison_reason=comparison_reason,
        scoring_population=index.score_meta["percentile_population"],
        comparison_population=index.comparison_population,
        vendor_product_relationships=[
            ProductRelationship(vendor=v, product=p) for v, p in products
        ],
        cwe_ids=cwes,
        cpe_evidence_status=cpe_status,
        cpe_evidence_reason=cpe_reason,
        cwe_evidence_status=cwe_status,
        cwe_evidence_reason=cwe_reason,
        snapshot_date=score["snapshot_date"],
        reference_time=index.provider_meta["reference_timestamp"],
        model_version=score["model_version"],
        provenance=StructuralProvenance(
            snapshot_id=index.provider_meta["snapshot_id"],
            graph_scope_id=index.provider_meta["graph_scope_id"],
            feature_schema_version=provider["feature_schema_version"],
            provider_model_version=provider["model_version"],
            source_record_published_at=provider["source_record_published_at"],
            source_record_last_modified_at=provider["source_record_last_modified_at"],
            source_nvd_file=provider["source_nvd_file"],
            feature_provenance=provider["feature_provenance"],
            provider_sha256=index.hashes["provider"],
            scores_sha256=index.hashes["scores"],
            analysis_sha256=index.hashes.get("analysis"),
        ),
    )


@router.get("/cves/{cve_id}", response_model=StructuralResponse)
def get_component_c_details(cve_id: CveId) -> StructuralResponse:
    """Serve one CVE from compatible frozen current-snapshot artifacts."""
    # The lock also prevents replacement/cleanup while another request reads the index.
    with _lock:
        index = _get_index()
        try:
            return _response(index, cve_id)
        except (ValueError, KeyError, TypeError, sqlite3.Error) as error:
            raise HTTPException(
                status_code=422, detail=f"Invalid Component C record: {error}"
            ) from error
