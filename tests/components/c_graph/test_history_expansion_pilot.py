"""Offline safety tests for the incremental history expansion pilot."""

import json
import subprocess
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[3]))
from scripts import run_c_graph_history_expansion_pilot as pilot


def test_request_reservations_survive_resume_and_enforce_global_ceiling(tmp_path):
    ledger = tmp_path / "requests.sqlite3"
    budget = pilot.DurableRequestBudget(ledger, maximum=2)
    budget.context = "CVE-2024-10001"
    budget.reserve()
    budget.context = "CVE-2024-10002 retry"
    budget.reserve()
    assert budget.used == 2
    budget.close()

    resumed = pilot.DurableRequestBudget(ledger, maximum=2)
    assert resumed.used == 2
    with pytest.raises(pilot.downloader.RequestBudgetExceeded):
        resumed.reserve()
    resumed.close()


def test_resumed_request_budget_cannot_be_increased(tmp_path):
    ledger = tmp_path / "requests.sqlite3"
    budget = pilot.DurableRequestBudget(ledger, maximum=2)
    budget.reserve()
    budget.close()

    with pytest.raises(ValueError, match="cannot change"):
        pilot.DurableRequestBudget(ledger, maximum=3)


def test_request_ceiling_defaults_to_260_and_explicit_20_persists_on_resume(tmp_path):
    default = pilot.DurableRequestBudget(tmp_path / "default.sqlite3")
    assert default.maximum == pilot.MAX_REQUESTS == 260
    default.close()

    ledger = tmp_path / "twenty.sqlite3"
    configured = pilot.DurableRequestBudget(ledger, maximum=20)
    assert configured.maximum == 20
    configured.close()
    resumed = pilot.DurableRequestBudget(ledger, maximum=None)
    assert resumed.maximum == 20
    resumed.close()
    with pytest.raises(ValueError, match="cannot change"):
        pilot.DurableRequestBudget(ledger, maximum=260)


def test_durable_ceiling_counts_retry_and_pagination_reservations(tmp_path, monkeypatch):
    import io
    import urllib.error
    from email.message import Message

    ledger = tmp_path / "requests.sqlite3"
    budget = pilot.DurableRequestBudget(ledger, maximum=3)
    monkeypatch.setattr(pilot.downloader, "HISTORY_PAGE_SIZE", 1)
    monkeypatch.setattr(pilot.downloader.time, "sleep", lambda *_args: None)
    calls = []

    class Response(io.BytesIO):
        def __enter__(self):
            return self

        def __exit__(self, *_args):
            self.close()

    def fake_urlopen(request, **_kwargs):
        calls.append(request.full_url)
        if len(calls) == 1:
            headers = Message()
            raise urllib.error.HTTPError(request.full_url, 429, "busy", headers, None)
        start = 0 if len(calls) == 2 else 1
        payload = {
            "resultsPerPage": 1,
            "startIndex": start,
            "totalResults": 2,
            "format": "NVD_CVEHistory",
            "version": "2.0",
            "timestamp": "2026-10-15T00:00:00.000",
            "cveChanges": [
                {
                    "change": {
                        "cveId": "CVE-2024-12345",
                        "cveChangeId": f"event-{start}",
                        "created": "2024-01-01T00:00:00.000",
                        "details": [],
                    }
                }
            ],
        }
        return Response(json.dumps(payload).encode())

    monkeypatch.setattr(pilot.downloader.urllib.request, "urlopen", fake_urlopen)
    pilot.downloader.fetch_history("CVE-2024-12345", None, max_attempts=2, request_budget=budget)
    assert len(calls) == budget.used == 3  # retry + first page + second page
    with pytest.raises(pilot.downloader.RequestBudgetExceeded):
        budget.reserve()
    budget.close()


def test_pilot_request_budget_serializes_concurrent_processes(tmp_path):
    ledger = tmp_path / "requests.sqlite3"
    initializer = pilot.DurableRequestBudget(ledger, maximum=1)
    initializer.close()
    project_root = Path(__file__).resolve().parents[3]
    scripts_dir = project_root / "scripts"
    script = (
        "import sys\n"
        "from pathlib import Path\n"
        "sys.path.insert(0, sys.argv[2])\n"
        "sys.path.insert(0, sys.argv[3])\n"
        "import run_c_graph_history_expansion_pilot as p\n"
        "b = p.DurableRequestBudget(Path(sys.argv[1]), maximum=1)\n"
        "try:\n"
        "    b.reserve()\n"
        "    print('reserved')\n"
        "except p.downloader.RequestBudgetExceeded:\n"
        "    print('exhausted')\n"
        "finally:\n"
        "    b.close()\n"
    )
    command = [
        sys.executable,
        "-c",
        script,
        str(ledger),
        str(scripts_dir),
        str(project_root / "src"),
    ]
    first = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    second = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    first_out, first_err = first.communicate(timeout=20)
    second_out, second_err = second.communicate(timeout=20)
    assert first.returncode == second.returncode == 0, first_err + second_err
    assert sorted([first_out.strip(), second_out.strip()]) == ["exhausted", "reserved"]


def test_stratum_boundaries_match_probability_pilot_definition():
    from datetime import UTC, datetime

    assert pilot._stratum(datetime(2026, 6, 16, 23, 59, tzinfo=UTC)) == "2026_pre_2026-06-17"
    assert pilot._stratum(datetime(2026, 6, 17, tzinfo=UTC)) == "2026_2026-06-17_to_2026-08-25"
    assert pilot._stratum(datetime(2026, 8, 26, tzinfo=UTC)) == "2026_from_2026-08-26"


def test_stratified_selection_is_deterministic_and_balanced(monkeypatch):
    from datetime import UTC, datetime

    dates = [datetime(year, 3, 1, tzinfo=UTC) for year in range(2016, 2026)] + [
        datetime(2026, 2, 1, tzinfo=UTC),
        datetime(2026, 7, 1, tzinfo=UTC),
        datetime(2026, 9, 1, tzinfo=UTC),
    ]
    population = {
        f"CVE-{date.year}-{group_index * 6 + index + 1000:04d}": date
        for group_index, date in enumerate(dates)
        for index in range(6)
    }
    monkeypatch.setattr(pilot, "load_research_manifest", lambda _path: population)

    first, counts = pilot.select_records(Path("unused.csv"), seed=418)
    second, _ = pilot.select_records(Path("unused.csv"), seed=418)

    assert first == second
    assert len(first) == 65
    assert counts == {stratum: 6 for stratum in pilot.STRATA}
    assert {
        stratum: sum(row["stratum"] == stratum for row in first) for stratum in pilot.STRATA
    } == {stratum: 5 for stratum in pilot.STRATA}


def test_sidecar_summarizes_durable_request_ledger_without_credentials(tmp_path):
    ledger = tmp_path / "request_ledger.jsonl"
    request = {
        "request_id": "CVE-2024-10001:0:1:123",
        "cve_id": "CVE-2024-10001",
        "source_endpoint": pilot.downloader.NVD_HISTORY_URL,
        "start_index": 0,
        "attempt": 1,
        "is_retry": False,
        "request_started_at_utc": "2026-10-17T00:00:00+00:00",
    }
    completed = {
        **request,
        "request_ended_at_utc": "2026-10-17T00:00:01+00:00",
        "http_status": 200,
        "response_bytes": 0,
        "response_sha256": "0" * 64,
        "raw_response_path": "outputs/run/raw_responses/page.body",
    }
    ledger.write_text(
        json.dumps({"event": "request_started", **request})
        + "\n"
        + json.dumps({"event": "request_completed", **completed})
        + "\n",
        encoding="utf-8",
    )

    pilot._write_request_sidecar(
        tmp_path,
        "CVE-2024-10001",
        "valid_response",
        {"cveChanges": [{"change": {"created": "2024-01-01T00:00:00.000", "details": []}}]},
    )

    sidecar_path = tmp_path / "request_metadata" / "CVE-2024-10001.json"
    sidecar = json.loads(sidecar_path.read_text(encoding="utf-8"))
    assert sidecar["http_statuses"] == [200]
    assert sidecar["request_started_at_utc"] == request["request_started_at_utc"]
    assert sidecar["request_ended_at_utc"] == completed["request_ended_at_utc"]
    assert sidecar["event_timestamp_timezone_policy"]["naive_event_timestamp_count"] == 1
    assert "apiKey" not in sidecar_path.read_text(encoding="utf-8")
