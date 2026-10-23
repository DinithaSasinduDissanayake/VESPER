"""Tests for the Component B API with a small Cox model fitted on made-up rows."""

import numpy as np
import pandas as pd
import pytest
from fastapi.testclient import TestClient

from vesper.api import b_survival
from vesper.api.main import app
from vesper.components.b_survival.cox_model import fit_cox
from vesper.components.b_survival.score_export import start_of_day
from vesper.components.b_survival.study_design import SNAPSHOT_DATE


def made_up_table(n=500, seed=0):
    """Rows like survival_table.csv: a public exploit and a high CVSS are listed sooner."""
    rng = np.random.default_rng(seed)
    score = rng.choice([4.3, 6.5, 7.5, 9.8], n)
    exploit = rng.random(n) < 0.2
    risk = np.exp(0.5 * (score - 7) + 1.5 * exploit)
    listing = rng.exponential(1500 / risk)
    follow_up = rng.integers(300, 900, n)
    event = (listing <= follow_up).astype(int)
    return pd.DataFrame(
        {
            "cve_id": [f"CVE-2023-{10000 + i}" for i in range(n)],
            "published_at": pd.to_datetime(["2023-03-01"] * n, utc=True),
            "duration_days": np.where(event == 1, np.floor(listing), follow_up).astype(int),
            "event": event,
            "already_exploited": False,
            "cvss_base_score": score,
            "cvss_attack_vector": rng.choice(["NETWORK", "LOCAL"], n),
            "cvss_attack_complexity": rng.choice(["LOW", "HIGH"], n),
            "cvss_privileges_required": rng.choice(["NONE", "LOW"], n),
            "cvss_user_interaction": rng.choice(["NONE", "REQUIRED"], n),
            "cwe_ids": rng.choice(["CWE-79", "CWE-22", None], n),
            "exploit_at_publication": exploit,
        }
    )


@pytest.fixture(scope="module")
def state():
    table = made_up_table()
    unlisted = table.index[table["event"] == 0]
    table.loc[unlisted[0], "cve_id"] = "CVE-2023-00001"  # eligible, not listed
    table.loc[unlisted[1], ["cve_id", "cvss_base_score"]] = ["CVE-2023-00002", np.nan]
    table.loc[unlisted[2], ["cve_id", "published_at"]] = [
        "CVE-2019-00003",
        pd.Timestamp("2019-05-01", tz="UTC"),
    ]
    listed = table.index[table["event"] == 1][0]
    table.loc[listed, "cve_id"] = "CVE-2023-00004"
    train = table[table["cvss_base_score"].notna()]
    return b_survival.prepare(table, fit_cox(train), start_of_day(SNAPSHOT_DATE))


@pytest.fixture
def client(monkeypatch, state):
    monkeypatch.setattr(b_survival, "_state", dict(state))
    return TestClient(app)


WHAT_IF = {
    "cvss_base_score": 9.8,
    "attack_vector": "NETWORK",
    "attack_complexity": "LOW",
    "privileges_required": "NONE",
    "user_interaction": "NONE",
    "public_exploit_at_publication": False,
    "cwe_ids": ["CWE-22"],
}


def test_eligible_cve_gets_curve_numbers_percentile_and_drivers(client):
    body = client.get("/api/b/cve/cve-2023-00001").json()
    assert body["status"] == "available"
    estimate = body["estimate"]
    assert estimate["curve"][0] == [0, 0.0]
    chances = [estimate["by_day"][d] for d in ("30", "90", "365")]
    assert 0 < chances[0] <= chances[1] <= chances[2] < 1
    assert 0 < estimate["percentile"] <= 1
    assert estimate["band"] in {"High", "Medium", "Low"}
    assert estimate["drivers"] and "hazard_ratio" in estimate["drivers"][0]
    assert len(body["population"]["curve"]) == len(estimate["curve"])


@pytest.mark.parametrize(
    ("cve_id", "status", "words"),
    [
        ("CVE-2023-00002", "not_eligible", "CVSS"),
        ("CVE-2019-00003", "not_eligible", "cohort"),
        ("CVE-2023-99999", "not_eligible", "snapshot"),
        ("hello", "not_eligible", "Not a CVE ID"),
        ("CVE-2023-00004", "already_exploited", "KEV"),
    ],
)
def test_other_cves_get_a_reason_not_an_error(client, cve_id, status, words):
    response = client.get(f"/api/b/cve/{cve_id}")
    assert response.status_code == 200
    assert response.json()["status"] == status
    assert words in response.json()["reason"]


def test_a_public_exploit_raises_the_what_if_curve(client):
    without = client.post("/api/b/predict", json=WHAT_IF).json()["estimate"]
    with_poc = client.post(
        "/api/b/predict", json=WHAT_IF | {"public_exploit_at_publication": True}
    ).json()["estimate"]
    assert with_poc["by_day"]["90"] > without["by_day"]["90"]
    assert with_poc["relative_risk"] > without["relative_risk"]


@pytest.mark.parametrize(
    "change", [{"cvss_base_score": 11}, {"attack_vector": "SPACE"}, {"colour": "red"}]
)
def test_invalid_what_if_is_422(client, change):
    assert client.post("/api/b/predict", json=WHAT_IF | change).status_code == 422


def test_plan_ranks_listed_first_and_not_eligible_last(client):
    ids = ["CVE-2023-00002", "CVE-2023-00001", "CVE-2023-00004", "CVE-2023-00001"]
    body = client.post("/api/b/plan", json={"cve_ids": ids, "deadline_days": 30}).json()
    rows = body["rows"]
    assert [r["cve_id"] for r in rows] == ["CVE-2023-00004", "CVE-2023-00001", "CVE-2023-00002"]
    assert rows[0]["patch_first"] is True
    assert 0 < rows[1]["p_before_deadline"] < 1
    assert rows[2]["p_before_deadline"] is None and "CVSS" in rows[2]["reason"]


def test_a_later_deadline_never_lowers_the_chance(client):
    def chance(days):
        body = client.post(
            "/api/b/plan", json={"cve_ids": ["CVE-2023-00001"], "deadline_days": days}
        )
        return body.json()["rows"][0]["p_before_deadline"]

    assert chance(30) <= chance(180)


def test_missing_data_is_503(client, monkeypatch, tmp_path):
    monkeypatch.setattr(b_survival, "_state", {})
    monkeypatch.setattr(
        b_survival, "load_settings", lambda: type("S", (), {"data_processed": tmp_path})
    )
    response = client.get("/api/b/model")
    assert response.status_code == 503
    assert "survival_table" in response.json()["detail"]
