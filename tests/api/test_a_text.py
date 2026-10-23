"""Tests for the Component A API with a fake scorer, so no trained model file is needed."""

import sys
import types

import pytest
from fastapi.testclient import TestClient

from vesper.api import a_text
from vesper.api.main import app

METADATA = {"cutoff": "2026-10-01", "horizon_days": 90, "n_train": 1000, "n_positives": 40}


def fake_score_description(model, text):
    available = "attacker" in text
    return {
        "status": "available" if available else "abstained",
        "reason": None if available else "not_a_vulnerability_description",
        "ranking_score": 0.7 if available else None,
        "model_version": f"a_text-tfidf-lr-{model['metadata']['cutoff']}",
    }


@pytest.fixture
def client(monkeypatch, tmp_path):
    """Point the router at a temporary model file and replace score.py with a fake."""
    model_file = tmp_path / "model.joblib"
    model_file.write_bytes(b"fake")
    fake = types.ModuleType("vesper.components.a_text.score")
    fake.MODEL_NAME = "a_text-tfidf-lr"
    fake.load_model = lambda path: {"model": object(), "metadata": METADATA}
    fake.score_description = fake_score_description
    monkeypatch.setitem(sys.modules, "vesper.components.a_text.score", fake)
    monkeypatch.setenv("VESPER_A_MODEL", str(model_file))
    monkeypatch.setattr(a_text, "_loaded", {})
    return TestClient(app), fake, model_file


def test_score_available(client):
    test_client, _, _ = client
    response = test_client.post("/api/a-text/score", json={"text": "A remote attacker can ..."})
    assert response.status_code == 200
    assert response.json()["status"] == "available"
    assert response.json()["ranking_score"] == 0.7


def test_abstained_is_still_200(client):
    test_client, _, _ = client
    response = test_client.post("/api/a-text/score", json={"text": "Lunch menu for Friday"})
    assert response.status_code == 200
    assert response.json()["status"] == "abstained"
    assert response.json()["reason"] == "not_a_vulnerability_description"


@pytest.mark.parametrize("body", [{}, {"text": ""}, {"text": "x" * 10_001}])
def test_invalid_body_is_422(client, body):
    test_client, _, _ = client
    assert test_client.post("/api/a-text/score", json=body).status_code == 422


def test_model_metadata(client):
    test_client, _, _ = client
    response = test_client.get("/api/a-text/model")
    assert response.status_code == 200
    assert response.json()["model_version"] == "a_text-tfidf-lr-2026-10-01"
    assert response.json()["n_positives"] == 40


def test_missing_model_is_503(client):
    test_client, _, model_file = client
    model_file.unlink()
    response = test_client.post("/api/a-text/score", json={"text": "A remote attacker can ..."})
    assert response.status_code == 503
    assert "VESPER_A_MODEL" in response.json()["detail"]


def test_changed_masking_rules_is_503(client):
    test_client, fake, _ = client

    def refuse(path):
        raise ValueError(f"{path}: masking rules changed since training; retrain with train.py")

    fake.load_model = refuse
    response = test_client.get("/api/a-text/model")
    assert response.status_code == 503
    assert "masking rules changed" in response.json()["detail"]


def test_warm_up_loads_in_background(client):
    _, _, model_file = client
    a_text.warm_up().join(timeout=5)
    assert model_file in a_text._loaded


def test_failed_warm_up_retries_on_request(client):
    test_client, fake, model_file = client
    model_file.unlink()
    a_text.warm_up().join(timeout=5)  # no exception escapes the thread
    assert a_text._loaded == {}
    assert test_client.get("/api/a-text/model").status_code == 503
    model_file.write_bytes(b"fake")
    assert test_client.get("/api/a-text/model").status_code == 200


def test_startup_starts_the_warm_up(client, monkeypatch):
    test_client, _, _ = client
    started = []
    monkeypatch.setattr(a_text, "warm_up", lambda: started.append(True))
    with test_client:  # runs the app's lifespan
        pass
    assert started == [True]
