"""Malformed request bodies are rejected with 422, never a server error."""

import pytest
from fastapi.testclient import TestClient

from vesper.api.main import app


@pytest.mark.parametrize("content_type", ["text/plain", "application/octet-stream"])
def test_non_utf8_body_is_422(content_type):
    response = TestClient(app).post(
        "/api/a-text/score", content=b"\xff\xfe not utf-8", headers={"content-type": content_type}
    )

    assert response.status_code == 422
    assert response.json()["detail"][0]["loc"] == ["body"]


def test_invalid_json_body_is_still_422():
    response = TestClient(app).post(
        "/api/a-text/score", content=b"{", headers={"content-type": "application/json"}
    )

    assert response.status_code == 422
