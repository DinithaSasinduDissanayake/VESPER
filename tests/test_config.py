from pathlib import Path

from vesper.config import load_settings


def test_settings_use_project_relative_data_paths(tmp_path: Path):
    settings = load_settings(tmp_path)

    assert settings.project_root == tmp_path
    assert settings.data_raw == tmp_path / "data" / "raw"
    assert settings.data_processed == tmp_path / "data" / "processed"


def test_nvd_api_key_is_optional(monkeypatch, tmp_path: Path):
    monkeypatch.delenv("NVD_API_KEY", raising=False)

    settings = load_settings(tmp_path)

    assert settings.nvd_api_key is None


def test_nvd_api_key_can_be_loaded(monkeypatch, tmp_path: Path):
    monkeypatch.setenv("NVD_API_KEY", "test-key")

    settings = load_settings(tmp_path)

    assert settings.nvd_api_key == "test-key"
