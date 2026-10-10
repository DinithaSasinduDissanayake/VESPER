from pathlib import Path

import pytest

from vesper.config import load_settings


def test_settings_use_project_relative_data_paths(tmp_path: Path):
    settings = load_settings(tmp_path)

    assert settings.project_root == tmp_path
    assert settings.data_raw == tmp_path / "data" / "raw"
    assert settings.data_processed == tmp_path / "data" / "processed"
    assert settings.outputs == tmp_path / "outputs"


def test_each_data_source_has_its_own_raw_folder(tmp_path: Path):
    settings = load_settings(tmp_path)

    assert settings.raw_source("nvd") == tmp_path / "data" / "raw" / "nvd"
    assert settings.raw_source("kev") == tmp_path / "data" / "raw" / "kev"


def test_unknown_data_source_is_rejected(tmp_path: Path):
    with pytest.raises(ValueError, match="Unknown data source"):
        load_settings(tmp_path).raw_source("twitter")


def test_nvd_api_key_is_optional(monkeypatch, tmp_path: Path):
    monkeypatch.delenv("NVD_API_KEY", raising=False)

    settings = load_settings(tmp_path)

    assert settings.nvd_api_key is None


def test_nvd_api_key_can_be_loaded(monkeypatch, tmp_path: Path):
    monkeypatch.setenv("NVD_API_KEY", "test-key")

    settings = load_settings(tmp_path)

    assert settings.nvd_api_key == "test-key"
