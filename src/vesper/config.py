"""Central application settings for VESPER."""

import os
from dataclasses import dataclass
from pathlib import Path

from dotenv import load_dotenv

PROJECT_ROOT = Path(__file__).resolve().parents[2]

DATA_SOURCES = ("nvd", "kev", "epss", "exploitdb")


@dataclass(frozen=True)
class Settings:
    """Settings shared by ingestion and application components."""

    project_root: Path
    data_raw: Path
    data_processed: Path
    outputs: Path
    nvd_api_key: str | None

    def raw_source(self, source: str) -> Path:
        """Folder that holds the downloaded files of one data source."""
        if source not in DATA_SOURCES:
            raise ValueError(f"Unknown data source: {source!r}")
        return self.data_raw / source


def load_settings(project_root: Path = PROJECT_ROOT) -> Settings:
    """Load settings from the project environment, if one exists."""

    load_dotenv(project_root / ".env")
    return Settings(
        project_root=project_root,
        data_raw=project_root / "data" / "raw",
        data_processed=project_root / "data" / "processed",
        outputs=project_root / "outputs",
        nvd_api_key=os.getenv("NVD_API_KEY") or None,
    )
