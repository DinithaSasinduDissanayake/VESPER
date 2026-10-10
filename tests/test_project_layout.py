"""Checks that keep the repository small and the components independent."""

import ast
import subprocess
from pathlib import Path

import pytest

PROJECT_ROOT = Path(__file__).resolve().parents[1]
PACKAGE_ROOT = PROJECT_ROOT / "src" / "vesper"
COMPONENTS_ROOT = PACKAGE_ROOT / "components"

MAX_FILE_SIZE = 500_000
LOCK_FILES = {"uv.lock", "frontend/bun.lock"}


def tracked_files() -> list[str]:
    try:
        result = subprocess.run(
            ["git", "ls-files"], cwd=PROJECT_ROOT, capture_output=True, text=True, check=True
        )
    except (OSError, subprocess.CalledProcessError):
        pytest.skip("git is not available")
    return result.stdout.splitlines()


def file_size(name: str) -> int:
    path = PROJECT_ROOT / name
    return path.stat().st_size if path.exists() else 0


def imported_modules(path: Path) -> set[str]:
    """Full names of the modules that a Python file imports."""
    package = path.relative_to(PACKAGE_ROOT.parent).with_suffix("").parts[:-1]
    modules = set()
    for node in ast.walk(ast.parse(path.read_text(encoding="utf-8"))):
        if isinstance(node, ast.Import):
            modules.update(alias.name for alias in node.names)
        elif isinstance(node, ast.ImportFrom):
            base = package[: len(package) - node.level + 1] if node.level else ()
            modules.add(".".join([*base, *(node.module or "").split(".")]).strip("."))
    return modules


def test_no_large_file_is_tracked():
    large = [
        name
        for name in tracked_files()
        if name not in LOCK_FILES and file_size(name) > MAX_FILE_SIZE
    ]

    assert large == []


def test_no_data_or_result_file_is_tracked():
    stored = [name for name in tracked_files() if name.startswith(("data/", "outputs/"))]

    assert stored == []


def test_components_do_not_import_each_other():
    components = [path.name for path in COMPONENTS_ROOT.iterdir() if path.is_dir()]
    for component in components:
        others = [f"vesper.components.{name}" for name in components if name != component]
        for path in (COMPONENTS_ROOT / component).rglob("*.py"):
            for module in imported_modules(path):
                assert not module.startswith(tuple(others)), f"{path} imports {module}"


def test_contracts_do_not_import_other_parts_of_vesper():
    for path in (PACKAGE_ROOT / "contracts").rglob("*.py"):
        for module in imported_modules(path):
            if module.startswith("vesper"):
                assert module.startswith("vesper.contracts"), f"{path} imports {module}"
