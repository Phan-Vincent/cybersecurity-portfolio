# conftest.py — load the scripts (one has a hyphenated name) as modules
import importlib.util
from pathlib import Path

import pytest

SCRIPTS = Path(__file__).resolve().parent.parent / "scripts"


def _load(name: str, filename: str):
    spec = importlib.util.spec_from_file_location(name, SCRIPTS / filename)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


@pytest.fixture(scope="session")
def secrets_audit():
    return _load("secrets_audit", "secrets-audit.py")


@pytest.fixture(scope="session")
def healthcheck():
    return _load("healthcheck", "healthcheck.py")
