# conftest.py — load the hyphen-named scripts as importable modules for tests
import importlib.util
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent


def _load(name: str, filename: str):
    spec = importlib.util.spec_from_file_location(name, ROOT / "scripts" / filename)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


@pytest.fixture(scope="session")
def validator():
    return _load("validate_segmentation", "validate-segmentation.py")


@pytest.fixture(scope="session")
def checklist():
    return _load("generate_compliance_checklist", "generate-compliance-checklist.py")


@pytest.fixture(scope="session")
def design(validator):
    return {
        "vlans": validator.load_csv(ROOT / "config" / "vlan-segmentation.csv"),
        "rules": validator.load_csv(ROOT / "config" / "firewall-rules.csv"),
        "addressing": validator.load_csv(ROOT / "config" / "ip-addressing.csv"),
        "devices": validator.load_csv(ROOT / "data" / "sample-device-inventory.csv"),
    }
