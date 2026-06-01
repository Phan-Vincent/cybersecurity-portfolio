"""Test input validation: path traversal, symlink, file size."""

import pytest
import os
from pathlib import Path
import tempfile

import sys
import importlib.util

REPO_ROOT = Path(__file__).parent.parent

def _load_module(name: str, rel_path: str):
    spec = importlib.util.spec_from_file_location(name, REPO_ROOT / rel_path)
    mod = importlib.util.module_from_spec(spec)
    sys.modules[name] = mod
    spec.loader.exec_module(mod)
    return mod

v_ingestion = _load_module("v_ingestion2", "vulnerable/ingestion.py")
m_ingestion = _load_module("m_ingestion2", "mitigated/ingestion.py")

class TestInputValidation:
    def test_vulnerable_ingestion_allows_symlink(self):
        """VULNERABLE: the original code resolves symlinks without checking."""
        with tempfile.TemporaryDirectory() as tmp:
            real_file = Path(tmp) / "real.csv"
            real_file.write_text("date,calories\n2024-01-01,2500\n")
            symlink = Path(tmp) / "link.csv"
            try:
                os.symlink(real_file, symlink)
            except OSError:
                pytest.skip("Symlink creation not supported on this OS")
            # Vulnerable code does not reject symlinks
            rows = v_ingestion.read_csv_safely(symlink, expected_columns=["date", "calories"])
            assert len(rows) == 1

    def test_mitigated_ingestion_rejects_symlink(self):
        """MITIGATED: symlink is rejected."""
        with tempfile.TemporaryDirectory() as tmp:
            real_file = Path(tmp) / "real.csv"
            real_file.write_text("date,calories\n2024-01-01,2500\n")
            symlink = Path(tmp) / "link.csv"
            try:
                os.symlink(real_file, symlink)
            except OSError:
                pytest.skip("Symlink creation not supported on this OS")
            with pytest.raises(m_ingestion.SecurityError) as exc_info:
                m_ingestion.read_csv_safely(symlink, expected_columns=["date", "calories"])
            assert "Symlinks are not allowed" in str(exc_info.value)

    def test_mitigated_ingestion_rejects_path_traversal(self):
        """MITIGATED: path traversal outside base_dir is rejected."""
        with tempfile.TemporaryDirectory() as tmp:
            base = Path(tmp) / "base"
            base.mkdir()
            outside = Path(tmp) / "outside.csv"
            outside.write_text("date,calories\n2024-01-01,2500\n")
            with pytest.raises(m_ingestion.SecurityError) as exc_info:
                m_ingestion.read_csv_safely(
                    outside, expected_columns=["date", "calories"], base_dir=base
                )
            assert "Path must be within" in str(exc_info.value)

    def test_mitigated_ingestion_rejects_oversized_file(self):
        """MITIGATED: files > 10MB are rejected."""
        with tempfile.TemporaryDirectory() as tmp:
            big_file = Path(tmp) / "big.csv"
            # Create ~10.6MB with 6,600 rows of 3 columns, each field ~800 chars (under 1024 limit)
            long_value = "x" * 800
            lines = ["date,calories,protein\n"]
            for i in range(6_600):
                lines.append(f"2024-01-01,{long_value},{long_value}\n")
            big_file.write_text("".join(lines))
            with pytest.raises(m_ingestion.SecurityError) as exc_info:
                m_ingestion.read_csv_safely(big_file, expected_columns=["date", "calories", "protein"])
            assert "File size" in str(exc_info.value)
