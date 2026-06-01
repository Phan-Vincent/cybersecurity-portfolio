"""Test permissions, logging hygiene, and least privilege."""

import pytest
from pathlib import Path
import os
import tempfile
import stat
import json

import sys
import importlib.util

REPO_ROOT = Path(__file__).parent.parent

def _load_module(name: str, rel_path: str):
    spec = importlib.util.spec_from_file_location(name, REPO_ROOT / rel_path)
    mod = importlib.util.module_from_spec(spec)
    sys.modules[name] = mod
    spec.loader.exec_module(mod)
    return mod

m_main = _load_module("m_main1", "mitigated/demo_pipeline.py")

class TestPermissions:
    def test_secret_scrubbing_formatter_redacts_api_key(self):
        """MITIGATED: SecretScrubbingFormatter removes sk- keys from logs."""
        fmt = m_main.SecretScrubbingFormatter("%(message)s")
        import logging
        record = logging.LogRecord(
            name="test", level=logging.INFO, pathname="", lineno=0,
            msg="Error with key sk-abc123def456ghi789jkl012", args=(), exc_info=None
        )
        out = fmt.format(record)
        assert "sk-abc123" not in out
        assert "[REDACTED]" in out

    def test_mitigated_code_checks_env_permissions(self):
        """MITIGATED: .env with loose permissions triggers error."""
        with tempfile.TemporaryDirectory() as tmp:
            env_file = Path(tmp) / ".env"
            env_file.write_text("OPENAI_API_KEY=sk-test\n")
            os.chmod(str(env_file), 0o644)
            # Change into the tmp dir so the check finds it
            old_cwd = os.getcwd()
            try:
                os.chdir(tmp)
                with pytest.raises(PermissionError) as exc_info:
                    m_main._check_env_permissions()
                assert "chmod 600 .env" in str(exc_info.value)
            finally:
                os.chdir(old_cwd)

    def test_mitigated_output_dir_is_restricted(self):
        """MITIGATED: _secure_makedirs creates directory with 0o700."""
        with tempfile.TemporaryDirectory() as tmp:
            out = Path(tmp) / "nested" / "out"
            m_main._secure_makedirs(out)
            mode = out.stat().st_mode
            assert (mode & 0o777) == 0o700
