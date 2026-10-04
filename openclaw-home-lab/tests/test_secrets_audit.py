"""Tests for scripts/secrets-audit.py.

Fake credentials are assembled at runtime so this file never contains a
literal that the scanner (or GitHub secret scanning) would flag.
"""

from pathlib import Path

FAKE_AWS = "AKIA" + "Z" * 16
FAKE_GH = "ghp_" + "a1" * 18
FAKE_API = "x" * 40
PEM_HEADER = "-----BEGIN " + "RSA PRIVATE KEY-----"


def write(tmp_path: Path, name: str, body: str) -> Path:
    p = tmp_path / name
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(body)
    return p


def patterns(findings):
    return {f["pattern"] for f in findings}


def test_detects_cloud_and_vcs_tokens(secrets_audit, tmp_path):
    p = write(tmp_path, "settings.py", f'AWS = "{FAKE_AWS}"\nGH = "{FAKE_GH}"\n')
    found = patterns(secrets_audit.scan_file(p))
    assert {"AWS Access Key ID", "GitHub Personal Access Token"} <= found


def test_detects_generic_api_key_and_private_key(secrets_audit, tmp_path):
    p = write(tmp_path, "config.yaml", f'api_key: "{FAKE_API}"\n{PEM_HEADER}\n')
    found = patterns(secrets_audit.scan_file(p))
    assert {"Generic API Key (high entropy)", "Private Key Inline"} <= found


def test_short_values_are_not_api_keys(secrets_audit, tmp_path):
    p = write(tmp_path, "config.yaml", 'password: "changeme"\n')
    assert secrets_audit.scan_file(p) == []


def test_comment_marked_as_example_is_ignored(secrets_audit, tmp_path):
    p = write(tmp_path, "README.md", f"# example key format: {FAKE_AWS}\n")
    assert secrets_audit.scan_file(p) == []


def test_unmarked_comment_still_flagged(secrets_audit, tmp_path):
    p = write(tmp_path, "deploy.sh", f"# old key {FAKE_AWS}\n")
    assert "AWS Access Key ID" in patterns(secrets_audit.scan_file(p))


def test_suspicious_filenames_and_extensions(secrets_audit, tmp_path):
    assert "suspicious_filename" in patterns(secrets_audit.scan_file(write(tmp_path, ".env", "X=1\n")))
    assert "suspicious_extension" in patterns(secrets_audit.scan_file(write(tmp_path, "server.pem", "x\n")))


def test_findings_never_echo_the_secret(secrets_audit, tmp_path):
    p = write(tmp_path, "settings.py", f'AWS = "{FAKE_AWS}"\n')
    for f in secrets_audit.scan_file(p):
        assert FAKE_AWS not in f["match"]
        assert FAKE_AWS not in f["context"]
        assert f["match"].startswith("AKIA")


def test_workspace_scan_skips_vendor_dirs_and_rolls_up_severity(secrets_audit, tmp_path):
    write(tmp_path, "node_modules/pkg/index.js", f'k="{FAKE_AWS}"')
    write(tmp_path, ".git/config", f'k="{FAKE_AWS}"')
    report = secrets_audit.scan_workspace(tmp_path)
    assert report["findings"] == [] and report["overall_status"] == "ok"

    write(tmp_path, "app.py", f'k="{FAKE_AWS}"')
    report = secrets_audit.scan_workspace(tmp_path)
    assert report["overall_status"] == "critical"
    assert report["severity_counts"]["critical"] == 1


def test_this_project_is_clean(secrets_audit):
    root = Path(__file__).resolve().parent.parent
    report = secrets_audit.scan_workspace(root)
    assert report["overall_status"] == "ok", report["findings"]
