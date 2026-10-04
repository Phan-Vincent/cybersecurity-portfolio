"""Guard against the CFR cross-reference drifting from the controls catalog."""

from pathlib import Path

import score_assessment as sa

ROOT = Path(__file__).resolve().parent.parent


def test_reference_lists_every_control_with_its_cfr():
    ref = (ROOT / "docs" / "hipaa-safeguards-reference.md").read_text(encoding="utf-8")
    for cid, c in sa.load_catalog(sa.CONTROLS_PATH).items():
        assert f"| {cid} | {c['cfr_reference']} |" in ref, cid
