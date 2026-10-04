"""Tests for scripts/score_assessment.py."""

import csv
import json
from datetime import date
from pathlib import Path

import pytest

import score_assessment as sa

ROOT = Path(__file__).resolve().parent.parent
SAMPLE = ROOT / "data" / "sample_pharmacy_assessment.csv"
AS_OF = date(2026, 6, 15)


@pytest.fixture(scope="module")
def catalog():
    return sa.load_catalog(sa.CONTROLS_PATH)


@pytest.fixture(scope="module")
def sample(catalog):
    return sa.score_rows(sa.read_assessment(SAMPLE), catalog, AS_OF)


def row(control_id, status, **extra):
    return {"control_id": control_id, "assessment_status": status, **extra}


class TestCatalog:
    def test_every_control_has_scoring_fields(self, catalog):
        assert len(catalog) == 58
        for c in catalog.values():
            assert c["phi_exposure"] in sa.PHI_MULTIPLIER
            assert 1 <= c["implementation_level"] <= 5
            assert c["implementation_specification"] in sa.DEFAULT_IMPACT

    def test_sample_covers_whole_catalog(self, catalog):
        ids = [r["control_id"] for r in sa.read_assessment(SAMPLE)]
        assert sorted(ids) == sorted(catalog)


class TestScoring:
    def test_formula_matches_readme(self):
        # README: Risk = L x I x PHI multiplier; Critical >= 30
        assert sa.severity_for(30) == ("Critical", "0-30 days")
        assert sa.severity_for(29.99)[0] == "High"
        assert sa.severity_for(20)[0] == "High"
        assert sa.severity_for(10)[0] == "Medium"
        assert sa.severity_for(9.99)[0] == "Low"

    def test_non_compliant_required_high_phi_is_critical(self, catalog):
        gaps, _ = sa.score_rows([row("ADM-1.1", "Non-Compliant")], {"ADM-1.1": catalog["ADM-1.1"]}, AS_OF)
        g = gaps[0]
        assert (g.likelihood, g.impact, g.phi_exposure) == (5, 4, "High")
        assert g.risk_score == 30.0 and g.severity == "Critical"

    def test_partial_scores_lower_than_non_compliant(self, catalog):
        sub = {"ADM-1.1": catalog["ADM-1.1"]}
        partial, _ = sa.score_rows([row("ADM-1.1", "Partial")], sub, AS_OF)
        nc, _ = sa.score_rows([row("ADM-1.1", "Non-Compliant")], sub, AS_OF)
        assert partial[0].risk_score < nc[0].risk_score

    def test_compliant_and_not_applicable_are_not_gaps(self, catalog):
        sub = {k: catalog[k] for k in ("ADM-1.1", "ADM-1.2")}
        gaps, summary = sa.score_rows([row("ADM-1.1", "Compliant"), row("ADM-1.2", "Not Applicable")], sub, AS_OF)
        assert gaps == []
        assert summary["compliance_pct"] == 100.0

    def test_assessor_overrides(self, catalog):
        gaps, _ = sa.score_rows([row("ADM-1.1", "Partial", likelihood="1", impact="2")], {"ADM-1.1": catalog["ADM-1.1"]}, AS_OF)
        assert gaps[0].risk_score == 3.0

    @pytest.mark.parametrize("bad", ["0", "6", "high"])
    def test_override_out_of_range_rejected(self, catalog, bad):
        with pytest.raises(sa.AssessmentError):
            sa.score_rows([row("ADM-1.1", "Partial", likelihood=bad)], {"ADM-1.1": catalog["ADM-1.1"]}, AS_OF)

    def test_missing_controls_become_not_assessed(self, catalog):
        sub = {k: catalog[k] for k in ("ADM-1.1", "ADM-1.2")}
        gaps, summary = sa.score_rows([row("ADM-1.1", "Compliant")], sub, AS_OF)
        assert [g.control_id for g in gaps] == ["ADM-1.2"]
        assert gaps[0].assessment_status == "Not Assessed"
        assert any("ADM-1.2" in w for w in summary["warnings"])

    def test_overdue_flag(self, catalog):
        sub = {"ADM-1.1": catalog["ADM-1.1"]}
        past, _ = sa.score_rows([row("ADM-1.1", "Partial", target_date="2026-01-01")], sub, AS_OF)
        future, _ = sa.score_rows([row("ADM-1.1", "Partial", target_date="2026-12-31")], sub, AS_OF)
        assert past[0].overdue and not future[0].overdue


class TestValidation:
    def test_unknown_control_rejected(self, catalog):
        with pytest.raises(sa.AssessmentError, match="Unknown control_id"):
            sa.score_rows([row("XYZ-9.9", "Partial")], catalog, AS_OF)

    def test_duplicate_control_rejected(self, catalog):
        with pytest.raises(sa.AssessmentError, match="Duplicate"):
            sa.score_rows([row("ADM-1.1", "Partial"), row("ADM-1.1", "Compliant")], catalog, AS_OF)

    def test_invalid_status_rejected(self, catalog):
        with pytest.raises(sa.AssessmentError, match="invalid assessment_status"):
            sa.score_rows([row("ADM-1.1", "Mostly Fine")], catalog, AS_OF)

    def test_missing_required_columns(self, tmp_path):
        p = tmp_path / "bad.csv"
        p.write_text("control_id,notes\nADM-1.1,x\n")
        with pytest.raises(sa.AssessmentError, match="assessment_status"):
            sa.read_assessment(p)


class TestSampleReport:
    def test_ranked_descending(self, sample):
        gaps, _ = sample
        scores = [g.risk_score for g in gaps]
        assert scores == sorted(scores, reverse=True)

    def test_sample_summary(self, sample):
        gaps, summary = sample
        assert summary["controls_total"] == 58
        assert len(gaps) == 52
        assert summary["severity_counts"]["Critical"] >= 1

    def test_markdown_sections(self, sample):
        md = sa.render_markdown(*sample, source="sample.csv")
        for heading in ("## Executive Summary", "## Prioritized Risk Register", "## Remediation Roadmap"):
            assert heading in md
        assert "### Critical — remediate within 0-30 days" in md


class TestOutputs:
    def test_csv_register_neutralises_formulas(self, catalog, tmp_path):
        gaps, summary = sa.score_rows(
            [row("ADM-1.1", "Partial", remediation_owner="=HYPERLINK(\"http://x\")")], {"ADM-1.1": catalog["ADM-1.1"]}, AS_OF
        )
        out = tmp_path / "reg.csv"
        sa.write_register(gaps, summary, out)
        rec = next(csv.DictReader(out.open()))
        assert rec["remediation_owner"].startswith("'=")

    def test_json_register(self, sample, tmp_path):
        out = tmp_path / "reg.json"
        sa.write_register(*sample, out)
        data = json.loads(out.read_text())
        assert len(data["gaps"]) == 52 and "summary" in data

    def test_cli_end_to_end(self, tmp_path):
        md, reg = tmp_path / "r.md", tmp_path / "r.csv"
        rc = sa.main(["-a", str(SAMPLE), "-o", str(md), "-r", str(reg), "--as-of", "2026-06-15"])
        assert rc == 0 and md.exists() and reg.exists()

    def test_cli_rejects_bad_input(self, tmp_path, capsys):
        p = tmp_path / "bad.csv"
        p.write_text("control_id,assessment_status\nADM-1.1,Maybe\n")
        assert sa.main(["-a", str(p), "-o", str(tmp_path / "r.md")]) == 2
