# test_sample_fixtures.py — regression tests over the shipped synthetic .eml fixtures
from pathlib import Path

import pytest

from phishing_analyzer import CompositeScorer, PhishingAnalyzer, main

ROOT = Path(__file__).resolve().parent.parent
SAMPLES = ROOT / "data" / "sample_emails"

PHISH = [
    "sample_01_obvious_phish.eml",
    "sample_02_healthcare_hipaa_breach.eml",
    "sample_03_cvs_pharmacy_refill.eml",
    "sample_04_paypal_lookalike.eml",
    "sample_05_azure_ad_login.eml",
]
LEGITIMATE = [
    "sample_07_legitimate_newsletter.eml",
    "sample_08_internal_memo.eml",
]


@pytest.fixture(scope="module")
def scores():
    analyzer = PhishingAnalyzer(config_path=str(ROOT / "config" / "heuristics.yaml"))
    return {p.name: analyzer.analyze_file(str(p)) for p in sorted(SAMPLES.glob("*.eml"))}


def test_all_eight_fixtures_present(scores):
    assert len(scores) == 8


def test_fixtures_are_marked_synthetic():
    for p in SAMPLES.glob("*.eml"):
        assert "X-Training-Notice: SYNTHETIC FIXTURE" in p.read_text(encoding="utf-8")


@pytest.mark.parametrize("name", PHISH)
def test_phish_reaches_medium_risk(scores, name):
    assert scores[name].composite_score >= CompositeScorer.MEDIUM_THRESHOLD


@pytest.mark.parametrize("name", LEGITIMATE)
def test_legitimate_mail_stays_below_low(scores, name):
    assert scores[name].composite_score < CompositeScorer.LOW_THRESHOLD


def test_every_phish_outscores_every_legitimate(scores):
    assert min(scores[n].composite_score for n in PHISH) > max(scores[n].composite_score for n in LEGITIMATE)


def test_authenticated_shortener_phish_is_a_documented_blind_spot(scores):
    # Sample 06 passes SPF/DKIM/DMARC and hides its payload behind a URL shortener.
    # It is still flagged (non-zero) but scores below MEDIUM — the reason the
    # awareness guide tells users to hover over links rather than trust a score.
    result = scores["sample_06_shipping_notification.eml"]
    url_category = next(c for c in result.category_scores if c.score > 0 and "URL" in c.category.upper())
    assert any("shortener" in i.lower() for i in url_category.indicators)
    assert result.composite_score < CompositeScorer.MEDIUM_THRESHOLD


def test_cli_score_only_on_readme_example(capsys):
    rc = main([str(SAMPLES / "sample_01_obvious_phish.eml"), "--score-only"])
    out = capsys.readouterr().out.strip()
    assert rc == 0
    assert float(out) >= CompositeScorer.MEDIUM_THRESHOLD
