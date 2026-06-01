#!/usr/bin/env python3
"""
test_analyzer.py — Unit tests for the Phishing Analyzer
=======================================================
Uses synthetic (fake) e-mail fixtures only.  No real PHI, PII, or secrets.

Run:  pytest tests/test_analyzer.py -v
"""

import email
import email.policy
from pathlib import Path

import pytest

# Import the module under test (MUT).  Adjust sys.path if needed when
# running outside the package directory.
import phishing_analyzer as mut


# ---------------------------------------------------------------------------
# Fixtures — synthetic e-mail messages
# ---------------------------------------------------------------------------


def _make_msg(
    *,
    from_addr: str = "sender@example.com",
    to_addr: str = "victim@example.com",
    subject: str = "Test",
    reply_to: str | None = None,
    return_path: str | None = None,
    auth_results: str | None = None,
    received: list[str] | None = None,
    body_text: str = "",
    body_html: str = "",
) -> email.message.EmailMessage:
    """Helper to build a MIME message with the exact headers we want."""
    msg = email.message.EmailMessage(policy=email.policy.default)
    msg["From"] = from_addr
    msg["To"] = to_addr
    msg["Subject"] = subject
    if reply_to:
        msg["Reply-To"] = reply_to
    if return_path:
        msg["Return-Path"] = return_path
    if auth_results:
        msg["Authentication-Results"] = auth_results
    for hop in received or []:
        msg.add_header("Received", hop)
    if body_text:
        msg.set_content(body_text)
    if body_html:
        msg.add_alternative(body_html, subtype="html")
    return msg


@pytest.fixture
def heuristics():
    """Default heuristics dict (same as embedded fallback)."""
    return mut.PhishingAnalyzer._load_config(None)


# ---------------------------------------------------------------------------
# EmailHeaderAnalyzer tests
# ---------------------------------------------------------------------------


class TestHeaderAnalyzer:
    def test_spf_dkim_dmarc_all_pass(self, heuristics):
        msg = _make_msg(
            auth_results="spf=pass dkim=pass dmarc=pass header.from=example.com",
        )
        analyzer = mut.EmailHeaderAnalyzer(heuristics)
        result = analyzer.analyze(msg)
        assert result.score == pytest.approx(0.0)
        assert not result.indicators

    def test_spf_fail(self, heuristics):
        msg = _make_msg(
            auth_results="spf=fail smtp.mailfrom=evil.com",
        )
        analyzer = mut.EmailHeaderAnalyzer(heuristics)
        result = analyzer.analyze(msg)
        assert any("SPF failure" in i for i in result.indicators)
        assert result.score >= 3.0

    def test_dkim_and_spf_none(self, heuristics):
        msg = _make_msg(
            auth_results="dkim=none spf=none",
        )
        analyzer = mut.EmailHeaderAnalyzer(heuristics)
        result = analyzer.analyze(msg)
        assert any("No DKIM or SPF" in i for i in result.indicators)
        assert result.score >= 1.5

    def test_missing_auth_results(self, heuristics):
        msg = _make_msg()  # no Authentication-Results at all
        analyzer = mut.EmailHeaderAnalyzer(heuristics)
        result = analyzer.analyze(msg)
        assert any("Missing Authentication-Results" in i for i in result.indicators)

    def test_reply_to_mismatch(self, heuristics):
        msg = _make_msg(
            from_addr="support@bankofamerica.com",
            reply_to="help-desk-secure@b0famerica.com",
        )
        analyzer = mut.EmailHeaderAnalyzer(heuristics)
        result = analyzer.analyze(msg)
        assert any("Reply-To" in i for i in result.indicators)
        assert result.score >= 3.0

    def test_free_mailer_sender(self, heuristics):
        msg = _make_msg(from_addr="irsteam@gmail.com")
        analyzer = mut.EmailHeaderAnalyzer(heuristics)
        result = analyzer.analyze(msg)
        assert any("free mailer" in i for i in result.indicators)

    def test_random_subdomain(self, heuristics):
        msg = _make_msg(from_addr="alert@xkjqzmnpblobcore.windows.net")
        analyzer = mut.EmailHeaderAnalyzer(heuristics)
        result = analyzer.analyze(msg)
        assert any("random-looking subdomain" in i for i in result.indicators)

    def test_many_hops(self, heuristics):
        hops = [f"from mx{i}.example.com by mx{i+1}.example.com" for i in range(6)]
        msg = _make_msg(received=hops)
        analyzer = mut.EmailHeaderAnalyzer(heuristics)
        result = analyzer.analyze(msg)
        assert any("long routing chain" in i for i in result.indicators)

    def test_private_ip_in_received(self, heuristics):
        msg = _make_msg(
            received=["from [192.168.1.55] by outbound.example.com"],
        )
        analyzer = mut.EmailHeaderAnalyzer(heuristics)
        result = analyzer.analyze(msg)
        assert any("Private IP" in i for i in result.indicators)

    def test_return_path_mismatch(self, heuristics):
        msg = _make_msg(
            from_addr="billing@paypal.com",
            return_path="<bounce@evil.com>",
        )
        analyzer = mut.EmailHeaderAnalyzer(heuristics)
        result = analyzer.analyze(msg)
        assert any("Return-Path" in i for i in result.indicators)

    def test_html_only(self, heuristics):
        msg = _make_msg(body_html="<html><body>Click here</body></html>")
        analyzer = mut.EmailHeaderAnalyzer(heuristics)
        result = analyzer.analyze(msg)
        assert any("HTML-only" in i for i in result.indicators)

    def test_subject_invoice_keyword(self, heuristics):
        msg = _make_msg(subject="Invoice #8842 — Action Required")
        analyzer = mut.EmailHeaderAnalyzer(heuristics)
        result = analyzer.analyze(msg)
        assert any("Subject contains common lure keyword" in i for i in result.indicators)


# ---------------------------------------------------------------------------
# URLHeuristicAnalyzer tests
# ---------------------------------------------------------------------------


class TestURLAnalyzer:
    def test_no_urls(self, heuristics):
        analyzer = mut.URLHeuristicAnalyzer(heuristics)
        result = analyzer.analyze([])
        assert result.score == 0.0
        assert any("No URLs found" in d for d in result.details)

    def test_ip_based_url(self, heuristics):
        analyzer = mut.URLHeuristicAnalyzer(heuristics)
        result = analyzer.analyze(["http://203.0.113.45/login"])
        assert any("IP-based URL" in i for i in result.indicators)
        assert result.score >= 4.0

    def test_url_shortener(self, heuristics):
        analyzer = mut.URLHeuristicAnalyzer(heuristics)
        result = analyzer.analyze(["https://bit.ly/3xFake00"])
        assert any("shortener" in i for i in result.indicators)

    def test_suspicious_tld(self, heuristics):
        analyzer = mut.URLHeuristicAnalyzer(heuristics)
        result = analyzer.analyze(["https://prize-winner.xyz/claim"])
        assert any("Suspicious TLD" in i for i in result.indicators)

    def test_http_not_https(self, heuristics):
        analyzer = mut.URLHeuristicAnalyzer(heuristics)
        result = analyzer.analyze(["http://old-portal.company.com/login"])
        assert any("Unencrypted HTTP" in i for i in result.indicators)

    def test_homoglyph(self, heuristics):
        # 'а' below is CYRILLIC SMALL LETTER A (U+0430), not ASCII 'a'
        cyrillic_amazon = "https://аmazon.com/signin"  # first char is Cyrillic
        analyzer = mut.URLHeuristicAnalyzer(heuristics)
        result = analyzer.analyze([cyrillic_amazon])
        assert any("Homoglyph" in i for i in result.indicators)
        assert result.score >= 4.0

    def test_lookalike_domain(self, heuristics):
        analyzer = mut.URLHeuristicAnalyzer(heuristics)
        result = analyzer.analyze(["https://paypa1.com/verify"])
        assert any("lookalike" in i.lower() for i in result.indicators)

    def test_deep_subdomain(self, heuristics):
        analyzer = mut.URLHeuristicAnalyzer(heuristics)
        result = analyzer.analyze(["https://login.secure.auth.mycorp.portal.evil.com/"])
        assert any("Deep subdomain" in i for i in result.indicators)

    def test_at_symbol_in_url(self, heuristics):
        analyzer = mut.URLHeuristicAnalyzer(heuristics)
        result = analyzer.analyze(["https://legit-looking.com@evil.com/capture"])
        assert any("@" in i for i in result.indicators)

    def test_data_uri(self, heuristics):
        analyzer = mut.URLHeuristicAnalyzer(heuristics)
        result = analyzer.analyze(["data:text/html,<h1>Phish</h1>"])
        assert any("Data URI" in i for i in result.indicators)

    def test_multiple_urls_additive(self, heuristics):
        analyzer = mut.URLHeuristicAnalyzer(heuristics)
        urls = [
            "http://203.0.113.45/login",       # +5
            "https://bit.ly/3xFake00",         # +3.5
            "https://prize-winner.xyz/claim",  # +3
        ]
        result = analyzer.analyze(urls)
        assert result.score >= 10.0
        assert result.score <= 40.0  # clamped


# ---------------------------------------------------------------------------
# UrgencyLanguageAnalyzer tests
# ---------------------------------------------------------------------------


class TestUrgencyAnalyzer:
    def test_empty_text(self, heuristics):
        analyzer = mut.UrgencyLanguageAnalyzer(heuristics)
        result = analyzer.analyze("")
        assert result.score == 0.0

    def test_basic_urgency_pattern(self, heuristics):
        analyzer = mut.UrgencyLanguageAnalyzer(heuristics)
        text = "Your account will be suspended within 24 hours if you do not act now."
        result = analyzer.analyze(text)
        assert any("suspended" in i.lower() for i in result.indicators)
        assert result.score > 0

    def test_multiple_patterns_additive(self, heuristics):
        analyzer = mut.UrgencyLanguageAnalyzer(heuristics)
        text = (
            "URGENT: Unauthorized access detected on your account. "
            "Verify your identity immediately or face legal action. "
            "Failure to respond will result in consequences."
        )
        result = analyzer.analyze(text)
        assert result.score >= 8.0  # several strong patterns

    def test_fear_density(self, heuristics):
        analyzer = mut.UrgencyLanguageAnalyzer(heuristics)
        # Pack a lot of fear words into a short sentence
        text = "Breach alert! Suspicious unauthorized stolen compromised exposed leaked hacked attack malware virus infected danger risk critical emergency scam fraud phishing"
        result = analyzer.analyze(text)
        assert any("fear-word density" in i.lower() for i in result.indicators)

    def test_all_caps(self, heuristics):
        analyzer = mut.UrgencyLanguageAnalyzer(heuristics)
        text = "WARNING ALERT IMPORTANT URGENT ACT NOW IMMEDIATELY"
        result = analyzer.analyze(text)
        assert any("ALL-CAPS" in i for i in result.indicators)

    def test_excessive_punctuation(self, heuristics):
        analyzer = mut.UrgencyLanguageAnalyzer(heuristics)
        text = "Act now!!! Or else??? You must respond!!!"
        result = analyzer.analyze(text)
        assert any("punctuation" in i.lower() for i in result.indicators)

    def test_legitimate_text_low_score(self, heuristics):
        analyzer = mut.UrgencyLanguageAnalyzer(heuristics)
        text = (
            "Hi team, just a reminder that the quarterly all-hands meeting is "
            "scheduled for Thursday at 10 AM in conference room B. "
            "Please let me know if you have any conflicts. Thanks!"
        )
        result = analyzer.analyze(text)
        assert result.score < 5.0


# ---------------------------------------------------------------------------
# Integration / end-to-end tests
# ---------------------------------------------------------------------------


class TestPhishingAnalyzerIntegration:
    def test_obvious_phish_high_score(self):
        raw = """\
From: security@аmazon.com
To: victim@example.com
Subject: Urgent — Your Account Will Be Suspended!!!
Reply-To: helpdesk@amaz0n-support.xyz
Authentication-Results: mx.example.com; spf=fail; dkim=fail; dmarc=fail
Content-Type: text/html; charset="utf-8"

<html>
<body>
<p>Dear Customer,</p>
<p>Your account will be suspended within 24 hours if you do not act now. 
Click <a href="http://203.0.113.66/login?token=FAKE123">here</a> to verify now!!!</p>
<p>Unauthorized access has been detected. Failure to respond will result in 
permanent account closure and legal consequences.</p>
</body>
</html>
"""
        analyzer = mut.PhishingAnalyzer()
        result = analyzer.analyze_email(raw)
        # With SPF/DKIM/DMARC fail + reply-to mismatch + IP URL + lookalike + urgency,
        # this should push into MEDIUM/HIGH territory.
        assert result.composite_score >= 45.0
        assert result.risk_level in ("MEDIUM", "HIGH", "CRITICAL")
        assert len(result.extracted_urls) >= 1

    def test_subtle_phish_medium_score(self):
        raw = """\
From: billing@paypa1.com
To: victim@example.com
Subject: Invoice #9912 — Action Required
Reply-To: accounts-receivable@paypa1-support.net
Authentication-Results: mx.example.com; spf=softfail; dkim=none
Content-Type: text/plain; charset="utf-8"

Hello,

Please review the attached invoice and confirm payment within 48 hours.
Visit https://bit.ly/3xFake01 to access your portal.

URGENT: If you do not respond within 24 hours, your account will be 
suspended and you will face legal action.

Thank you,
Accounts Receivable
"""
        analyzer = mut.PhishingAnalyzer()
        result = analyzer.analyze_email(raw)
        # Lookalike domain + shortener + subject keyword + urgency + auth issues
        # should push into MEDIUM territory.
        assert result.composite_score >= 35.0
        assert result.composite_score < 70.0
        assert result.risk_level in ("MEDIUM", "HIGH")

    def test_legitimate_email_low_score(self):
        raw = """\
From: sarah.jenkins@company.com
To: team@company.com
Subject: Q3 Planning Meeting — Thursday 10 AM
Authentication-Results: mx.example.com; spf=pass; dkim=pass; dmarc=pass
Content-Type: text/plain; charset="utf-8"

Hi everyone,

Just a friendly reminder that our Q3 planning meeting is this Thursday
at 10 AM in conference room B.  Agenda items are attached.

Let me know if you have any questions.

Best,
Sarah
"""
        analyzer = mut.PhishingAnalyzer()
        result = analyzer.analyze_email(raw)
        assert result.composite_score < 20.0
        assert result.risk_level in ("VERY_LOW", "LOW")

    def test_no_body_no_urls(self):
        raw = """\
From: noreply@example.com
To: user@example.com
Subject: Test
Content-Type: text/plain; charset="utf-8"

Hello.
"""
        analyzer = mut.PhishingAnalyzer()
        result = analyzer.analyze_email(raw)
        assert result.composite_score < 10.0

    def test_output_json_serialisable(self):
        raw = """\
From: alert@example.com
To: user@example.com
Subject: Test
Content-Type: text/plain; charset="utf-8"

Please visit http://203.0.113.1/login immediately.
"""
        analyzer = mut.PhishingAnalyzer()
        result = analyzer.analyze_email(raw)
        # _serialise must not raise
        blob = mut._serialise(result)
        assert isinstance(blob, dict)
        assert "composite_score" in blob
        assert "category_scores" in blob
        assert len(blob["category_scores"]) == 3

    def test_looks_random_subdomain(self):
        # DGA-style subdomain
        assert mut.EmailHeaderAnalyzer._looks_random("xkjqzmnp") is True
        assert mut.EmailHeaderAnalyzer._looks_random("paypal") is False
        assert mut.EmailHeaderAnalyzer._looks_random("") is False

    def test_levenshtein_distance(self):
        assert mut._levenshtein("paypal", "paypa1") == 1
        assert mut._levenshtein("amazon", "amaz0n") == 1
        assert mut._levenshtein("apple", "apple") == 0
        assert mut._levenshtein("", "abc") == 3

    def test_extract_urls(self):
        text = "Visit https://example.com/path?a=1 and http://1.2.3.4/x or www.site.org"
        urls = mut._extract_urls(text)
        assert len(urls) == 3
        assert "https://example.com/path?a=1" in urls
        assert "http://1.2.3.4/x" in urls

    def test_homoglyph_detection(self):
        # Cyrillic 'а' in "аmazon"
        domain = "\u0430mazon.com"  # U+0430 Cyrillic Small Letter A
        flag, chars = mut._has_homoglyphs(domain)
        assert flag is True
        assert len(chars) > 0

    def test_normalise_domain(self):
        assert mut._normalise_domain("WWW.PayPal.COM") == "paypal.com"
        assert mut._normalise_domain("www.amazon.co.uk.") == "amazon.co.uk"


# ---------------------------------------------------------------------------
# CLI-level tests
# ---------------------------------------------------------------------------


class TestCLI:
    def test_list_indicators_exit_code(self):
        assert mut.main(["--list-indicators"]) == 0

    def test_missing_file_error(self):
        assert mut.main(["--config", "config/heuristics.yaml", "/nonexistent"]) == 1

    def test_score_only_output(self, capsys, tmp_path):
        eml = tmp_path / "test.eml"
        eml.write_text(
            "From: a@b.com\nTo: c@d.com\nSubject: X\n\nClick http://1.2.3.4/x\n",
            encoding="utf-8",
        )
        assert mut.main([str(eml), "--score-only"]) == 0
        captured = capsys.readouterr()
        assert captured.out.strip().replace(".", "").isdigit()

    def test_json_output_valid(self, capsys, tmp_path):
        eml = tmp_path / "test.eml"
        eml.write_text(
            "From: a@b.com\nTo: c@d.com\nSubject: X\n\nHello.\n",
            encoding="utf-8",
        )
        assert mut.main([str(eml), "--json"]) == 0
        captured = capsys.readouterr()
        import json
        data = json.loads(captured.out)
        assert "composite_score" in data
        assert "risk_level" in data
