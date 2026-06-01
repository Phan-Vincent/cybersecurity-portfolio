#!/usr/bin/env python3
"""
Phishing Analyzer — Core Engine
================================
A defensive-security CLI tool that analyzes emails and URLs for phishing
indicators.  Designed for SOC analysts, security engineers, and awareness
training programs.

Author:  Vincent Phan
License: MIT
"""

from __future__ import annotations

import argparse
import email
import json
import math
import os
import re
import sys
import unicodedata
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

import yaml

# ---------------------------------------------------------------------------
# Constants & lookup tables
# ---------------------------------------------------------------------------

# Common URL shorteners — these are frequently abused to hide the final
# destination from casual inspection.
URL_SHORTENERS = frozenset(
    [
        "bit.ly",
        "tinyurl.com",
        "t.co",
        "ow.ly",
        "buff.ly",
        "short.link",
        "rebrand.ly",
        "cutt.ly",
        "short.io",
        "rb.gy",
    ]
)

# TLDs with historically high abuse rates (source: SpamHaus, APWG reports).
SUSPICIOUS_TLDS = frozenset(
    [
        ".tk",
        ".ml",
        ".ga",
        ".cf",
        ".top",
        ".xyz",
        ".club",
        ".online",
        ".site",
        ".work",
        ".ninja",
        ".click",
        ".link",
        ".download",
        ".zip",        # recently released, already weaponised
        ".mov",        # same
    ]
)

# Brands commonly impersonated in phishing.  Scored via Levenshtein distance.
HIGH_VALUE_BRANDS = frozenset(
    [
        "amazon",
        "apple",
        "microsoft",
        "google",
        "paypal",
        "chase",
        "wellsfargo",
        "bankofamerica",
        "cvs",
        "walgreens",
        "cigna",
        "aetna",
        "kaiserpermanente",
        "mychart",
        "epic",
        "cerner",
        "office365",
        "linkedin",
        "facebook",
        "instagram",
        "netflix",
        "fedex",
        "ups",
        "dhl",
        "irs",
        "socialsecurity",
        "medicare",
    ]
)

# Pre-defined urgency / fear patterns.  Each tuple is (regex_pattern, weight).
# Weights are additive; higher weights → stronger indicator.
URGENCY_PATTERNS: list[tuple[re.Pattern[str], float]] = [
    # Immediate action demanded
    (re.compile(r"\b(act\s+now|immediate\s+action|respond\s+within\s+\d+\s*(hours?|minutes?|hrs?|mins?))\b", re.I), 3.0),
    (re.compile(r"\b(urgent|asap|emergency|critical)\b", re.I), 2.5),
    (re.compile(r"\b(your\s+account\s+(will\s+be|is\s+being)\s+(suspended|disabled|locked|terminated|closed))\b", re.I), 4.0),
    # Threat / consequence
    (re.compile(r"\b(unauthorized\s+access|suspicious\s+activity|unusual\s+login|security\s+alert)\b", re.I), 3.5),
    (re.compile(r"\b(failure\s+to\s+respond|consequences|legal\s+action|penalty|fine)\b", re.I), 2.5),
    # Credential harvest
    (re.compile(r"\b(verify\s+your\s+(identity|account|information|details))\b", re.I), 3.0),
    (re.compile(r"\b(confirm\s+your\s+password|update\s+your\s+billing|re-?validate)\b", re.I), 3.5),
    (re.compile(r"\bclick\s+(below|here|this\s+link)\s+to\s+(verify|confirm|update|secure)\b", re.I), 2.0),
    # Scarcity / time pressure
    (re.compile(r"\b(limited\s+time|expires?\s+(in|today|soon)|only\s+\d+\s+(spots?|seats?)\s+left)\b", re.I), 2.0),
    (re.compile(r"\b(you\s+have\s+\d+\s+(hours?|minutes?)\s+to)\b", re.I), 2.5),
    # Authority impersonation
    (re.compile(r"\b(from\s+(the\s+)?(irs|social\s+security\s+administration|medicare|medicaid|fbi|dea|fcc))\b", re.I), 3.0),
    # Healthcare-specific lures (relevant to Vincent's CVS / HIPAA background)
    (re.compile(r"\b(hipaa\s+violation|phi\s+breach|patient\s+data\s+exposure|insurance\s+claim\s+denied)\b", re.I), 3.5),
    (re.compile(r"\b(prescription\s+(expired|canceled)|medication\s+recall|drug\s+interaction\s+alert)\b", re.I), 3.0),
]

# ---------------------------------------------------------------------------
# Data classes
# ---------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class CategoryScore:
    """Per-category result from a single analysis pass."""

    category: str
    score: float           # 0–100
    max_possible: float      # theoretical ceiling for this category
    details: list[str] = field(default_factory=list)
    indicators: list[str] = field(default_factory=list)


@dataclass(frozen=True, slots=True)
class AnalysisResult:
    """Top-level output produced by the analyzer."""

    composite_score: float       # 0–100
    risk_level: str              # LOW / MEDIUM / HIGH / CRITICAL
    category_scores: list[CategoryScore]
    raw_headers: dict[str, str] | None = None
    extracted_urls: list[str] = field(default_factory=list)
    summary: str = ""


# ---------------------------------------------------------------------------
# String helpers
# ---------------------------------------------------------------------------


def _levenshtein(a: str, b: str) -> int:
    """Classic DP Levenshtein distance (O(n·m) but strings are short domains)."""
    if a == b:
        return 0
    if len(a) < len(b):
        a, b = b, a
    if not b:
        return len(a)

    prev = list(range(len(b) + 1))
    curr = [0] * (len(b) + 1)
    for i, ca in enumerate(a, 1):
        curr[0] = i
        for j, cb in enumerate(b, 1):
            # substitution cost
            cost = 0 if ca == cb else 1
            curr[j] = min(curr[j - 1] + 1, prev[j] + 1, prev[j - 1] + cost)
        prev, curr = curr, prev
    return prev[len(b)]


def _normalise_domain(domain: str) -> str:
    """Lower-case, strip 'www.', remove trailing dot."""
    d = domain.lower().strip().rstrip(".")
    if d.startswith("www."):
        d = d[4:]
    return d


def _extract_urls(text: str) -> list[str]:
    """
    Naïve but effective URL extraction.
    We deliberately keep the scheme so the caller can distinguish http vs https.
    """
    # Relaxed regex: captures http(s)://, ftp://, and bare domains that look
    # like they have a TLD followed by a path or query.
    pattern = re.compile(
        r"https?://[^\s\"'<>()\[\]{}]+|"
        r"ftp://[^\s\"'<>()\[\]{}]+|"
        r"(?:www\.)?[a-zA-Z0-9\-]+\.[a-zA-Z]{2,}(?:/[^\s\"'<>()\[\]{}]*)?"
    )
    return pattern.findall(text)


def _has_homoglyphs(domain: str) -> tuple[bool, list[str]]:
    """
    Detect visually-confusable Unicode characters (homoglyphs) in a domain.
    Returns (flag, list_of_offending_chars).
    """
    offenders: list[str] = []
    for ch in domain:
        cat = unicodedata.category(ch)
        name = unicodedata.name(ch, "UNKNOWN")
        # Latin-1 ASCII plus common symbols (hyphen, period) are fine.
        if cat.startswith("Lo") or cat.startswith("So") or cat.startswith("Ll") and ord(ch) > 127:
            # Extended Latin / Cyrillic / Greek lookalikes
            offenders.append(f"{ch} (U+{ord(ch):04X} {name})")
        # Specific known confusables
        if ch in "οοο":  # Greek omicron
            offenders.append(f"{ch} (Greek omicron)")
        if ch in "еЕ":  # Cyrillic ye
            offenders.append(f"{ch} (Cyrillic ye)")
        if ch in "аА":  # Cyrillic a
            offenders.append(f"{ch} (Cyrillic a)")
    # Deduplicate while preserving order
    seen = set()
    unique = []
    for o in offenders:
        if o not in seen:
            seen.add(o)
            unique.append(o)
    return bool(unique), unique


# ---------------------------------------------------------------------------
# Analyzers
# ---------------------------------------------------------------------------


class EmailHeaderAnalyzer:
    """
    Parses RFC-5322 / MIME headers and derives phishing indicators.
    We do NOT perform live DNS lookups (no external dependency) — all checks
    are heuristic or static-pattern based, making the tool fully offline-safe.
    """

    def __init__(self, heuristics: dict[str, Any]) -> None:
        self.h = heuristics.get("headers", {})
        self.max_score = float(self.h.get("max_score", 25.0))

    def analyze(self, msg: email.message.EmailMessage) -> CategoryScore:
        score = 0.0
        details: list[str] = []
        indicators: list[str] = []

        # --- 1. SPF / DKIM / DMARC hints in Authentication-Results ---
        # Convert header values to str (email.message.Message may return Header objects)
        auth_results = str(msg.get("Authentication-Results", ""))
        if auth_results:
            auth_lower = auth_results.lower()
            if "spf=fail" in auth_lower or "spf=softfail" in auth_lower:
                score += float(self.h.get("spf_fail", 4.0))
                indicators.append("SPF failure in Authentication-Results")
            if "dkim=fail" in auth_lower:
                score += float(self.h.get("dkim_fail", 3.5))
                indicators.append("DKIM failure in Authentication-Results")
            if "dmarc=fail" in auth_lower:
                score += float(self.h.get("dmarc_fail", 5.0))
                indicators.append("DMARC failure in Authentication-Results")
            if "dkim=none" in auth_lower and "spf=none" in auth_lower:
                score += float(self.h.get("no_auth", 2.0))
                indicators.append("No DKIM or SPF results present")
        else:
            # No Authentication-Results at all → can't verify sender
            score += float(self.h.get("missing_auth_results", 2.5))
            indicators.append("Missing Authentication-Results header")

        # --- 2. Reply-To vs From mismatch ---
        from_addr = self._extract_address(str(msg.get("From", "")))
        reply_to = self._extract_address(str(msg.get("Reply-To", "")))
        if reply_to and reply_to != from_addr:
            # Mismatch is a classic redirect-to-attacker technique.
            score += float(self.h.get("reply_to_mismatch", 4.0))
            indicators.append(f"Reply-To ({reply_to}) differs from From ({from_addr})")
            details.append(f"Reply-To mismatch: header says {reply_to} but From is {from_addr}")

        # --- 3. Suspicious sender domain patterns ---
        sender_domain = self._domain_from_address(from_addr)
        if sender_domain:
            # Free-mailer sending "official" notices?
            free_mailers = {"gmail.com", "yahoo.com", "hotmail.com", "outlook.com", "aol.com", "protonmail.com", "icloud.com"}
            if sender_domain in free_mailers:
                score += float(self.h.get("free_mailer_sender", 2.0))
                indicators.append(f"Sender uses free mailer: {sender_domain}")

            # Domain age can't be checked offline, but we can flag recently-registered TLDs
            # or domains with high randomness (e.g. 8+ character subdomain).
            parts = sender_domain.split(".")
            if len(parts) >= 2:
                subdomain = parts[0]
                if len(subdomain) > 12 and self._looks_random(subdomain):
                    score += float(self.h.get("random_subdomain", 3.0))
                    indicators.append(f"Suspicious random-looking subdomain: {subdomain}")

        # --- 4. Routing hop analysis (Received headers) ---
        received = msg.get_all("Received", [])
        if len(received) > 5:
            score += float(self.h.get("many_hops", 1.5))
            indicators.append(f"Unusually long routing chain ({len(received)} hops)")

        for hop in received:
            hop_l = hop.lower()
            # Mail relayed through known bullet-proof / high-risk ASNs is hard to detect
            # offline, but we can flag private IP ranges in Received headers (spoofed).
            if re.search(r"from\s+\[?(10\.|172\.(1[6-9]|2[0-9]|3[01])\.|192\.168\.)\]?", hop_l):
                score += float(self.h.get("private_ip_in_received", 2.5))
                indicators.append("Private IP address found in Received header hop")
                break  # once is enough

        # --- 5. Return-Path vs From mismatch ---
        return_path = self._extract_address(str(msg.get("Return-Path", "")))
        if return_path and return_path != from_addr:
            score += float(self.h.get("return_path_mismatch", 2.0))
            indicators.append(f"Return-Path ({return_path}) differs From ({from_addr})")

        # --- 6. Subject-line red flags ---
        subject = str(msg.get("Subject", ""))
        subject_lower = subject.lower()
        if any(w in subject_lower for w in ["invoice", "payment", "re:", "fwd:", "action required"]):
            score += float(self.h.get("subject_keyword", 1.0))
            indicators.append(f"Subject contains common lure keyword: '{subject}'")

        # --- 7. MIME structure oddities ---
        if msg.is_multipart():
            parts = list(msg.walk())
            html_parts = [p for p in parts if p.get_content_type() == "text/html"]
            text_parts = [p for p in parts if p.get_content_type() == "text/plain"]
            # Phishers often hide payload in HTML-only with no plain-text alternative
            if html_parts and not text_parts:
                score += float(self.h.get("html_only", 1.5))
                indicators.append("HTML-only email (no text/plain part)")

        score = min(score, self.max_score)
        return CategoryScore(
            category="headers",
            score=score,
            max_possible=self.max_score,
            details=details,
            indicators=indicators,
        )

    @staticmethod
    def _extract_address(header_value: str) -> str:
        """Extract bare e-mail address from 'Name <addr@domain>' or 'addr@domain'."""
        m = re.search(r"<([^>]+)>", header_value)
        if m:
            return m.group(1).lower().strip()
        # bare address
        m = re.search(r"[\w.+-]+@[\w.-]+\.\w{2,}", header_value)
        return m.group(0).lower().strip() if m else ""

    @staticmethod
    def _domain_from_address(addr: str) -> str:
        """Everything after the '@'."""
        if "@" in addr:
            return addr.split("@", 1)[1]
        return ""

    @staticmethod
    def _looks_random(s: str) -> bool:
        """Simple entropy heuristic: high ratio of consonant clusters suggests DGA / random."""
        if not s:
            return False
        vowels = set("aeiou")
        consonant_runs = 0
        max_run = 0
        cur_run = 0
        for ch in s.lower():
            if ch not in vowels and ch.isalpha():
                cur_run += 1
                max_run = max(max_run, cur_run)
            else:
                if cur_run > 2:
                    consonant_runs += 1
                cur_run = 0
        # Either many consonant clusters or one very long run
        return consonant_runs >= 3 or max_run >= 5


class URLHeuristicAnalyzer:
    """
    Examines every URL discovered in the e-mail body (and headers) for
    structural and semantic phishing indicators.
    """

    def __init__(self, heuristics: dict[str, Any]) -> None:
        self.h = heuristics.get("urls", {})
        self.max_score = float(self.h.get("max_score", 40.0))

    def analyze(self, urls: list[str]) -> CategoryScore:
        score = 0.0
        details: list[str] = []
        indicators: list[str] = []

        if not urls:
            return CategoryScore(
                category="urls",
                score=0.0,
                max_possible=self.max_score,
                details=["No URLs found in message"],
                indicators=[],
            )

        # Track which checks fired so we don't double-count the same URL
        # for the same reason, but different URLs can each contribute.
        for raw_url in urls:
            url = raw_url.strip()
            parsed = urlparse(url)
            host = parsed.netloc or parsed.path.split("/", 1)[0]
            host = _normalise_domain(host)
            if not host:
                continue

            # 1. IP-based URL (e.g. http://192.168.1.1/login)
            if re.match(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$", host):
                score += float(self.h.get("ip_based_url", 5.0))
                indicators.append(f"IP-based URL: {url}")
                details.append(f"IP-based URL detected: {url}")
                continue  # heavy indicator, move to next URL

            # 2. URL shortener
            if any(host.endswith(s) for s in URL_SHORTENERS):
                score += float(self.h.get("url_shortener", 3.5))
                indicators.append(f"URL shortener detected: {host}")
                details.append(f"Shortened URL hides final destination: {url}")

            # 3. Suspicious TLD
            tld = "." + host.rsplit(".", 1)[-1] if "." in host else ""
            if tld and tld in SUSPICIOUS_TLDS:
                score += float(self.h.get("suspicious_tld", 3.0))
                indicators.append(f"Suspicious TLD: {tld}")
                details.append(f"Domain uses high-abuse TLD: {host}")

            # 4. HTTP (not HTTPS) — weak signal but worth noting
            if url.startswith("http://"):
                score += float(self.h.get("http_not_https", 1.0))
                indicators.append(f"Unencrypted HTTP link: {url}")

            # 5. Homoglyph / confusable characters
            has_hg, hg_list = _has_homoglyphs(host)
            if has_hg:
                score += float(self.h.get("homoglyph", 5.0))
                indicators.append(f"Homoglyph characters in domain: {', '.join(hg_list)}")
                details.append(f"Domain contains visually-confusable characters: {host}")

            # 6. Lookalike domain scoring (Levenshtein distance vs known brands)
            brand_match = self._lookalike_score(host)
            if brand_match:
                brand, dist, threshold = brand_match
                score += float(self.h.get("lookalike_domain", 4.0))
                indicators.append(f"Possible lookalike of '{brand}': {host} (distance={dist})")
                details.append(
                    f"Domain '{host}' looks similar to known brand '{brand}' "
                    f"(Levenshtein distance {dist}, threshold {threshold})"
                )

            # 7. Excessive subdomains (e.g. login.secure.bank.example.com)
            subdomain_count = host.count(".") - 1  # minus root + TLD
            if subdomain_count >= 4:
                score += float(self.h.get("deep_subdomain", 1.5))
                indicators.append(f"Deep subdomain chain: {host}")

            # 8. @-symbol in URL (deprecated but still abused for credential stuffing visual tricks)
            if "@" in url:
                score += float(self.h.get("at_symbol_in_url", 2.0))
                indicators.append(f"URL contains '@' symbol: {url}")

            # 9. Port other than 80/443
            if parsed.port and parsed.port not in (80, 443):
                score += float(self.h.get("nonstandard_port", 1.5))
                indicators.append(f"Non-standard port in URL: {parsed.port}")

            # 10. Data URI scheme (phishers embed whole pages in data:text/html,...
            if url.startswith("data:"):
                score += float(self.h.get("data_uri", 4.0))
                indicators.append("Data URI scheme detected")
                details.append("Message contains a data: URI — often used to embed phishing pages inline")

        score = min(score, self.max_score)
        return CategoryScore(
            category="urls",
            score=score,
            max_possible=self.max_score,
            details=details,
            indicators=indicators,
        )

    def _lookalike_score(self, domain: str) -> tuple[str, int, int] | None:
        """
        Compare domain against HIGH_VALUE_BRANDS.  If Levenshtein distance
        is within a dynamic threshold (shorter names → tighter threshold),
        flag it as a probable typosquat / lookalike.
        """
        # strip common prefixes
        clean = domain
        for prefix in ("www.", "mail.", "secure.", "login.", "account.", "verify."):
            if clean.startswith(prefix):
                clean = clean[len(prefix):]
        # strip TLD
        clean = clean.rsplit(".", 1)[0] if "." in clean else clean

        for brand in HIGH_VALUE_BRANDS:
            dist = _levenshtein(clean, brand)
            threshold = max(2, len(brand) // 4)
            if dist <= threshold and dist > 0:  # exact match is legitimate, not lookalike
                return brand, dist, threshold
        return None


class UrgencyLanguageAnalyzer:
    """
    Scans body text for social-engineering language patterns.
    Combines:
      • Static regex patterns (high signal, no false-positives from prose)
      • Simple keyword-density heuristic for fear/urgency sentiment
    """

    def __init__(self, heuristics: dict[str, Any]) -> None:
        self.h = heuristics.get("urgency", {})
        self.max_score = float(self.h.get("max_score", 35.0))

    def analyze(self, text: str) -> CategoryScore:
        score = 0.0
        details: list[str] = []
        indicators: list[str] = []

        if not text:
            return CategoryScore(
                category="urgency",
                score=0.0,
                max_possible=self.max_score,
                details=["No body text available for analysis"],
                indicators=[],
            )

        text_lower = text.lower()

        # --- 1. Regex pattern hits ---
        pattern_hits = 0
        for pattern, weight in URGENCY_PATTERNS:
            matches = pattern.findall(text_lower)
            for m in matches:
                pattern_hits += 1
                score += weight
                # Use the actual matched text in the indicator (truncated for safety)
                matched_text = str(m) if not isinstance(m, str) else m
                matched_text = matched_text[:60]
                indicators.append(f"Urgency pattern match: '{matched_text}'")

        if pattern_hits:
            details.append(f"Matched {pattern_hits} urgency/fear language pattern(s)")

        # --- 2. Sentiment density heuristic ---
        # Count fear / urgency / threat words and normalise by word count.
        fear_words = {
            "urgent", "immediately", "alert", "warning", "suspended", "disabled",
            "terminated", "locked", "breach", "unauthorized", "suspicious", "stolen",
            "compromised", "exposed", "leaked", "violation", "penalty", "fine",
            "legal", "lawsuit", "fraud", "scam", "phishing", "hack", "hacked",
            "attack", "malware", "virus", "infected", "danger", "risk", "critical",
            "emergency", "asap", "now", "today", "expires", "deadline", "limited",
            "only", "last", "final", "notice", "alert", "attention", "important",
        }
        words = re.findall(r"[a-zA-Z']+", text_lower)
        total_words = len(words) or 1
        fear_count = sum(1 for w in words if w in fear_words)
        fear_density = fear_count / total_words

        # Score grows non-linearly with density (sigmoid-like clamp)
        density_score = min(fear_density * 200, 10.0)  # cap at 10 pts
        if density_score > 2.0:
            score += density_score
            indicators.append(
                f"High fear-word density: {fear_count}/{total_words} words ({fear_density:.2%})"
            )
            details.append(
                f"Fear/urgency keyword density = {fear_density:.2%} (threshold > 1%)"
            )

        # --- 3. ALL-CAPS shouting ---
        caps_words = re.findall(r"\b[A-Z]{4,}\b", text)
        if len(caps_words) > 3:
            score += float(self.h.get("all_caps", 2.0))
            indicators.append(f"Excessive ALL-CAPS words: {len(caps_words)} found")

        # --- 4. Excessive punctuation (e.g. "Act now!!!!!") ---
        excessive_punct = len(re.findall(r"[!?]{2,}", text))
        if excessive_punct > 2:
            score += float(self.h.get("excessive_punctuation", 1.5))
            indicators.append(f"Excessive repeated punctuation: {excessive_punct} instances")

        score = min(score, self.max_score)
        return CategoryScore(
            category="urgency",
            score=score,
            max_possible=self.max_score,
            details=details,
            indicators=indicators,
        )


# ---------------------------------------------------------------------------
# Composite scorer
# ---------------------------------------------------------------------------


class CompositeScorer:
    """
    Normalises per-category scores and maps them to an overall 0–100 scale.
    Also applies a small non-linear boost when multiple categories fire
    simultaneously (attackers tend to layer techniques).
    """

    # Risk-level thresholds
    LOW_THRESHOLD = 20.0
    MEDIUM_THRESHOLD = 35.0
    HIGH_THRESHOLD = 70.0

    def __init__(self, heuristics: dict[str, Any]) -> None:
        self.h = heuristics.get("composite", {})

    def score(self, categories: list[CategoryScore]) -> tuple[float, str]:
        if not categories:
            return 0.0, "LOW"

        raw_sum = sum(c.score for c in categories)
        max_sum = sum(c.max_possible for c in categories)

        # Base linear proportion
        base = (raw_sum / max_sum) * 100.0 if max_sum else 0.0

        # Multi-category bonus: each extra firing category adds 5% of base
        firing = sum(1 for c in categories if c.score > 0)
        bonus = base * (0.05 * max(0, firing - 1))
        composite = min(base + bonus, 100.0)

        # Hard floor/ceiling logic from config
        floor = float(self.h.get("hard_floor", 0.0))
        ceiling = float(self.h.get("hard_ceiling", 100.0))
        composite = max(floor, min(ceiling, composite))

        if composite >= self.HIGH_THRESHOLD:
            level = "CRITICAL" if composite >= 85 else "HIGH"
        elif composite >= self.MEDIUM_THRESHOLD:
            level = "MEDIUM"
        elif composite >= self.LOW_THRESHOLD:
            level = "LOW"
        else:
            level = "VERY_LOW"

        return round(composite, 2), level


# ---------------------------------------------------------------------------
# Main engine
# ---------------------------------------------------------------------------


class PhishingAnalyzer:
    """
    Orchestrates header, URL, and language analysis into a single
    composite suspicion score.
    """

    def __init__(self, config_path: str | None = None) -> None:
        self.heuristics = self._load_config(config_path)
        self.header_analyzer = EmailHeaderAnalyzer(self.heuristics)
        self.url_analyzer = URLHeuristicAnalyzer(self.heuristics)
        self.urgency_analyzer = UrgencyLanguageAnalyzer(self.heuristics)
        self.scorer = CompositeScorer(self.heuristics)

    @staticmethod
    def _load_config(config_path: str | None) -> dict[str, Any]:
        if config_path and os.path.isfile(config_path):
            with open(config_path, "r", encoding="utf-8") as fh:
                return yaml.safe_load(fh) or {}
        # Embedded fallback defaults
        return {
            "headers": {
                "max_score": 25.0,
                "spf_fail": 4.0,
                "dkim_fail": 3.5,
                "dmarc_fail": 5.0,
                "no_auth": 2.0,
                "missing_auth_results": 2.5,
                "reply_to_mismatch": 4.0,
                "free_mailer_sender": 2.0,
                "random_subdomain": 3.0,
                "many_hops": 1.5,
                "private_ip_in_received": 2.5,
                "return_path_mismatch": 2.0,
                "subject_keyword": 1.0,
                "html_only": 1.5,
            },
            "urls": {
                "max_score": 40.0,
                "ip_based_url": 5.0,
                "url_shortener": 3.5,
                "suspicious_tld": 3.0,
                "http_not_https": 1.0,
                "homoglyph": 5.0,
                "lookalike_domain": 4.0,
                "deep_subdomain": 1.5,
                "at_symbol_in_url": 2.0,
                "nonstandard_port": 1.5,
                "data_uri": 4.0,
            },
            "urgency": {
                "max_score": 35.0,
                "all_caps": 2.0,
                "excessive_punctuation": 1.5,
            },
            "composite": {
                "hard_floor": 0.0,
                "hard_ceiling": 100.0,
            },
        }

    def analyze_email(self, raw_email: str | bytes) -> AnalysisResult:
        """
        Parse a raw RFC-5322 message and run the full analysis pipeline.
        Accepts both str (for .txt fixtures) and bytes (for real .eml files).
        """
        if isinstance(raw_email, str):
            raw_email = raw_email.encode("utf-8", errors="replace")

        msg = email.message_from_bytes(raw_email)

        # Collect body text (concatenate all text/plain and text/html parts)
        body_parts: list[str] = []
        for part in msg.walk():
            content_type = part.get_content_type()
            if content_type in ("text/plain", "text/html"):
                payload = part.get_payload(decode=True)
                if payload:
                    charset = part.get_content_charset() or "utf-8"
                    try:
                        text = payload.decode(charset, errors="replace")
                    except (LookupError, UnicodeDecodeError):
                        text = payload.decode("utf-8", errors="replace")
                    body_parts.append(text)
        full_text = "\n".join(body_parts)

        # Extract every URL we can find (body + headers)
        urls = _extract_urls(full_text)
        for header_name in ("From", "Reply-To", "Return-Path", "Subject"):
            urls.extend(_extract_urls(str(msg.get(header_name, ""))))
        urls = list(dict.fromkeys(urls))  # deduplicate while preserving order

        # Run analyzers
        header_result = self.header_analyzer.analyze(msg)
        url_result = self.url_analyzer.analyze(urls)
        urgency_result = self.urgency_analyzer.analyze(full_text)

        categories = [header_result, url_result, urgency_result]
        composite, level = self.scorer.score(categories)

        # Build human-readable summary
        summary_lines = [
            f"Composite Score: {composite}/100  (Risk: {level})",
            f"Categories:",
            f"  • Headers:    {header_result.score:.1f} / {header_result.max_possible:.1f}",
            f"  • URLs:       {url_result.score:.1f} / {url_result.max_possible:.1f}",
            f"  • Urgency:    {urgency_result.score:.1f} / {urgency_result.max_possible:.1f}",
        ]
        total_indicators = sum(len(c.indicators) for c in categories)
        summary_lines.append(f"Total Indicators Found: {total_indicators}")
        if total_indicators:
            summary_lines.append("Key Indicators:")
            for cat in categories:
                for ind in cat.indicators[:5]:  # cap per category
                    summary_lines.append(f"  [{cat.category}] {ind}")

        return AnalysisResult(
            composite_score=composite,
            risk_level=level,
            category_scores=categories,
            raw_headers={k: str(v) for k, v in msg.items()},
            extracted_urls=urls,
            summary="\n".join(summary_lines),
        )

    def analyze_file(self, path: str) -> AnalysisResult:
        with open(path, "rb") as fh:
            raw = fh.read()
        return self.analyze_email(raw)


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="phishing_analyzer.py",
        description="Analyze e-mails for phishing indicators.  Offline-safe, no external API calls.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python phishing_analyzer.py email.eml
  python phishing_analyzer.py email.eml --config config/heuristics.yaml --json
  python phishing_analyzer.py --list-indicators
        """,
    )
    parser.add_argument("target", nargs="?", help="Path to .eml or .txt file")
    parser.add_argument(
        "--config", "-c", default="config/heuristics.yaml",
        help="Path to YAML heuristic configuration (default: config/heuristics.yaml)",
    )
    parser.add_argument(
        "--json", "-j", action="store_true",
        help="Emit machine-readable JSON instead of human-readable text",
    )
    parser.add_argument(
        "--list-indicators", action="store_true",
        help="Print the full indicator catalogue and exit",
    )
    parser.add_argument(
        "--score-only", action="store_true",
        help="Print only the numeric composite score (useful for scripting)",
    )
    return parser


def _serialise(result: AnalysisResult) -> dict[str, Any]:
    """Convert dataclass tree to plain dict for json.dumps."""
    return {
        "composite_score": result.composite_score,
        "risk_level": result.risk_level,
        "extracted_urls": result.extracted_urls,
        "summary": result.summary,
        "category_scores": [
            {
                "category": c.category,
                "score": c.score,
                "max_possible": c.max_possible,
                "details": c.details,
                "indicators": c.indicators,
            }
            for c in result.category_scores
        ],
    }


def _print_text(result: AnalysisResult) -> None:
    print(result.summary)
    print()
    print("-" * 60)
    print("EXTRACTED URLS")
    print("-" * 60)
    for u in result.extracted_urls:
        print(f"  • {u}")
    if not result.extracted_urls:
        print("  (none)")
    print()
    print("-" * 60)
    print("CATEGORY BREAKDOWN")
    print("-" * 60)
    for cat in result.category_scores:
        print(f"\n[{cat.category.upper()}]  Score: {cat.score:.1f} / {cat.max_possible:.1f}")
        if cat.details:
            print("  Details:")
            for d in cat.details:
                print(f"    • {d}")
        if cat.indicators:
            print("  Indicators:")
            for i in cat.indicators:
                print(f"    ⚠  {i}")
    print()
    print("-" * 60)
    print("VERDICT")
    print("-" * 60)
    verdict = (
        "LIKELY PHISHING" if result.composite_score >= 60
        else "SUSPICIOUS — review recommended" if result.composite_score >= 35
        else "LIKELY LEGITIMATE" if result.composite_score < 20
        else "INCONCLUSIVE"
    )
    print(f"  {verdict}")


def _print_indicator_catalogue() -> None:
    print("PHISHING INDICATOR CATALOGUE")
    print("=" * 60)
    print("\n--- Header Indicators ---")
    print("  • SPF failure (softfail or hard fail)")
    print("  • DKIM failure")
    print("  • DMARC failure")
    print("  • Missing Authentication-Results header")
    print("  • Reply-To mismatch against From address")
    print("  • Return-Path mismatch against From address")
    print("  • Free-mailer sender for official correspondence")
    print("  • Random-looking / DGA-style subdomain")
    print("  • Private IP in Received routing hop")
    print("  • Excessive routing hops (>5)")
    print("  • Subject contains lure keywords (invoice, payment, action required)")
    print("  • HTML-only multipart (no text/plain alternative)")
    print("\n--- URL Indicators ---")
    print("  • IP-based URL (http://1.2.3.4/...)")
    print("  • Known URL shortener (bit.ly, tinyurl, etc.)")
    print("  • Suspicious / high-abuse TLD")
    print("  • Unencrypted HTTP link")
    print("  • Homoglyph / confusable Unicode characters in domain")
    print("  • Lookalike / typosquat domain vs known brand")
    print("  • Deep subdomain chain (≥4 levels)")
    print("  • '@' symbol in URL (credential-trick syntax)")
    print("  • Non-standard port (not 80/443)")
    print("  • Data URI scheme (data:text/html,...)")
    print("\n--- Urgency / Language Indicators ---")
    print("  • Predefined fear/urgency regex patterns")
    print("  • High density of fear/threat keywords")
    print("  • Excessive ALL-CAPS shouting")
    print("  • Excessive repeated punctuation (!!!, ???)")
    print()


def main(argv: list[str] | None = None) -> int:
    parser = _build_parser()
    args = parser.parse_args(argv)

    if args.list_indicators:
        _print_indicator_catalogue()
        return 0

    if not args.target:
        parser.error("the following arguments are required: target")

    if not os.path.isfile(args.target):
        print(f"ERROR: file not found: {args.target}", file=sys.stderr)
        return 1

    analyzer = PhishingAnalyzer(config_path=args.config)
    result = analyzer.analyze_file(args.target)

    if args.score_only:
        print(result.composite_score)
        return 0

    if args.json:
        print(json.dumps(_serialise(result), indent=2))
    else:
        _print_text(result)

    return 0


if __name__ == "__main__":
    sys.exit(main())
