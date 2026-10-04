"""Offline IOC matching (check_iocs.py) against the embedded demo database."""

import check_iocs as ioc

DB = ioc.DEFAULT_IOC_DB
KNOWN_HASH = next(iter(DB["file_hashes"]["sha256"]))


def test_exact_hash_match_case_insensitive():
    m = ioc.check_hashes([KNOWN_HASH.upper()], DB)
    assert len(m) == 1 and m[0]["match_type"] == "exact"


def test_prefix_collision_is_weak_evidence():
    near = KNOWN_HASH[:8] + "0" * 56
    m = ioc.check_hashes([near], DB)
    assert m and m[0]["match_type"] == "partial_prefix" and m[0]["confidence"] < 0.5


def test_unknown_hash_no_match():
    assert ioc.check_hashes(["f" * 64], DB) == []


def test_validators():
    assert ioc.is_valid_sha256("a" * 64)
    assert not ioc.is_valid_sha256("a" * 63)
    assert ioc.is_valid_ip("203.0.113.77") and ioc.is_valid_ip("2001:db8::1")
    assert not ioc.is_valid_ip("999.1.1.1")
    assert ioc.is_valid_domain("example-pharmacy.com")
    assert not ioc.is_valid_domain("not a domain")


def test_confidence_levels():
    assert ioc.calculate_overall_confidence([]) == (0.0, "NONE")
    exact = ioc.check_hashes([KNOWN_HASH], DB)
    score, level = ioc.calculate_overall_confidence(exact)
    assert score >= 0.9 and level == "CRITICAL"
    weak = ioc.check_hashes([KNOWN_HASH[:8] + "0" * 56], DB)
    assert ioc.calculate_overall_confidence(weak) == (0.0, "NONE")


def test_embedded_db_is_labelled_fabricated():
    assert "FABRICATED" in DB["metadata"]["disclaimer"]
