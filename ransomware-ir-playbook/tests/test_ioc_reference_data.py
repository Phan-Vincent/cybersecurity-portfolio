"""Shape checks for data/known_ransomware_iocs.json (sourced CISA indicators)."""

import ipaddress
import json
import re
from pathlib import Path

DATA = json.loads((Path(__file__).resolve().parent.parent / "data" / "known_ransomware_iocs.json").read_text())
FAMILIES = DATA["ransomware_families"]


def test_every_family_cites_a_cisa_advisory():
    for f in FAMILIES:
        adv = f["source_advisory"]
        assert re.fullmatch(r"AA\d{2}-\d{3}A", adv["id"])
        assert adv["url"].startswith("https://www.cisa.gov/") and adv["id"].lower() in adv["url"]


def test_hashes_are_sha256_and_tagged_with_their_advisory():
    for f in FAMILIES:
        for h in f["known_sha256_hashes"]:
            assert re.fullmatch(r"[0-9a-f]{64}", h["hash"])
            assert h["source"] == f["source_advisory"]["id"]


def test_ips_and_domains_are_refanged_and_valid():
    for f in FAMILIES:
        for ip in f["c2_ips"]:
            ipaddress.ip_address(ip)
        for dom in f["c2_domains"]:
            assert "[" not in dom and re.fullmatch(r"[a-z0-9.-]+\.[a-z]{2,}", dom)


def test_no_duplicate_indicators_within_a_family():
    for f in FAMILIES:
        for key in ("c2_ips", "c2_domains"):
            assert len(f[key]) == len(set(f[key]))
        hashes = [h["hash"] for h in f["known_sha256_hashes"]]
        assert len(hashes) == len(set(hashes))


def test_attack_ids_are_well_formed():
    for f in FAMILIES:
        for t in f["mitre_techniques"]:
            assert re.fullmatch(r"T\d{4}(\.\d{3})?", t["technique_id"])
