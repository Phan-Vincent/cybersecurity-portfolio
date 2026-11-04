"""
export_queries.py
Converts the Sigma rules into SIEM queries with the official toolchain (sigma-cli /
pySigma), so the rules are shown to work outside this lab's evaluator:

- queries/splunk/savedsearches.conf  one Splunk saved search per alerting rule
- queries/esql/<rule>.esql           one Elastic ES|QL query per alerting rule

    pip install -r requirements-sigma.txt
    python src/export_queries.py            # rewrite queries/
    python src/export_queries.py --check    # exit 1 if queries/ is out of date (CI)

No field-mapping pipeline is applied: the queries use the rules' own field names,
so a deployment would add its SIEM's field mapping as a pySigma pipeline.
"""

from __future__ import annotations

import argparse
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))
from sigma_lite import load_rules  # noqa: E402

ROOT = Path(__file__).resolve().parent.parent
RULES = ROOT / "rules"
QUERIES = ROOT / "queries"


def sigma(*args: str) -> str:
    result = subprocess.run(["sigma", "convert", "--without-pipeline", *args],
                            capture_output=True, text=True)
    if result.returncode != 0:
        sys.exit(f"sigma convert failed:\n{result.stderr}")
    return result.stdout


def sort_stanzas(conf: str) -> str:
    """Order saved searches by title. sigma-cli emits them in directory-listing order,
    which differs between filesystems, so sorting keeps the export reproducible."""
    blocks = [b.strip("\n") for b in conf.split("\n\n") if b.strip()]
    head = [b for b in blocks if b.startswith("[default]")]
    rest = sorted((b for b in blocks if not b.startswith("[default]")), key=lambda b: b.split("\n", 1)[0])
    return "\n\n".join(head + rest) + "\n"


def build() -> dict[str, str]:
    """Return {relative path: content} for every generated query file."""
    rules = load_rules(RULES)
    by_ref = {r.name: r for r in rules} | {r.id: r for r in rules}
    out = {}
    with tempfile.TemporaryDirectory() as tmp:
        conf = Path(tmp) / "savedsearches.conf"
        sigma("-t", "splunk", "-f", "savedsearches", "-o", str(conf), str(RULES))
        out["splunk/savedsearches.conf"] = sort_stanzas(conf.read_text(encoding="utf-8"))
    for rule in sorted(rules, key=lambda r: r.name):
        if rule.level == "informational":
            continue  # building blocks: converted as part of their correlation
        # sigma-cli parses each file argument on its own, so a correlation and the base
        # rules it references are converted together from one directory.
        with tempfile.TemporaryDirectory() as tmp:
            refs = rule.data["correlation"]["rules"] if rule.is_correlation else []
            for path in [rule.path] + [by_ref[ref].path for ref in refs]:
                shutil.copy(path, tmp)
            query = sigma("-t", "esql", tmp).strip()
        out[f"esql/{rule.name}.esql"] = f"// {rule.title} ({rule.id})\n{query}\n"
    return out


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description="Convert the Sigma rules to Splunk and ES|QL")
    parser.add_argument("--check", action="store_true", help="fail if queries/ is out of date")
    args = parser.parse_args(argv)
    generated = build()
    current = {str(p.relative_to(QUERIES)): p.read_text(encoding="utf-8")
               for p in QUERIES.rglob("*") if p.is_file()} if QUERIES.exists() else {}
    if args.check:
        stale = sorted(set(generated) ^ set(current) | {k for k in generated if current.get(k) != generated[k]})
        if stale:
            print("queries/ is out of date; run python src/export_queries.py:\n  " + "\n  ".join(stale))
            return 1
        print(f"queries/ is up to date ({len(generated)} files)")
        return 0
    for path in set(current) - set(generated):
        (QUERIES / path).unlink()
    for path, text in generated.items():
        (QUERIES / path).parent.mkdir(parents=True, exist_ok=True)
        (QUERIES / path).write_text(text, encoding="utf-8")
    print(f"wrote {len(generated)} files to queries/")
    return 0


if __name__ == "__main__":
    sys.exit(main())
