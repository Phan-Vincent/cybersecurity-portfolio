#!/usr/bin/env python3
"""
healthcheck.py — OpenClaw Home Lab System Health Monitor

A lightweight, dependency-free health checker that assesses the status of
critical services, system resources, and automation jobs. Outputs structured
JSON suitable for log ingestion or Discord alerting.

Usage:
    python3 healthcheck.py              # Live check against real system
    python3 healthcheck.py --demo       # Synthetic demo output (safe, no PII)

Author: Vincent Phan
License: MIT
"""

import json
import os
import shutil
import subprocess
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

HOME = Path.home()
WORKSPACE = HOME / ".openclaw" / "workspace"
LOG_DIR = HOME / "Library" / "Logs" / "openclaw"
GATEWAY_URL = "ws://127.0.0.1:18789"

# Alert thresholds
DISK_WARNING_PCT = 90.0
DISK_CRITICAL_PCT = 95.0
MEM_WARNING_PCT = 85.0
MEM_CRITICAL_PCT = 95.0

# Critical services to check
SERVICES = [
    {"name": "openclaw-gateway", "type": "process", "pattern": "openclaw gateway"},
    {"name": "cron-scheduler", "type": "cron", "command": "openclaw cron list"},
]

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def run(cmd: list[str], timeout: int = 10) -> tuple[int, str, str]:
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        return proc.returncode, proc.stdout, proc.stderr
    except subprocess.TimeoutExpired:
        return -1, "", "timeout"
    except FileNotFoundError:
        return -2, "", "command not found"


def disk_usage(path: Path) -> dict:
    total, used, free = shutil.disk_usage(path)
    pct = (used / total) * 100 if total else 0.0
    return {
        "total_gb": round(total / (1024 ** 3), 2),
        "used_gb": round(used / (1024 ** 3), 2),
        "free_gb": round(free / (1024 ** 3), 2),
        "used_pct": round(pct, 2),
        "status": _threshold_status(pct, DISK_WARNING_PCT, DISK_CRITICAL_PCT),
    }


def memory_usage() -> dict:
    # macOS vm_statistics — lightweight, no third-party deps
    rc, out, err = run(["vm_stat"], timeout=5)
    if rc != 0:
        return {"status": "unknown", "error": err}

    # Parse vm_stat output (page size is typically 4096 bytes on Apple Silicon)
    pages = {}
    for line in out.splitlines():
        if ":" in line:
            key, val = line.split(":", 1)
            try:
                pages[key.strip()] = int(val.strip().replace(".", ""))
            except ValueError:
                pass

    page_size = 4096
    free_pages = pages.get("Pages free", 0)
    active_pages = pages.get("Pages active", 0)
    inactive_pages = pages.get("Pages inactive", 0)
    speculative_pages = pages.get("Pages speculative", 0)
    wired_pages = pages.get("Pages wired down", 0)
    compressed_pages = pages.get("Pages occupied by compressor", 0)

    used = (active_pages + inactive_pages + speculative_pages + wired_pages + compressed_pages) * page_size
    free = free_pages * page_size
    total = used + free
    pct = (used / total) * 100 if total else 0.0

    return {
        "total_gb": round(total / (1024 ** 3), 2),
        "used_gb": round(used / (1024 ** 3), 2),
        "free_gb": round(free / (1024 ** 3), 2),
        "used_pct": round(pct, 2),
        "status": _threshold_status(pct, MEM_WARNING_PCT, MEM_CRITICAL_PCT),
    }


def _threshold_status(value: float, warn: float, crit: float) -> str:
    if value >= crit:
        return "critical"
    if value >= warn:
        return "warning"
    return "ok"


def check_process(pattern: str) -> dict:
    rc, out, _ = run(["pgrep", "-f", pattern], timeout=5)
    return {
        "running": rc == 0,
        "pids": [int(p) for p in out.strip().splitlines()] if rc == 0 else [],
    }


def check_cron() -> dict:
    rc, out, err = run(["openclaw", "cron", "list"], timeout=15)
    if rc != 0:
        return {"status": "error", "error": err or out}

    # Very lightweight parse: count total, enabled, and look for recent errors
    total = 0
    enabled = 0
    for line in out.splitlines():
        if line.strip().startswith("-") or not line.strip():
            continue
        if line.strip().startswith("ID"):
            continue
        total += 1
        # crude: look for 'true' in enabled column (simplified)
        if "true" in line.lower():
            enabled += 1

    return {
        "status": "ok",
        "total_jobs": total,
        "enabled_jobs": enabled,
    }


def recent_log_errors(log_dir: Path, minutes: int = 60) -> list[dict]:
    """Scan recent log files for ERROR or CRITICAL lines."""
    errors = []
    if not log_dir.exists():
        return errors

    cutoff = time.time() - (minutes * 60)
    for fpath in log_dir.glob("*.log"):
        try:
            mtime = fpath.stat().st_mtime
            if mtime < cutoff:
                continue
            with fpath.open("r", errors="ignore") as fh:
                for i, line in enumerate(fh, 1):
                    if "ERROR" in line or "CRITICAL" in line:
                        errors.append({
                            "file": fpath.name,
                            "line": i,
                            "snippet": line.strip()[:200],
                        })
        except (OSError, PermissionError):
            continue
    return errors


def check_gateway_port() -> dict:
    rc, out, _ = run(["lsof", "-i", ":18789"], timeout=5)
    return {
        "listening": rc == 0 and "LISTEN" in out,
        "detail": out.strip().splitlines()[0] if rc == 0 and out else None,
    }


# ---------------------------------------------------------------------------
# Synthetic demo data (no PII, safe for public sharing)
# ---------------------------------------------------------------------------

DEMO_REPORT = {
    "generated_at": "2026-06-01T07:48:00+00:00",
    "host": "macbook-pro-demo",
    "version": "1.0.0",
    "overall_status": "warning",
    "checks": {
        "gateway": {
            "listening": True,
            "port": 18789,
            "protocol": "ws",
            "bind": "127.0.0.1",
        },
        "disk": {
            "total_gb": 499.96,
            "used_gb": 445.23,
            "free_gb": 54.73,
            "used_pct": 89.05,
            "status": "warning",
        },
        "memory": {
            "total_gb": 16.0,
            "used_gb": 12.8,
            "free_gb": 3.2,
            "used_pct": 80.0,
            "status": "ok",
        },
        "services": [
            {"name": "openclaw-gateway", "running": True, "pids": [12345]},
            {"name": "cron-scheduler", "status": "ok", "total_jobs": 29, "enabled_jobs": 29},
        ],
        "recent_errors": [
            {
                "file": "gateway.log",
                "line": 4821,
                "snippet": "2026-06-01 00:12:34 ERROR Subagent announce give up (retry-limit)",
            },
            {
                "file": "gateway.log",
                "line": 4933,
                "snippet": "2026-06-01 00:15:01 ERROR Cron job 'morning-habits' failed: gateway restart during run",
            },
        ],
        "secrets_audit": {
            "last_run": "2026-05-31T22:00:00+00:00",
            "files_scanned": 142,
            "findings": 0,
            "status": "ok",
        },
    },
    "recommendations": [
        "Disk usage at 89% — run log-rotate.sh and review ~/Library/Logs/openclaw/",
        "Gateway restart caused 2 cron failures — investigate root cause in gateway.log",
        "Consider enabling DNS over HTTPS for additional privacy hardening",
    ],
}


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------


def live_check() -> dict:
    disk = disk_usage(HOME)
    mem = memory_usage()
    gw = check_gateway_port()
    svc_results = []

    for svc in SERVICES:
        if svc["type"] == "process":
            svc_results.append({
                "name": svc["name"],
                **check_process(svc["pattern"]),
            })
        elif svc["type"] == "cron":
            svc_results.append({
                "name": svc["name"],
                **check_cron(),
            })

    errors = recent_log_errors(LOG_DIR, minutes=60)

    # Determine overall status
    statuses = [disk["status"], mem["status"]]
    if gw["listening"]:
        statuses.append("ok")
    else:
        statuses.append("critical")
    if errors:
        statuses.append("warning")

    overall = "ok"
    if "critical" in statuses:
        overall = "critical"
    elif "warning" in statuses:
        overall = "warning"

    report = {
        "generated_at": now_iso(),
        "host": os.uname().nodename,
        "version": "1.0.0",
        "overall_status": overall,
        "checks": {
            "gateway": gw,
            "disk": disk,
            "memory": mem,
            "services": svc_results,
            "recent_errors": errors,
            "secrets_audit": {
                "note": "Run secrets-audit.py separately for full results",
                "status": "pending",
            },
        },
        "recommendations": _recommendations(disk, mem, gw, errors),
    }
    return report


def _recommendations(disk, mem, gw, errors) -> list[str]:
    recs = []
    if disk["status"] != "ok":
        recs.append(f"Disk usage at {disk['used_pct']}% — run log-rotate.sh")
    if mem["status"] != "ok":
        recs.append(f"Memory usage at {mem['used_pct']}% — consider reducing subagent concurrency")
    if not gw["listening"]:
        recs.append("Gateway not listening on 127.0.0.1:18789 — check if process is running")
    if errors:
        recs.append(f"Found {len(errors)} recent error(s) in logs — review gateway.log")
    if not recs:
        recs.append("All checks nominal. No action required.")
    return recs


def main():
    demo_mode = "--demo" in sys.argv

    if demo_mode:
        report = DEMO_REPORT
    else:
        report = live_check()

    # Pretty-print JSON
    print(json.dumps(report, indent=2))

    # Exit non-zero if critical
    if report.get("overall_status") == "critical":
        sys.exit(2)
    if report.get("overall_status") == "warning":
        sys.exit(1)
    sys.exit(0)


if __name__ == "__main__":
    main()
