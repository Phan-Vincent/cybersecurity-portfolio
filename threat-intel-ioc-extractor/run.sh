#!/usr/bin/env bash
# run.sh - Convenience script to run the IOC extractor in sample/demo mode.
set -euo pipefail

cd "$(dirname "$0")"
python3 -m src.cli --samples --output-dir ./output --format both
