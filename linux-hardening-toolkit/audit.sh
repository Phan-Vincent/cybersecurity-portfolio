#!/usr/bin/env bash
###############################################################################
# audit.sh — Read-only audit entrypoint
# Thin wrapper so the safe path is also the obvious one: it always runs
# harden.sh in --audit mode and refuses --harden.
###############################################################################

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

for arg in "$@"; do
    if [[ "${arg}" == "--harden" || "${arg}" == "--auto" || "${arg}" == "--key-auth" ]]; then
        echo "audit.sh is read-only; use harden.sh ${arg} to make changes." >&2
        exit 2
    fi
done

exec "${SCRIPT_DIR}/harden.sh" --audit "$@"
