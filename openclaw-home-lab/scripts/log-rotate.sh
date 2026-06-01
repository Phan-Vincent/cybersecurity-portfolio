#!/usr/bin/env bash
#
# log-rotate.sh — Rotate and compress OpenClaw gateway logs
#
# Keeps ~/Library/Logs/openclaw/ from growing unbounded. Runs weekly via cron.
# Safe to run manually; dry-run mode available.
#
# Usage:
#   bash log-rotate.sh         # Live rotation
#   bash log-rotate.sh --dry-run # Preview only
#
# Author: Vincent Phan
# License: MIT

set -euo pipefail

LOG_DIR="${HOME}/Library/Logs/openclaw"
ARCHIVE_DIR="${LOG_DIR}/archive"
RETENTION_DAYS=30
MAX_SIZE_MB=100
DRY_RUN=false

# Parse args
for arg in "$@"; do
    if [[ "$arg" == "--dry-run" ]]; then
        DRY_RUN=true
    fi
done

log() {
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] $*"
}

if [[ ! -d "$LOG_DIR" ]]; then
    log "Log directory does not exist: $LOG_DIR"
    exit 0
fi

mkdir -p "$ARCHIVE_DIR"

# Find logs older than 7 days or larger than MAX_SIZE_MB
find "$LOG_DIR" -maxdepth 1 -type f -name "*.log" | while read -r f; do
    size_mb=$(du -m "$f" | cut -f1)
    mtime_days=$(( ($(date +%s) - $(stat -f%m "$f")) / 86400 ))

    should_rotate=false
    reason=""

    if [[ "$mtime_days" -ge 7 ]]; then
        should_rotate=true
        reason="age=${mtime_days}d"
    fi

    if [[ "$size_mb" -ge "$MAX_SIZE_MB" ]]; then
        should_rotate=true
        reason="size=${size_mb}MB"
    fi

    if [[ "$should_rotate" == true ]]; then
        basename=$(basename "$f")
        archive_name="${ARCHIVE_DIR}/${basename%.log}-$(date +%Y%m%d_%H%M%S).log.gz"

        if [[ "$DRY_RUN" == true ]]; then
            log "[DRY-RUN] Would rotate: $f ($reason) -> $archive_name"
        else
            log "Rotating: $f ($reason) -> $archive_name"
            gzip -c "$f" > "$archive_name"
            : > "$f"  # Truncate original
            log "Rotated successfully"
        fi
    fi
done

# Clean archives older than RETENTION_DAYS
find "$ARCHIVE_DIR" -type f -mtime +"$RETENTION_DAYS" | while read -r f; do
    if [[ "$DRY_RUN" == true ]]; then
        log "[DRY-RUN] Would delete old archive: $f"
    else
        log "Deleting old archive: $f"
        rm -f "$f"
    fi
done

# Disk usage summary
used_kb=$(du -sk "$LOG_DIR" | cut -f1)
used_mb=$((used_kb / 1024))
log "Log directory usage: ${used_mb}MB"

if [[ "$DRY_RUN" == true ]]; then
    log "Dry run complete. No changes made."
else
    log "Rotation complete."
fi
