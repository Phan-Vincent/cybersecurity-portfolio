#!/usr/bin/env bash
#
# backup.sh — Git-based workspace backup
#
# Backs up automation configs, scripts, docs, and cron definitions to a private
# GitHub repo. Excludes data files, secrets, and large binaries.
#
# Usage:
#   bash backup.sh           # Live backup (pushes to origin)
#   bash backup.sh --dry-run # Preview what would be committed
#
# Author: Vincent Phan
# License: MIT

set -euo pipefail

WORKSPACE="${HOME}/.openclaw/workspace"
REPO_URL="git@github.com:Phan-Vincent/workspace-backup.git"
DRY_RUN=false

for arg in "$@"; do
    if [[ "$arg" == "--dry-run" ]]; then
        DRY_RUN=true
    fi
done

log() {
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] $*"
}

cd "$WORKSPACE" || { log "Cannot cd to $WORKSPACE"; exit 1; }

# Verify we're in the right repo
if ! git remote -v | grep -q "workspace-backup"; then
    log "Warning: remote 'workspace-backup' not found. Checking configured remotes:"
    git remote -v
    exit 1
fi

# Check for uncommitted changes
if git diff --quiet && git diff --cached --quiet; then
    log "No changes to commit."
    exit 0
fi

# Dry-run: show status
if [[ "$DRY_RUN" == true ]]; then
    log "[DRY-RUN] Changes to be committed:"
    git status --short
    log "[DRY-RUN] Would commit with message: 'Backup $(date +%Y-%m-%d_%H:%M:%S)'"
    log "[DRY-RUN] Would push to origin master"
    exit 0
fi

# Add all (gitignore handles exclusions)
git add -A

# Commit with timestamp
COMMIT_MSG="Backup $(date +%Y-%m-%d_%H:%M:%S)"
git commit -m "$COMMIT_MSG" || { log "Commit failed"; exit 1; }

# Push
if git push origin master; then
    log "Backup complete: $COMMIT_MSG"
else
    log "Push failed. Check network or SSH key."
    exit 1
fi
