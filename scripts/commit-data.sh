#!/usr/bin/env bash
# Commit data/ changes as the bot and push, rebasing over any data commit
# pushed meanwhile (the collect and translate jobs both write data/).
set -euo pipefail
msg="${1:?commit message prefix required}"
if [ -z "$(git status --porcelain data)" ]; then
  echo "No data changes."
  exit 0
fi
git config user.name  "threat-radar-bot"
git config user.email "threat-radar-bot@users.noreply.github.com"
git add data
git commit -m "$msg $(date -u +%Y-%m-%dT%H:%MZ)"
# data/ is regenerated in full by this job, so on a conflict its own version
# wins (-X theirs keeps the commit being replayed). A failed rebase is
# aborted before the next attempt so it cannot block the retry.
for attempt in 1 2 3; do
  if git pull --rebase -X theirs --quiet && git push --quiet; then
    exit 0
  fi
  git rebase --abort 2>/dev/null || true
  echo "push attempt $attempt failed; retrying" >&2
  sleep 5
done
exit 1
