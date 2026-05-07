#!/bin/bash
# Purge sensitive files from git history using git-filter-repo
# Requires: git-filter-repo installed (https://github.com/newren/git-filter-repo)
# WARNING: This rewrites history; coordinate with collaborators before running.

set -euo pipefail

# Files/paths to remove from history
FILES=("database/" "backups/" "ver_licencas.py" "*check*.html" ".env" "*.db")

echo "This will rewrite git history and force-push to origin/main. Continue? (y/N)"
read ans
if [[ "$ans" != "y" ]]; then
  echo "Aborting."
  exit 1
fi

# Create a backup branch
git branch backup-before-purge

# Build arguments for git-filter-repo
args=(--invert-paths)
for f in "${FILES[@]}"; do
  args+=(--paths "$f")
done

# Run git-filter-repo
git filter-repo "${args[@]}"

# Force push
git push origin --force --all
git push origin --force --tags

echo "Purge complete. Inform collaborators to reclone the repo." 
