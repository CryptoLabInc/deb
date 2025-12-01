#!/bin/bash

set -euo pipefail

REMOVE_PATHS=(
  ".github/workflows/"
)
TARGET_PRESET="CMakePresets.json"

PROJECT_ROOT="$(dirname "${BASH_SOURCE[0]}")/.."
cd "$PROJECT_ROOT"


# check current branch
CURRENT_BRANCH=$(git rev-parse --abbrev-ref HEAD)
if [[ "$CURRENT_BRANCH" != oss-release* ]]; then
    echo "This branch is not for oss-release: $CURRENT_BRANCH"
    exit 1
fi

# check working tree clean
if [[ -n "$(git status --porcelain)" ]]; then
  echo "Working tree is not clean. Please commit or stash your changes."
  exit 1
fi

for path in "${REMOVE_PATHS[@]}"; do
  if [[ -e "$path" ]]; then
    echo "  - removing $path"
    # If the file is tracked by git, use git rm, otherwise just rm
    if git ls-files --error-unmatch "$path" >/dev/null 2>&1; then
      git rm -r "$path"
    else
      rm -rf "$path"
    fi
  else
    echo "  - $path (already removed)"
  fi
done

# Update CMakePresets.json
if [[ -f "$TARGET_PRESET" ]]; then
  # remove ci presets
  jq '
    .configurePresets |= map(select(.name | contains("ci") | not)) |
    .buildPresets     |= map(select(.name | contains("ci") | not)) |
    .testPresets      |= map(
      if .configurePreset == "ci"
        then .configurePreset = "release"
      else .
      end)
  ' "$TARGET_PRESET" > "${TARGET_PRESET}.tmp" && mv "${TARGET_PRESET}.tmp" "$TARGET_PRESET"
fi
