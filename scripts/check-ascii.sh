#!/bin/sh
# README, CHANGELOG, and docs/ are plain ASCII: no smart quotes, dashes,
# arrows, or box characters.
bad="$(grep -rnP '[^\x00-\x7F]' README.md CHANGELOG.md docs --include='*.md')"
if [ -n "$bad" ]; then
  echo "non-ASCII characters in documentation:"
  echo "$bad" | cut -c1-120
  exit 1
fi
