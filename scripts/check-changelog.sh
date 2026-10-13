#!/bin/sh
# CHANGELOG entries are one line of at most 200 characters; details belong in
# the PR body or docs/.
bad="$(awk '/^- / && length > 200 {print FILENAME ":" NR ": " length " chars"}' "${1:-CHANGELOG.md}")"
if [ -n "$bad" ]; then
  echo "CHANGELOG entries over 200 characters:"
  echo "$bad"
  exit 1
fi
