#!/bin/sh
# Markdown files (README.md, CHANGELOG.md, and every *.md under docs/) are
# plain printable ASCII: no smart quotes, dashes, arrows, or box characters.
# Tabs are allowed. Other files under docs/ (images, YAML) are not checked.
# Portable: POSIX grep in the C locale, no grep -P, so it runs on macOS too.
tab="$(printf '\t')"
bad="$(LC_ALL=C grep -rn "[^${tab} -~]" README.md CHANGELOG.md docs --include='*.md')"
if [ -n "$bad" ]; then
  echo "non-ASCII characters in documentation:"
  echo "$bad" | cut -c1-120
  exit 1
fi
