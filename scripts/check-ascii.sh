#!/bin/sh
# Tracked source, scripts, workflows, configs, and documentation are plain
# printable ASCII: no smart quotes, dashes, arrows, or box characters. Tabs are
# allowed. The web UI under internal/httpapi/web/ is exempt: it renders
# non-ASCII text, and the UI smoke tests in ci.yml match it by byte escape.
# Portable: POSIX grep in the C locale, no grep -P, so it runs on macOS too.
tab="$(printf '\t')"
bad="$(git ls-files -z -- '*.go' '*.md' '*.yml' '*.yaml' '*.sh' '*.tmpl' '*.conf' '*.toml' '*.proto' '*.txt' Makefile Dockerfile ':(exclude)internal/httpapi/web' |
  LC_ALL=C xargs -0 grep -n "[^${tab} -~]" /dev/null)"
if [ -n "$bad" ]; then
  echo "non-ASCII characters in tracked files:"
  echo "$bad" | cut -c1-120
  exit 1
fi
