#!/usr/bin/env bash
# UI e2e smoke test (#49). Loads a dashboard page in headless Chrome, lets
# its scripts fetch the API and render, and checks the rendered DOM.
#
#   lab/ui-smoke.sh URL TEXT... [--absent TEXT...]
#
# Every TEXT must appear in the rendered DOM; every TEXT after --absent
# must not. The page is retried until it matches (the first probe round
# may still be running) or the attempts run out. Read-only: it only loads
# pages. Set CHROME to pick the browser binary.
set -euo pipefail

url="${1:?usage: ui-smoke.sh URL TEXT... [--absent TEXT...]}"
shift
want=()
absent=()
mode=want
for a in "$@"; do
  if [ "$a" = "--absent" ]; then mode=absent; continue; fi
  if [ "$mode" = want ]; then want+=("$a"); else absent+=("$a"); fi
done

chrome="${CHROME:-}"
if [ -z "$chrome" ]; then
  for c in google-chrome google-chrome-stable chromium chromium-browser; do
    if command -v "$c" >/dev/null 2>&1; then chrome="$c"; break; fi
  done
fi
if [ -z "$chrome" ]; then echo "ui-smoke: no Chrome or Chromium found" >&2; exit 1; fi

dom="$(mktemp)"
profile="$(mktemp -d)"
trap 'rm -rf "$dom" "$profile"' EXIT

check() {
  local miss=0
  for t in "${want[@]}"; do
    if ! grep -qF -- "$t" "$dom"; then echo "ui-smoke: missing: $t" >&2; miss=1; fi
  done
  for t in "${absent[@]}"; do
    if grep -qF -- "$t" "$dom"; then echo "ui-smoke: unexpected: $t" >&2; miss=1; fi
  done
  return "$miss"
}

for attempt in $(seq 1 "${UI_SMOKE_ATTEMPTS:-10}"); do
  timeout 60 "$chrome" --headless=new --no-sandbox --disable-gpu --disable-extensions \
    --no-first-run --user-data-dir="$profile" --virtual-time-budget=8000 \
    --dump-dom "$url" >"$dom" 2>/dev/null || true
  if check; then
    echo "ui-smoke: ok: $url (attempt $attempt)"
    exit 0
  fi
  sleep 2
done
echo "ui-smoke: rendered DOM of $url:" >&2
cat "$dom" >&2
exit 1
