#!/usr/bin/env bash
# UI e2e smoke test (#49). Loads a dashboard page in headless Chrome, lets
# its scripts fetch the API and render, and checks the rendered DOM.
# Same-origin images and icons in that DOM must come back as images (#327).
#
#   lab/ui-smoke.sh URL TEXT... [--absent TEXT...]
#
# Every TEXT must appear in the rendered DOM; every TEXT after --absent
# must not. The page is retried until it matches (the first probe round
# may still be running) or the attempts run out. Read-only: it only loads
# pages. Set CHROME to pick the browser binary and UI_SMOKE_WINDOW (for
# example 1440,900) to set the window size.
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

# asset_refs lists img src and icon href values from the rendered DOM.
# Chrome may wrap a tag, so the match runs on one flattened line.
asset_refs() {
  local flat tag ref
  flat="$(tr '\n' ' ' <"$dom")"
  while IFS= read -r tag; do
    [ -n "$tag" ] || continue
    ref="$(printf '%s' "$tag" | sed -nE 's/.* src="([^"]*)".*/\1/p')"
    if [ -z "$ref" ]; then
      ref="$(printf '%s' "$tag" | sed -nE 's/.*src="([^"]*)".*/\1/p')"
    fi
    [ -n "$ref" ] && printf '%s\n' "$ref"
  done < <(printf '%s' "$flat" | grep -oE '<img[^>]*>' || true)
  while IFS= read -r tag; do
    [ -n "$tag" ] || continue
    printf '%s' "$tag" | grep -qiE 'rel="[^"]*icon' || continue
    ref="$(printf '%s' "$tag" | sed -nE 's/.*href="([^"]*)".*/\1/p')"
    [ -n "$ref" ] && printf '%s\n' "$ref"
  done < <(printf '%s' "$flat" | grep -oE '<link[^>]*>' || true)
}

# check_assets fetches each same-origin image and icon. A PNG must carry
# the PNG signature, so a 200 HTML page does not count as the logo loading.
check_assets() {
  local origin ref target code hdr body sig ct miss=0 seen=" "
  origin="$(printf '%s' "$url" | sed -E 's#^(https?://[^/?#]+).*#\1#')"
  if ! command -v curl >/dev/null 2>&1; then
    echo "ui-smoke: curl is required to check images" >&2
    return 1
  fi
  while IFS= read -r ref; do
    [ -n "$ref" ] || continue
    case "$seen" in *" $ref "*) continue ;; esac
    seen="$seen$ref "
    case "$ref" in
      //*) echo "ui-smoke: protocol-relative image: $ref" >&2; miss=1; continue ;;
      http://*|https://*) target="$ref" ;;
      /*) target="${origin}${ref}" ;;
      *) echo "ui-smoke: image path is not rooted: $ref" >&2; miss=1; continue ;;
    esac
    hdr="$(mktemp)"
    body="$(mktemp)"
    code="$(curl -sS --max-time 15 -o "$body" -D "$hdr" -w '%{http_code}' "$target" || true)"
    ct="$(tr -d '\r' <"$hdr" | awk '{
      line = tolower($0)
      if (line ~ /^content-type:/) { split(line, a, /[ \t]+/); print a[2]; exit }
    }')"
    if [ "$code" != "200" ] || [[ "$ct" != image/* ]]; then
      echo "ui-smoke: $ref did not load ($code ${ct:-no content-type})" >&2
      miss=1
    elif [[ "$ref" == *.png || "$ref" == *.png\?* ]]; then
      sig="$(od -An -tx1 -N 8 "$body" | tr -d ' \n')"
      if [ "$sig" != "89504e470d0a1a0a" ]; then
        echo "ui-smoke: $ref is not a PNG" >&2
        miss=1
      fi
    fi
    rm -f "$hdr" "$body"
  done < <(asset_refs)
  return "$miss"
}

for attempt in $(seq 1 "${UI_SMOKE_ATTEMPTS:-10}"); do
  timeout 60 "$chrome" --headless=new --no-sandbox --disable-gpu --disable-extensions \
    --no-first-run --user-data-dir="$profile" --virtual-time-budget=8000 \
    ${UI_SMOKE_WINDOW:+--window-size="$UI_SMOKE_WINDOW"} \
    --dump-dom "$url" >"$dom" 2>/dev/null || true
  if check && check_assets; then
    echo "ui-smoke: ok: $url (attempt $attempt)"
    exit 0
  fi
  sleep 2
done
echo "ui-smoke: rendered DOM of $url:" >&2
cat "$dom" >&2
exit 1
