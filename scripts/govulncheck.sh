#!/bin/sh
# Runs govulncheck and fails on any finding whose ID is not listed in
# .govulncheck-ignore (one "GO-YYYY-NNNN reason" per line).
set -u
out="$(govulncheck ./... 2>&1)"; rc=$?
printf '%s\n' "$out" | tail -n 40
[ "$rc" -eq 0 ] && exit 0
ids="$(printf '%s\n' "$out" | sed -n 's/^Vulnerability #[0-9]*: \(GO-[0-9-]*\).*/\1/p')"
[ -z "$ids" ] && { echo "govulncheck failed without findings"; exit "$rc"; }
bad=0
for id in $ids; do
  grep -q "^$id\b" .govulncheck-ignore 2>/dev/null || { echo "unaccepted vulnerability: $id"; bad=1; }
done
exit $bad
