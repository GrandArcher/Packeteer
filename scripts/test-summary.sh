#!/bin/sh
# go test with a skip summary at the end. Root-only socket tests and the UI
# page tests (they need node) skip silently, so a green run can leave those
# paths untested; CI runs them. A passing package prints one line, a failing
# package prints everything it said, and the exit status is go test's.
# Arguments are package patterns; the default is ./...
[ $# -eq 0 ] && set -- ./...
log="$(mktemp)" || exit 1
trap 'rm -f "$log"' EXIT
go test -v "$@" >"$log" 2>&1
status=$?
awk '
/^(ok|FAIL|\?)[ ]*\t/ {
	if ($1 == "FAIL") printf "%s", buf
	print
	for (i = 1; i <= n; i++) lines[++total] = "  " $2 ": " names[i] ": " reasons[i]
	n = 0; buf = ""
	next
}
{
	buf = buf $0 "\n"
	if ($0 ~ /^ *--- SKIP: /) {
		r = prev
		sub(/^[ \t]+/, "", r)
		sub(/^[^ ]+:[0-9]+: /, "", r)
		n++; names[n] = $3; reasons[n] = r
	}
	prev = $0
}
END {
	if (total == 0) { print "skipped tests: none"; exit }
	printf "skipped tests: %d (these paths did not run on this machine)\n", total
	for (i = 1; i <= total; i++) print lines[i]
}' "$log"
exit $status
