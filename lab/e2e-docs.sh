#!/bin/bash
# Run every shell block of a guide, in order, as CI steps (#50). The blocks
# and their hidden ci-* directives are turned into a script by lab/doccmds.
#
#   bash lab/e2e-docs.sh docs/quickstart.md packeteer:ci
#   PACKETEER_DOCS_DIR=. bash lab/e2e-docs.sh docs/walkthrough.md
#
# With an image argument, that image is tagged ghcr.io/grandarcher/packeteer:edge
# so the guide's commands run unchanged against the image CI just built.
# Downloads from raw.githubusercontent.com/GrandArcher/Packeteer/main/ read
# the same path from this checkout, and `docker pull` is refused, so the
# test never exercises a published image instead of this commit.
#
# PACKETEER_DOCS_DIR is where the steps start (default: an empty temporary
# directory). PACKETEER_DOCS_ON_FAIL is a command run when a step fails
# (logs), PACKETEER_DOCS_CLEANUP one run on exit either way.
set -euo pipefail

root=$(cd "$(dirname "$0")/.." && pwd)
guide=$(cd "$(dirname "$1")" && pwd)/$(basename "$1")
image=${2:-}
cd "$root"

work=$(mktemp -d)
cleanup() {
	rc=$?
	if [ "$rc" -ne 0 ] && [ -n "${PACKETEER_DOCS_ON_FAIL:-}" ]; then
		(cd "$root" && eval "$PACKETEER_DOCS_ON_FAIL") >&2 || true
	fi
	if [ -n "${PACKETEER_DOCS_CLEANUP:-}" ]; then
		(cd "$root" && eval "$PACKETEER_DOCS_CLEANUP") || true
	fi
	rm -rf "$work"
	exit "$rc"
}
trap cleanup EXIT

go build -o "$work/doccmds" ./lab/doccmds

if [ -n "$image" ]; then
	docker image inspect "$image" >/dev/null
	docker tag "$image" ghcr.io/grandarcher/packeteer:edge
fi

{
	cat <<'PRELUDE'
__doc_raw=https://raw.githubusercontent.com/GrandArcher/Packeteer/main/
curl() {
	local a args=()
	for a in "$@"; do
		case $a in
		"$__doc_raw"*) a="file://$PACKETEER_DOCS_ROOT/${a#"$__doc_raw"}" ;;
		esac
		args+=("$a")
	done
	command curl "${args[@]}"
}
docker() {
	if [ "${1:-}" = pull ]; then
		echo "doc test: refusing docker pull; CI tests the image it built" >&2
		return 1
	fi
	command docker "$@"
}
PRELUDE
	"$work/doccmds" "$guide"
} >"$work/run.sh"

dir=${PACKETEER_DOCS_DIR:-$work/run}
mkdir -p "$dir"
cd "$dir"
PACKETEER_DOCS_ROOT="$root" bash "$work/run.sh"
