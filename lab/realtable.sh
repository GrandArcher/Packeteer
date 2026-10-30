#!/usr/bin/env bash
# Opt-in replay of a real public full table (#342). Lab only: the soak
# harness plays one peer's view of a RIPE RIS or RouteViews MRT dump to the
# stock image over loopback, with next hops rewritten to documentation
# addresses. Packeteer runs in observe mode and announces nothing; nothing
# connects to a real router. The dump is downloaded here, kept in a
# temporary directory, and deleted on exit. Logs and the result file hold
# counts and timings only.
#
#   lab/realtable.sh IMAGE [MULTIPLY]
#
# REALTABLE_PROFILE=realtable3m (#103) plays the three largest peers' views
# of the dump as three providers' routes, grows the table to 3 million
# prefixes with more-specifics of the dump's own prefixes, and gives it
# SIMULATED probe results from the sim prober (a seeded delay and loss model
# per provider; no packet is sent and nothing real is probed). MULTIPLY must
# stay 1 then. It holds 8 to 9 million paths (expect 18 to 23 GiB): use a host with 32 GB or more.
#
# MULTIPLY (default 1, at most 4) plays the table on that many sessions, so
# Packeteer holds that many paths per prefix. REALTABLE_URL names the dump
# (default: RIPE RIS rrc00, the latest bview) and must be on the RIS or
# RouteViews archive. REALTABLE_MRT names a dump already on disk and skips
# the download. The result is written to $SOAK_OUT (default
# realtable-result.json). Never run it from the default CI.
set -euo pipefail

image=${1:?usage: lab/realtable.sh IMAGE [MULTIPLY]}
multiply=${2:-1}
url=${REALTABLE_URL:-https://data.ris.ripe.net/rrc00/latest-bview.gz}
profile=${REALTABLE_PROFILE:-realtable}
here=$(cd "$(dirname "$0")" && pwd)

case "$url" in
https://data.ris.ripe.net/* | https://archive.routeviews.org/*) ;;
*)
	echo "REALTABLE_URL must be on data.ris.ripe.net or archive.routeviews.org" >&2
	exit 2
	;;
esac
case "$profile" in
realtable) ;;
realtable3m)
	if [ "$multiply" != 1 ]; then
		echo "MULTIPLY must be 1 for realtable3m: it plays three peers' views" >&2
		exit 2
	fi
	;;
*)
	echo "REALTABLE_PROFILE must be realtable or realtable3m" >&2
	exit 2
	;;
esac
case "$multiply" in
1 | 2 | 3 | 4) ;;
*)
	echo "MULTIPLY must be 1 to 4" >&2
	exit 2
	;;
esac

work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT

mrt=${REALTABLE_MRT:-}
if [ -z "$mrt" ]; then
	mrt=$work/dump
	echo "downloading the dump"
	curl -fsS --retry 3 --max-time 900 -o "$mrt" "$url"
	echo "dump: $(stat -c %s "$mrt") bytes"
fi

# Packeteer holds a path per session; the stop can take longer than the
# 30 seconds of the synthetic profiles (docs/performance.md).
SOAK_MRT=$mrt SOAK_MULTIPLY=$multiply SOAK_STOP_TIMEOUT=120 \
	SOAK_OUT=${SOAK_OUT:-realtable-result.json} \
	bash "$here/soak.sh" "$image" "$profile"
