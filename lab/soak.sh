#!/usr/bin/env bash
# Load and soak test (#51) against the stock image with a mounted config.
# Lab only: documentation prefixes and ASNs, observe mode, a simulated edge
# router inside lab/soak, synthetic IPFIX, the fixed prober (no probe
# packets leave the host).
#
#   lab/soak.sh IMAGE [PROFILE] [DURATION]
#
# PROFILE is a profile in lab/soak/budgets.yaml (default pr). DURATION
# overrides its soak phase (for example 30m). The result is printed, added
# to the GitHub step summary, and written to $SOAK_OUT (default
# soak-result.json). Any budget over or invariant broken exits non-zero.
set -euo pipefail

image=${1:?usage: lab/soak.sh IMAGE [PROFILE] [DURATION]}
profile=${2:-pr}
duration=${3:-}
out=${SOAK_OUT:-soak-result.json}
name=pksoak

work=$(mktemp -d)
cleanup() {
	rc=$?
	if [ "$rc" -ne 0 ]; then
		echo "---- packeteer log (tail) ----"
		docker logs --tail 200 "$name" 2>&1 || true
	fi
	docker rm -f "$name" >/dev/null 2>&1 || true
	rm -rf "$work"
	exit "$rc"
}
trap cleanup EXIT

echo "building the soak harness"
go build -o "$work/soak" ./lab/soak
"$work/soak" config -profile "$profile" -out "$work/config.yaml"

docker rm -f "$name" >/dev/null 2>&1 || true
# Probe logs are at info level, as in the example config; rotate them so a
# long soak cannot fill the runner's disk.
docker run -d --name "$name" --network host --cap-add NET_RAW --cap-add NET_ADMIN \
	--log-opt max-size=50m --log-opt max-file=2 \
	-v "$work/config.yaml:/etc/packeteer/config.yaml:ro" "$image" >/dev/null
pid=$(docker inspect -f '{{.State.Pid}}' "$name")
echo "packeteer pid $pid (host view)"

args=(run -profile "$profile" -pid "$pid" -stop "docker stop -t 30 $name" -json "$out")
if [ -n "$duration" ]; then
	args+=(-duration "$duration")
fi
"$work/soak" "${args[@]}"

code=$(docker inspect -f '{{.State.ExitCode}}' "$name")
if [ "$code" != 0 ]; then
	echo "packeteer exited $code after SIGTERM"
	exit 1
fi
docker logs "$name" >"$work/packeteer.log" 2>&1
grep -q "shutting down" "$work/packeteer.log"
echo "soak ok"
