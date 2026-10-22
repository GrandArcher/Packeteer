#!/usr/bin/env bash
# Load and soak test (#51) against the stock image with a mounted config.
# Lab only: documentation prefixes and ASNs, observe mode (inject inside the
# documentation allowlist on the multi-session profiles, #383), simulated
# edge routers inside lab/soak, synthetic IPFIX, the fixed prober (no probe
# packets leave the host).
#
#   lab/soak.sh IMAGE [PROFILE] [DURATION]
#
# PROFILE is a profile in lab/soak/budgets.yaml (default pr). DURATION
# overrides its soak phase (for example 30m). The result is printed, added
# to the GitHub step summary, and written to $SOAK_OUT (default
# soak-result.json). Any budget over or invariant broken exits non-zero.
#
# Environment: SOAK_MULTIPLY=N plays the table on N sessions (#342).
# SOAK_MRT=FILE replays a downloaded RIS or RouteViews dump and needs a
# profile with real: true (lab/realtable.sh sets it); the log of a failed
# real run is printed with addresses masked. SOAK_STOP_TIMEOUT is the
# seconds docker stop waits for SIGTERM to finish (default 30).
set -euo pipefail

image=${1:?usage: lab/soak.sh IMAGE [PROFILE] [DURATION]}
profile=${2:-pr}
duration=${3:-}
out=${SOAK_OUT:-soak-result.json}
name=pksoak
mrt=${SOAK_MRT:-}

work=$(mktemp -d)
cleanup() {
	rc=$?
	if [ "$rc" -ne 0 ]; then
		echo "---- packeteer log (tail) ----"
		if [ -n "$mrt" ]; then
			# A real table puts real prefixes in the log; counts only.
			docker logs --tail 200 "$name" 2>&1 | sed -E 's/[0-9a-fA-F:.]*[.:][0-9a-fA-F:.]*[0-9a-fA-F:](\/[0-9]+)?/<addr>/g' || true
		else
			docker logs --tail 200 "$name" 2>&1 || true
		fi
	fi
	docker rm -f "$name" >/dev/null 2>&1 || true
	rm -rf "$work"
	exit "$rc"
}
trap cleanup EXIT

echo "building the soak harness"
go build -o "$work/soak" ./lab/soak
shared=(-profile "$profile")
if [ -n "${SOAK_MULTIPLY:-}" ]; then
	shared+=(-multiply "$SOAK_MULTIPLY")
fi
"$work/soak" config "${shared[@]}" -out "$work/config.yaml"

docker rm -f "$name" >/dev/null 2>&1 || true
# Probe logs are at info level, as in the example config; rotate them so a
# long soak cannot fill the runner's disk.
docker run -d --name "$name" --network host --cap-add NET_RAW --cap-add NET_ADMIN \
	--log-opt max-size=50m --log-opt max-file=2 \
	-v "$work/config.yaml:/etc/packeteer/config.yaml:ro" "$image" >/dev/null
pid=$(docker inspect -f '{{.State.Pid}}' "$name")
echo "packeteer pid $pid (host view)"

args=(run "${shared[@]}" -pid "$pid" -stop "docker stop -t ${SOAK_STOP_TIMEOUT:-30} $name" -json "$out")
if [ -n "$mrt" ]; then
	args+=(-mrt "$mrt")
fi
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
