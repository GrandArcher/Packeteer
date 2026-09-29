#!/bin/bash
# Inbound commit control (#25) against a simulated edge with two simulated
# eBGP transits. Documentation prefixes and documentation/private ASNs only.
#
# transit-a's inbound 95th is over commit, so Packeteer re-announces
# 203.0.113.0/24 to the edge with transit-a's catalog action. The edge must
# then send transit-a the prefix prepended twice with transit-a's TE
# community, and send transit-b the plain prefix. Release, SIGTERM, and
# SIGKILL must each leave both transits with the plain prefix.
set -euo pipefail

root=$(cd "$(dirname "$0")/.." && pwd)
cd "$root"
compose=(docker compose -f lab/docker-compose-inbound.yml)

lab_dir=$(mktemp -d)
check_bin=$(mktemp)
trap 'rc=$?; if [ "$rc" -ne 0 ]; then echo "---- lab logs ----"; "${compose[@]}" logs --no-color || true; "${compose[@]}" ps || true; fi; "${compose[@]}" down -v --remove-orphans || true; rm -f "$check_bin"; rm -rf "$lab_dir"; exit "$rc"' EXIT

echo "building path check"
go build -o "$check_bin" ./lab/checkpath

cp lab/probes/inbound-over.yaml "$lab_dir/usage.yaml"
chmod 0644 "$lab_dir/usage.yaml"
export PACKETEER_LAB_DIR="$lab_dir"

echo "building lab"
"${compose[@]}" build
"${compose[@]}" up -d

prefix=203.0.113.0/24

path_json() {
	"${compose[@]}" exec -T "$1" vtysh -c "show bgp ipv4 unicast $prefix json" 2>/dev/null || true
}

# steered: transit-a gets the double prepend and its own TE community, and
# no Packeteer or transit-b community.
a_steered() {
	path_json transit-a | "$check_bin" -aspath "64512 64512 64512" -has 64496:3 \
		-lacks 64512: -lacks 64497: -lacks no-export
}

plain_on() {
	path_json "$1" | "$check_bin" -aspath "64512" -lacks 64512: -lacks 64496: -lacks 64497: -lacks no-export
}

dump_bgp() {
	for r in edge transit-a transit-b; do
		echo "---- $r ----" >&2
		"${compose[@]}" exec -T "$r" vtysh -c 'show bgp summary' >&2 || true
		"${compose[@]}" exec -T "$r" vtysh -c "show bgp ipv4 unicast $prefix" >&2 || true
	done
	"${compose[@]}" logs --no-color packeteer >&2 || true
}

wait_for() {
	local what=$1
	shift
	local i
	for i in $(seq 1 45); do
		if "$@" 2>/dev/null; then
			return 0
		fi
		sleep 2
	done
	echo "timed out waiting for: $what" >&2
	"$@" || true
	dump_bgp
	return 1
}

both_plain() { plain_on transit-a && plain_on transit-b; }
steered_only_a() { a_steered && plain_on transit-b; }

flip_usage() {
	local tmp
	tmp=$(mktemp "$lab_dir/.usage.XXXXXX")
	cp "$1" "$tmp"
	chmod 0644 "$tmp"
	mv "$tmp" "$lab_dir/usage.yaml"
}

session_text() {
	"${compose[@]}" exec -T edge vtysh -c 'show bgp neighbors 192.0.2.10' 2>/dev/null || true
}

echo "waiting for the steer: prepend and TE community on transit-a only"
wait_for "transit-a steered, transit-b plain" steered_only_a
logs=$("${compose[@]}" logs --no-color packeteer)
for want in 'msg="inbound steer"' 'inbound announced' 'communities="64512:666 64512:667 64512:1102 64496:3"'; do
	if ! printf '%s\n' "$logs" | grep -qF "$want"; then
		echo "packeteer log is missing: $want" >&2
		dump_bgp
		exit 1
	fi
done
if printf '%s\n' "$logs" | grep -q 'cause=performance\|cause=commit'; then
	echo "inbound lab produced an outbound improvement" >&2
	dump_bgp
	exit 1
fi

echo "inbound back under release_pct; the steer must be released"
flip_usage lab/probes/inbound-under.yaml
wait_for "both transits plain after release" both_plain
if ! "${compose[@]}" logs --no-color packeteer | grep -q 'msg="inbound release"'; then
	echo "withdraw was not an inbound release" >&2
	dump_bgp
	exit 1
fi

echo "over commit again (after the hold_time cooldown)"
flip_usage lab/probes/inbound-over.yaml
wait_for "steer again" steered_only_a

echo "stopping packeteer (SIGTERM, WithdrawAll)"
"${compose[@]}" stop -t 20 packeteer
wait_for "both transits plain after SIGTERM" both_plain
if ! "${compose[@]}" logs --no-color packeteer | grep -q 'inbound steer routes withdrawn'; then
	echo "SIGTERM did not withdraw the steer route" >&2
	dump_bgp
	exit 1
fi

echo "starting packeteer again for the crash path"
"${compose[@]}" start packeteer
wait_for "steer after restart" steered_only_a

hold=$(awk '$1 == "neighbor" && $2 == "192.0.2.10" && $3 == "timers" { print $5 }' lab/frr-inbound/frr.conf)
case "$hold" in
''|*[!0-9]*)
	echo "lab hold timer is not an integer: '${hold}'" >&2
	exit 1
	;;
esac
if [ "$hold" -lt 3 ] || [ "$hold" -gt 30 ]; then
	echo "lab hold timer ${hold}s is not a bounded crash-test value (want 3-30)" >&2
	exit 1
fi

echo "SIGKILL packeteer (no WithdrawAll)"
cid=$("${compose[@]}" ps -q packeteer)
if [ -z "$cid" ]; then
	echo "packeteer is not running" >&2
	dump_bgp
	exit 1
fi
start=$(date +%s)
docker kill -s KILL "$cid"
code=
for _ in $(seq 1 25); do
	code=$(docker inspect -f '{{.State.ExitCode}}' "$cid" 2>/dev/null || true)
	if [ "$(docker inspect -f '{{.State.Status}}' "$cid" 2>/dev/null || true)" = "exited" ] && [ "$code" = "137" ]; then
		break
	fi
	sleep 0.2
done
if [ "$code" != "137" ]; then
	echo "expected SIGKILL exit 137, got ${code:-unknown}" >&2
	dump_bgp
	exit 1
fi

echo "waiting for the edge to drop the steer after session loss (hold ${hold}s)"
deadline=$((start + hold + 10))
cleared=0
while [ "$(date +%s)" -le "$deadline" ]; do
	nbr=$(session_text)
	if [[ "$nbr" == *"BGP state = Established"* ]]; then
		if ! a_steered 2>/dev/null; then
			echo "steer cleared while the session to the dead process is still Established" >&2
			dump_bgp
			exit 1
		fi
	elif [[ "$nbr" == *"BGP state ="* ]] && both_plain 2>/dev/null; then
		cleared=1
		break
	fi
	sleep 1
done
if [ "$cleared" -ne 1 ]; then
	echo "steer still on transit-a after SIGKILL past the ${hold}s hold timer" >&2
	dump_bgp
	exit 1
fi
echo "session lost and transits plain $(($(date +%s) - start))s after SIGKILL (hold ${hold}s)"

echo "inbound e2e ok"
