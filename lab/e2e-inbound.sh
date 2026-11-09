#!/bin/bash
# Inbound optimization (#25) against a simulated edge with two simulated
# eBGP transits. Documentation prefixes and documentation/private ASNs only.
#
# Commit trigger: transit-a's inbound 95th is over commit, so Packeteer
# re-announces 203.0.113.0/24 to the edge with transit-a's catalog action.
# The edge must then send transit-a the prefix prepended twice with
# transit-a's TE community, and send transit-b the plain prefix. Release
# leaves both plain. A second steer inside the flap window is damped: its
# hold doubles and it learns inertia, so flipping usage under again must
# NOT release it. SIGTERM withdraws it.
#
# Performance trigger: after a restart with usage under commit, transit-a's
# probes are 240 ms slower, so it is steered as the worst performer;
# equal probes release it. transit-b slowest withholds the prefix from
# transit-b (selective announcement) and equal probes give it back.
# transit-a slow again steers it; SIGKILL drops it with the session. Every step is checked on the transits themselves.
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
cp lab/probes/inbound-paths-equal.yaml "$lab_dir/paths.yaml"
chmod 0644 "$lab_dir/usage.yaml" "$lab_dir/paths.yaml"
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

# withheld: the selective announcement keeps the prefix off transit-b.
b_withheld() {
	path_json transit-b | "$check_bin" -absent
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
withheld_only_b() { b_withheld && plain_on transit-a; }
steered_only_a() { a_steered && plain_on transit-b; }

flip_file() {
	local tmp
	tmp=$(mktemp "$lab_dir/.flip.XXXXXX")
	cp "$1" "$tmp"
	chmod 0644 "$tmp"
	mv "$tmp" "$lab_dir/$2"
}
flip_usage() { flip_file "$1" usage.yaml; }
flip_paths() { flip_file "$1" paths.yaml; }

packeteer_logs() { "${compose[@]}" logs --no-color packeteer; }

# The logs are read into a variable first: with pipefail, grep -q exiting
# on the first match would SIGPIPE docker compose logs and fail the check.
need_log() {
	local logs
	logs=$(packeteer_logs)
	if ! grep -qE "$1" <<<"$logs"; then
		echo "packeteer log is missing: $1 ($2)" >&2
		dump_bgp
		exit 1
	fi
}

session_text() {
	"${compose[@]}" exec -T edge vtysh -c 'show bgp neighbors 192.0.2.10' 2>/dev/null || true
}

echo "commit trigger: waiting for the steer (prepend and TE community on transit-a only)"
wait_for "transit-a steered, transit-b plain" steered_only_a
logs=$(packeteer_logs)
for want in 'msg="inbound steer"' 'trigger=commit' 'inbound announced' 'communities="64512:666 64512:667 64512:1102 64496:3"'; do
	if ! grep -qF "$want" <<<"$logs"; then
		echo "packeteer log is missing: $want" >&2
		dump_bgp
		exit 1
	fi
done
if grep -q 'cause=performance\|cause=commit\|msg=injected' <<<"$logs"; then
	echo "inbound lab produced an outbound improvement" >&2
	dump_bgp
	exit 1
fi

echo "inbound back under release_pct; the steer must be released"
flip_usage lab/probes/inbound-under.yaml
wait_for "both transits plain after release" both_plain
need_log 'msg="inbound release"' "withdraw was not an inbound release"

echo "over commit again inside the flap window: damped re-steer"
flip_usage lab/probes/inbound-over.yaml
wait_for "steer again" steered_only_a
need_log 'msg="inbound steer".*flaps=1 inertia_mbps=100' "second steer was not damped (flaps=1, inertia 100 Mbps)"

echo "under commit again: inertia must hold the steer past its 10s hold"
flip_usage lab/probes/inbound-under.yaml
for _ in $(seq 1 25); do
	if ! steered_only_a 2>/dev/null; then
		echo "damped steer was released: the steer/release loop was not damped" >&2
		dump_bgp
		exit 1
	fi
	sleep 1
done
if [ "$(packeteer_logs | grep -c 'msg="inbound release"')" -ne 1 ]; then
	echo "expected exactly one inbound release before SIGTERM" >&2
	dump_bgp
	exit 1
fi

echo "stopping packeteer (SIGTERM, WithdrawAll)"
"${compose[@]}" stop -t 20 packeteer
wait_for "both transits plain after SIGTERM" both_plain
need_log 'inbound steer routes withdrawn' "SIGTERM did not withdraw the steer route"

echo "performance trigger: usage under commit, transit-a probes 240 ms slower"
flip_paths lab/probes/inbound-paths-slow-a.yaml
"${compose[@]}" start packeteer
wait_for "performance steer after restart" steered_only_a
need_log 'msg="inbound steer".*trigger=performance' "steer after restart was not a performance steer"

echo "probes equal again: the performance steer must be released"
flip_paths lab/probes/inbound-paths-equal.yaml
wait_for "both transits plain after performance release" both_plain

echo "transit-b slowest: selective announcement withholds the prefix from transit-b"
flip_paths lab/probes/inbound-paths-slow-b.yaml
wait_for "transit-b withheld, transit-a plain" withheld_only_b
need_log 'msg="inbound steer".*provider=transit-b.*withhold=true' "transit-b steer was not a withhold"

echo "probes equal again: transit-b gets the prefix back"
flip_paths lab/probes/inbound-paths-equal.yaml
wait_for "both transits plain after the withhold is released" both_plain

echo "transit-a slow again: performance steer for the crash path"
flip_paths lab/probes/inbound-paths-slow-a.yaml
wait_for "performance steer again" steered_only_a

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
