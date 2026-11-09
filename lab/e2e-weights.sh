#!/bin/bash
# Improvement weights (#34) against a simulated FRR edge. Documentation
# prefixes and a private ASN only. Lab-proven only, not on a public edge.
#
# The edge originates 198.51.100.0/24 (5 Mbps) and 203.0.113.0/24
# (500 Mbps). Both have the same score gain. max_improvements is 1 and the
# weighted scorer's improvement_weights add volume. Checked on the router
# (lab/checkms lists every prefix with a Packeteer path) on every sample:
# never more than one Packeteer route (a withdraw in flight gets 3s), and
# never 198.51.100.0/25, which Packeteer probes with the heaviest volume
# but the edge never advertises. Then:
#  1. the heavier 203.0.113.0/24 takes the one slot, with next hop
#     192.0.2.2, local-pref 250, 64512:666, and no-export; /api/decisions
#     shows its weight and 198.51.100.0/24 capped (without weights the
#     lighter 198.51.100.0/24 would win: equal gain breaks by prefix);
#  2. "no network 203.0.113.0/24": a real RIB leave withdraws it and the
#     slot goes to 198.51.100.0/24;
#  3. "network 203.0.113.0/24" again: weights never displace an active
#     improvement, so 198.51.100.0/24 stays;
#  4. SIGTERM withdraws the route; a restart gives the slot to the
#     heavier prefix again;
#  5. SIGKILL: the route drops with the session within the hold timer.
set -euo pipefail
export LC_ALL=C

root=$(cd "$(dirname "$0")/.." && pwd)
cd "$root"
compose=(docker compose -f lab/docker-compose-weights.yml)

check_bin=$(mktemp)
trap 'rc=$?; if [ "$rc" -ne 0 ]; then echo "---- lab logs ----"; "${compose[@]}" logs --no-color || true; "${compose[@]}" ps || true; fi; "${compose[@]}" down -v --remove-orphans || true; rm -f "$check_bin"; exit "$rc"' EXIT

echo "building route-set check"
go build -o "$check_bin" ./lab/checkms

echo "building lab"
"${compose[@]}" build
"${compose[@]}" up -d

max_routes=1
# Every prefix the edge advertises during the run. A Packeteer route for
# anything else (198.51.100.0/25) fails the run on first sight.
ever="198.51.100.0/24 203.0.113.0/24"

edge() {
	"${compose[@]}" exec -T edge vtysh "$@"
}

api() {
	"${compose[@]}" exec -T packeteer wget -qO- "http://127.0.0.1:8080$1" 2>/dev/null || true
}

dump_bgp() {
	edge -c 'show bgp summary' >&2 || true
	edge -c 'show bgp ipv4 unicast' >&2 || true
	api /api/decisions >&2 || true
	"${compose[@]}" logs --no-color packeteer >&2 || true
}

over_cap_grace=3
got=
read_edge() {
	local p
	out=$(edge -c 'show bgp ipv4 unicast json' 2>/dev/null) || return 1
	out=$(printf '%s\n' "$out" | "$check_bin") || return 1
	for p in $out; do
		if [[ " $ever " != *" $p "* ]]; then
			echo "FAIL: Packeteer announced $p, which the edge never advertised" >&2
			dump_bgp
			exit 1
		fi
	done
	n=$(printf '%s\n' "$out" | grep -c . || true)
}
sample() {
	local out n i
	got="?"
	read_edge || return 1
	for i in $(seq 1 "$over_cap_grace"); do
		[ "$n" -gt "$max_routes" ] || break
		echo "edge shows $n routes (cap $max_routes): $(echo $out); re-reading for a withdraw in flight" >&2
		sleep 1
		read_edge || return 1
	done
	if [ "$n" -gt "$max_routes" ]; then
		echo "FAIL: $n Packeteer routes on the edge, max_improvements is $max_routes: $(echo $out)" >&2
		dump_bgp
		exit 1
	fi
	got=$out
}

want_set() {
	local want i
	want=$(printf '%s\n' "$@" | grep . | sort || true)
	for i in $(seq 1 45); do
		if sample && [ "$got" = "$want" ]; then
			echo "edge has Packeteer routes: [$(echo $got)]"
			return 0
		fi
		sleep 1
	done
	echo "timed out: edge has [$(echo $got)], want [$(echo $want)]" >&2
	dump_bgp
	return 1
}

stay_set() {
	local seconds=$1
	shift
	local want i
	want=$(printf '%s\n' "$@" | grep . | sort || true)
	for i in $(seq 1 "$seconds"); do
		if ! sample || [ "$got" != "$want" ]; then
			echo "set changed at second $i: [$(echo $got)], want [$(echo $want)]" >&2
			dump_bgp
			return 1
		fi
		sleep 1
	done
}

tagged() {
	local text
	text=$(edge -c "show bgp ipv4 unicast $1" 2>/dev/null || true)
	if [[ "$text" != *"192.0.2.2 from 192.0.2.10"* ]] || [[ "$text" != *"localpref 250"* ]] || [[ "$text" != *"Community: 64512:666 no-export"* ]]; then
		echo "FAIL: $1 from Packeteer is not tagged (next hop, local-pref, community, no-export)" >&2
		printf '%s\n' "$text" >&2
		dump_bgp
		exit 1
	fi
}

# decisions jq: wait until /api/decisions satisfies the jq filter.
decisions() {
	local i
	for i in $(seq 1 30); do
		if api /api/decisions | jq -e "$1" >/dev/null 2>&1; then
			return 0
		fi
		sleep 1
	done
	echo "FAIL: /api/decisions never matched: $1" >&2
	dump_bgp
	exit 1
}

network() {
	local args=(-c 'configure terminal' -c 'router bgp 64512' -c 'address-family ipv4 unicast') line
	for line in "$@"; do
		args+=(-c "$line")
	done
	edge "${args[@]}" -c 'end'
}

neighbor_text() {
	edge -c 'show bgp neighbors 192.0.2.10' 2>/dev/null || true
}

echo "1. the heavier prefix takes the one slot"
want_set 203.0.113.0/24
tagged 203.0.113.0/24
# Weight = gain (70 ms) + volume: 570 for 203.0.113.0/24, 75 for 198.51.100.0/24.
decisions '[.decisions[] | select(.prefix == "198.51.100.0/24" and .action == "capped" and (.reason | test("max_improvements \\(1\\) reached")) and .weight == 75)] | length == 1'
decisions '[.decisions[] | select(.prefix == "198.51.100.0/25" and .action == "none" and .reason == "prefix not in RIB")] | length == 1'
# Past policy.NativePathConfirm (5s) and several 2s probe rounds.
stay_set 10 203.0.113.0/24

echo "2. a real RIB leave withdraws it; the slot goes to the other prefix"
network 'no network 203.0.113.0/24'
want_set 198.51.100.0/24
tagged 198.51.100.0/24

echo "3. the heavier prefix returns: an active improvement is never displaced"
network 'network 203.0.113.0/24'
decisions '[.decisions[] | select(.prefix == "203.0.113.0/24" and .action == "capped" and .weight == 570)] | length == 1'
stay_set 10 198.51.100.0/24

echo "4. SIGTERM withdraws the route"
"${compose[@]}" stop -t 20 packeteer
want_set
for p in 198.51.100.0/24 203.0.113.0/24; do
	text=$(edge -c "show bgp ipv4 unicast $p" 2>/dev/null || true)
	if [[ "$text" != *"$p"* ]]; then
		echo "FAIL: the edge lost its own $p" >&2
		dump_bgp
		exit 1
	fi
done

echo "restarting packeteer: the heavier prefix wins the slot again"
"${compose[@]}" start packeteer
want_set 203.0.113.0/24
tagged 203.0.113.0/24

echo "5. SIGKILL: the route drops with the session"
hold=$(awk '$1 == "neighbor" && $2 == "192.0.2.10" && $3 == "timers" { print $5 }' lab/frr-wt-edge/frr.conf)
case "$hold" in
'' | *[!0-9]*)
	echo "lab hold timer is not an integer: '${hold}'" >&2
	exit 1
	;;
esac
if [ "$hold" -lt 3 ] || [ "$hold" -gt 30 ]; then
	echo "lab hold timer ${hold}s is not a bounded crash-test value (want 3-30)" >&2
	exit 1
fi
cid=$("${compose[@]}" ps -q packeteer)
if [ -z "$cid" ]; then
	echo "packeteer is not running" >&2
	exit 1
fi
start=$(date +%s)
docker kill -s KILL "$cid"
deadline=$((start + hold + 6))
dropped=0
while [ "$(date +%s)" -le "$deadline" ]; do
	sample || true
	nbr=$(neighbor_text)
	if [ -z "$got" ] && [[ "$nbr" == *"BGP state ="* ]] && [[ "$nbr" != *"BGP state = Established"* ]]; then
		dropped=1
		break
	fi
	sleep 1
done
if [ "$dropped" -ne 1 ]; then
	echo "FAIL: Packeteer route still on the edge ${hold}s after SIGKILL: [$(echo $got)]" >&2
	dump_bgp
	exit 1
fi
echo "session lost and the route gone $(($(date +%s) - start))s after SIGKILL (hold ${hold}s)"

echo "e2e weights ok"
