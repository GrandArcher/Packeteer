#!/bin/bash
# More-specific injection with a route cap (#56) against a simulated FRR
# edge. Documentation prefixes and a private ASN only.
#
# The edge originates 198.51.100.0/24 with three more-specifics inside it.
# Packeteer runs with more_specific on and max_routes 4. Checked on the
# router, from `show bgp ipv4 unicast json` (lab/checkms), on every sample:
# the route count never exceeds 4 and no prefix the edge never advertised
# (an unlearned more-specific) ever appears. Then:
#  1. the /24 and exactly its three learned more-specifics arrive, each with
#     next hop 192.0.2.2, local-pref 250, 64512:666, and no-export;
#  2. the edge adds 203.0.113.0/24 with one more-specific: it needs 2
#     routes and 4 are in use, so neither is announced (all or nothing);
#  3. "no network 198.51.100.192/27": a real RIB leave withdraws that
#     more-specific; 3 in use + 2 needed is still over the cap;
#  4. "no network 198.51.100.128/26": withdrawn, and 203.0.113.0/24 and
#     its more-specific now fit: 4 routes;
#  5. SIGTERM withdraws every route; a restart announces the same 4;
#  6. SIGKILL: every route drops with the session within the hold timer.
set -euo pipefail

root=$(cd "$(dirname "$0")/.." && pwd)
cd "$root"
compose=(docker compose -f lab/docker-compose-more-specific.yml)

check_bin=$(mktemp)
trap 'rc=$?; if [ "$rc" -ne 0 ]; then echo "---- lab logs ----"; "${compose[@]}" logs --no-color || true; "${compose[@]}" ps || true; fi; "${compose[@]}" down -v --remove-orphans || true; rm -f "$check_bin"; exit "$rc"' EXIT

echo "building route-set check"
go build -o "$check_bin" ./lab/checkms

echo "building lab"
"${compose[@]}" build
"${compose[@]}" up -d

max_routes=4
# Every prefix the edge has advertised during the run. A Packeteer route
# for anything else is an unlearned prefix and fails the run.
ever="198.51.100.0/24 198.51.100.0/25 198.51.100.128/26 198.51.100.192/27"

edge() {
	"${compose[@]}" exec -T edge vtysh "$@"
}

dump_bgp() {
	edge -c 'show bgp summary' >&2 || true
	edge -c 'show bgp ipv4 unicast' >&2 || true
	edge -c 'show bgp ipv4 unicast neighbors 192.0.2.10 received-routes' >&2 || true
	"${compose[@]}" logs --no-color packeteer >&2 || true
}

# sample sets got to the prefixes Packeteer has on the edge, one per line,
# sorted. It runs in the script's shell (never in $(...)), so an unlearned
# prefix or more than max_routes routes ends the run. A failed read leaves
# got unset-equivalent ("?") and returns 1.
got=
sample() {
	local out p n
	got="?"
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
	if [ "$n" -gt "$max_routes" ]; then
		echo "FAIL: $n Packeteer routes on the edge, cap is $max_routes: $(echo $out)" >&2
		dump_bgp
		exit 1
	fi
	got=$out
}

# want_set prefixes...: wait until the edge has exactly that set.
want_set() {
	local want i
	want=$(printf '%s\n' "$@" | grep . | sort || true)
	for i in $(seq 1 45); do
		if sample && [ "$got" = "$want" ]; then
			echo "edge has $(printf '%s\n' "$got" | grep -c . || true) Packeteer routes: $(echo $got)"
			return 0
		fi
		sleep 1
	done
	echo "timed out: edge has [$(echo $got)], want [$(echo $want)]" >&2
	dump_bgp
	return 1
}

# stay_set seconds prefixes...: the set must not change.
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

# tagged prefix: Packeteer's path carries transit-b's next hop, local-pref
# 250, the packeteer community, and no-export.
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

need_log() {
	local pattern=$1 why=$2 i
	for i in $(seq 1 30); do
		if "${compose[@]}" logs --no-color packeteer 2>/dev/null | grep -Eq "$pattern"; then
			return 0
		fi
		sleep 1
	done
	echo "FAIL: $why (no log matching: $pattern)" >&2
	dump_bgp
	exit 1
}

# network "line"...: apply network statements on the edge in one session.
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

first="198.51.100.0/24 198.51.100.0/25 198.51.100.128/26 198.51.100.192/27"

echo "1. the /24 and exactly its learned more-specifics"
# shellcheck disable=SC2086
want_set $first
for p in $first; do
	tagged "$p"
done
need_log 'msg="injected more-specific" prefix=198.51.100.192/27 improvement=198.51.100.0/24' "more-specific not logged"

echo "2. a second /24 with one learned more-specific waits at the cap"
ever="$ever 203.0.113.0/24 203.0.113.0/25"
network 'network 203.0.113.0/24' 'network 203.0.113.0/25'
need_log 'more_specific.max_routes \(4\) reached: 203.0.113.0/24 needs 2 routes, 4 in use' "second improvement was not held at the route cap"
# Longer than policy.NativePathConfirm (5s) and the 2s probe interval, so
# the next leave is a confirmed one.
# shellcheck disable=SC2086
stay_set 10 $first

echo "3. a real RIB leave withdraws that more-specific"
network 'no network 198.51.100.192/27'
want_set 198.51.100.0/24 198.51.100.0/25 198.51.100.128/26
need_log 'more-specific left the RIB; withdrawn" prefix=198.51.100.192/27' "leave not logged"
stay_set 8 198.51.100.0/24 198.51.100.0/25 198.51.100.128/26

echo "4. a second leave makes room: the waiting /24 is announced whole"
network 'no network 198.51.100.128/26'
final="198.51.100.0/24 198.51.100.0/25 203.0.113.0/24 203.0.113.0/25"
# shellcheck disable=SC2086
want_set $final
for p in $final; do
	tagged "$p"
done
# shellcheck disable=SC2086
stay_set 6 $final

echo "5. SIGTERM withdraws every route"
"${compose[@]}" stop -t 20 packeteer
want_set
text=$(edge -c 'show bgp ipv4 unicast 198.51.100.0/25' 2>/dev/null || true)
if [[ "$text" != *"198.51.100.0/25"* ]]; then
	echo "FAIL: the edge lost its own 198.51.100.0/25" >&2
	dump_bgp
	exit 1
fi

echo "restarting packeteer"
"${compose[@]}" start packeteer
# shellcheck disable=SC2086
want_set $final

echo "6. SIGKILL: routes drop with the session"
hold=$(awk '$1 == "neighbor" && $2 == "192.0.2.10" && $3 == "timers" { print $5 }' lab/frr-ms-edge/frr.conf)
case "$hold" in
'' | *[!0-9]*)
	echo "lab hold timer is not an integer: '${hold}'" >&2
	exit 1
	;;
esac
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
	echo "FAIL: Packeteer routes still on the edge ${hold}s after SIGKILL: [$(echo $got)]" >&2
	dump_bgp
	exit 1
fi
echo "session lost and every route gone $(($(date +%s) - start))s after SIGKILL (hold ${hold}s)"

echo "e2e more-specific ok"
