#!/bin/bash
# Synthesized more-specific injection (#122) against a simulated FRR edge
# and a simulated transit outside the AS ("ext", AS 64511) that streams its
# Adj-RIB-In to Packeteer over BMP for the leak watch. Documentation
# prefixes and private ASNs only. Lab only: never on a production edge.
#
# The edge originates 198.51.100.0/24 and 203.0.113.0/24 and nothing inside
# them. lab/sendflow sends equal traffic to a low and a high /25 of a /24;
# the fixed prober makes transit-b faster toward each low /25 only, so each
# /24 stays native and each low /25 is a synthesized move. The route cap
# (more_specific.max_routes) is 1. Checked on the routers on every sample:
# no Packeteer prefix other than the two low /25s ever appears on the edge,
# nothing Packeteer announced ever reaches ext, and never more than 1 route.
#  1. 198.51.100.0/25 is announced toward transit-b with local-pref 250,
#     64512:666, the marker 64512:667, and no-export; the /24 is not;
#     /api/decisions lists it with its covering prefix;
#  2. traffic to 203.0.113.0/24 starts: 203.0.113.0/25 waits at the cap;
#  3. "no network 198.51.100.0/24" on the edge: after the confirm window
#     the synthesized /25 is withdrawn, and the waiting one takes the room;
#  4. SIGTERM withdraws every route; a restart announces the same one;
#  5. SIGKILL: every route drops with the session within the hold timer.
set -euo pipefail
export LC_ALL=C

root=$(cd "$(dirname "$0")/.." && pwd)
cd "$root"
compose=(docker compose -f lab/docker-compose-synthesize.yml)

check_bin=$(mktemp)
flow_bin=$(mktemp)
rates=$(mktemp)
flow_pid=
trap 'rc=$?; if [ -n "$flow_pid" ]; then kill "$flow_pid" 2>/dev/null || true; fi; if [ "$rc" -ne 0 ]; then echo "---- lab logs ----"; "${compose[@]}" logs --no-color || true; "${compose[@]}" ps || true; fi; "${compose[@]}" down -v --remove-orphans || true; rm -f "$check_bin" "$flow_bin" "$rates" "$rates.tmp"; exit "$rc"' EXIT

echo "building route-set check and flow sender"
go build -o "$check_bin" ./lab/checkms
go build -o "$flow_bin" ./lab/sendflow

echo "building lab"
"${compose[@]}" build
"${compose[@]}" up -d

api=http://192.0.2.10:8080/api
max_routes=1
# The only prefixes Packeteer may ever put on the edge.
allowed="198.51.100.0/25 203.0.113.0/25"

edge() { "${compose[@]}" exec -T edge vtysh "$@"; }
ext() { "${compose[@]}" exec -T ext vtysh "$@"; }

dump() {
	edge -c 'show bgp summary' -c 'show bgp ipv4 unicast' >&2 || true
	ext -c 'show bgp summary' -c 'show bgp ipv4 unicast' >&2 || true
	curl -sS "$api/decisions" >&2 || true
	"${compose[@]}" logs --no-color packeteer >&2 || true
}

ext_has() { [[ "$(ext -c "show bgp ipv4 unicast $1" 2>/dev/null || true)" == *"BGP routing table entry for $1"* ]]; }

# sample sets got to the prefixes Packeteer has on the edge, sorted. It
# runs in the script's shell, so a prefix outside $allowed, more than
# max_routes routes, or a Packeteer route on ext ends the run. A withdraw
# in flight gets 3s before the cap fails, as in lab/e2e-more-specific.sh.
got=
read_edge() {
	local p
	out=$(edge -c 'show bgp ipv4 unicast json' 2>/dev/null) || return 1
	out=$(printf '%s\n' "$out" | "$check_bin") || return 1
	for p in $out; do
		if [[ " $allowed " != *" $p "* ]]; then
			echo "FAIL: Packeteer announced $p, which synthesize may not" >&2
			dump
			exit 1
		fi
	done
	n=$(printf '%s\n' "$out" | grep -c . || true)
}
sample() {
	local out n i p
	got="?"
	read_edge || return 1
	for i in 1 2 3; do
		[ "$n" -gt "$max_routes" ] || break
		sleep 1
		read_edge || return 1
	done
	if [ "$n" -gt "$max_routes" ]; then
		echo "FAIL: $n Packeteer routes on the edge, cap is $max_routes: $(echo $out)" >&2
		dump
		exit 1
	fi
	for p in $allowed; do
		if ext_has "$p"; then
			echo "FAIL: $p reached ext, the other transit" >&2
			dump
			exit 1
		fi
	done
	got=$out
}

want_set() {
	local want i
	want=$(printf '%s\n' "$@" | grep . | sort || true)
	for i in $(seq 1 90); do
		if sample && [ "$got" = "$want" ]; then
			echo "edge has Packeteer routes: [$(echo $got)]"
			return 0
		fi
		sleep 1
	done
	echo "timed out: edge has [$(echo $got)], want [$(echo $want)]" >&2
	dump
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
			dump
			return 1
		fi
		sleep 1
	done
}

# tagged prefix: Packeteer's path carries transit-b's next hop, local-pref
# 250, the packeteer community, the marker, and no-export.
tagged() {
	local text
	text=$(edge -c "show bgp ipv4 unicast $1" 2>/dev/null || true)
	if [[ "$text" != *"192.0.2.2 from 192.0.2.10"* ]] || [[ "$text" != *"localpref 250"* ]] ||
		[[ "$text" != *"64512:666"* ]] || [[ "$text" != *"64512:667"* ]] || [[ "$text" != *"no-export"* ]]; then
		echo "FAIL: $1 from Packeteer is not tagged (next hop, local-pref, community, marker, no-export)" >&2
		printf '%s\n' "$text" >&2
		dump
		exit 1
	fi
}

need_log() {
	local pattern=$1 why=$2 i
	for i in $(seq 1 45); do
		if "${compose[@]}" logs --no-color packeteer 2>/dev/null | grep -Eq "$pattern"; then
			return 0
		fi
		sleep 1
	done
	echo "FAIL: $why (no log matching: $pattern)" >&2
	dump
	exit 1
}

session_up() { [[ "$(edge -c 'show bgp neighbors 192.0.2.10' 2>/dev/null || true)" == *"BGP state = Established"* ]]; }

echo "waiting for the Packeteer session"
for i in $(seq 1 60); do
	session_up && break
	sleep 2
done
session_up || {
	echo "FAIL: no Packeteer session" >&2
	dump
	exit 1
}
need_log 'WARNING: synthesize is on' "no startup warning"

# set_rates LINE...: "destination protocol mbps" per line, swapped in
# atomically; lab/sendflow re-reads the file before every export.
set_rates() {
	printf '%s\n' "$@" >"$rates.tmp"
	mv "$rates.tmp" "$rates"
}

echo "synthetic traffic to a low and a high /25 of 198.51.100.0/24"
set_rates "198.51.100.10 udp 1" "198.51.100.200 udp 1"
"$flow_bin" -to 192.0.2.10:2055 -rates "$rates" -every 200ms &
flow_pid=$!

echo "1. the low /25 of 198.51.100.0/24 is synthesized and tagged"
want_set 198.51.100.0/25
tagged 198.51.100.0/25
need_log 'injected synthesized more-specific; it is not in the learned RIB" prefix=198.51.100.0/25 covering=198.51.100.0/24 provider=transit-b' "synthesized route not logged"
covering=$(curl -sS "$api/decisions" | jq -r '.decisions[] | select(.prefix == "198.51.100.0/25") | .covering')
if [ "$covering" != 198.51.100.0/24 ]; then
	echo "FAIL: /api/decisions does not list 198.51.100.0/25 inside 198.51.100.0/24 (got '$covering')" >&2
	dump
	exit 1
fi
if ! ext_has 198.51.100.0/24; then
	echo "FAIL: ext did not receive the edge's own 198.51.100.0/24; the export check proves nothing" >&2
	dump
	exit 1
fi

echo "2. the second synthesized /25 waits at the route cap"
set_rates "198.51.100.10 udp 1" "198.51.100.200 udp 1" "203.0.113.10 udp 1" "203.0.113.200 udp 1"
need_log 'max_routes \(1\) reached: 203.0.113.0/25 needs 1 routes, 1 in use' "second synthesized route was not held at the cap"
# Longer than policy.NativePathConfirm (5s) and the 2s probe interval, so
# the covering prefix's leave below is a confirmed one.
stay_set 12 198.51.100.0/25

echo "3. the covering prefix leaves the RIB: withdrawn, and the waiting one fits"
edge -c 'configure terminal' -c 'router bgp 64512' -c 'address-family ipv4 unicast' -c 'no network 198.51.100.0/24' -c 'end'
want_set 203.0.113.0/25
tagged 203.0.113.0/25
need_log 'improvement retired.*prefix=198.51.100.0/25.*reason="prefix no longer in RIB"' "covering leave not logged"
stay_set 8 203.0.113.0/25

echo "4. SIGTERM withdraws every route"
"${compose[@]}" stop -t 20 packeteer
want_set
echo "restarting packeteer"
"${compose[@]}" start packeteer
want_set 203.0.113.0/25

echo "5. SIGKILL: routes drop with the session"
hold=$(awk '$1 == "neighbor" && $2 == "192.0.2.10" && $3 == "timers" { print $5 }' lab/frr-syn-edge/frr.conf)
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
	nbr=$(edge -c 'show bgp neighbors 192.0.2.10' 2>/dev/null || true)
	if [ -z "$got" ] && [[ "$nbr" == *"BGP state ="* ]] && [[ "$nbr" != *"BGP state = Established"* ]]; then
		dropped=1
		break
	fi
	sleep 1
done
if [ "$dropped" -ne 1 ]; then
	echo "FAIL: Packeteer routes still on the edge ${hold}s after SIGKILL: [$(echo $got)]" >&2
	dump
	exit 1
fi
echo "session lost and every route gone $(($(date +%s) - start))s after SIGKILL (hold ${hold}s)"

echo "e2e synthesize ok"
