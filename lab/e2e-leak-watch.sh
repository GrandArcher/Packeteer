#!/bin/bash
# Leak watch (#199) against a simulated FRR edge and a simulated router
# outside the AS ("ext") that streams its Adj-RIB-In to Packeteer over BMP.
# Documentation prefixes and private ASNs only.
#
# The edge originates 198.51.100.0/24 and 203.0.113.0/24, which Packeteer
# injects (transit-b is the faster probed path), and 192.0.2.64/26, an own
# prefix that is meant to be seen outside. Packeteer's routes carry
# 64512:666 and no-export. Checked on the routers:
#  1. both /24s are injected, tagged, and best on the edge;
#  2. a clean run: for 40s ext sees only 192.0.2.64/26, nothing is flagged,
#     and both routes stay (no false positive, no flap);
#  3. the edge is misconfigured the way a real one is: its import policy
#     strips communities and its export filter lets 203.0.113.0/24 through.
#     ext receives the route, the leak watch sees it over BMP, and withdraws
#     203.0.113.0/24 alone. 198.51.100.0/24 stays. The prefix stays out
#     across decision rounds;
#  4. the misconfiguration is fixed and the operator clears the hold: the
#     route returns, tagged, and ext never sees it again;
#  5. ext stops sending BMP: the watch reports unknown, and no route moves;
#  6. SIGTERM withdraws every route, a restart injects both again;
#  7. SIGKILL: every route drops with the session within the hold timer.
set -euo pipefail
export LC_ALL=C

root=$(cd "$(dirname "$0")/.." && pwd)
cd "$root"
compose=(docker compose -f lab/docker-compose-leak-watch.yml)

check_bin=$(mktemp)
trap 'rc=$?; if [ "$rc" -ne 0 ]; then echo "---- lab logs ----"; "${compose[@]}" logs --no-color || true; "${compose[@]}" ps || true; fi; "${compose[@]}" down -v --remove-orphans || true; rm -f "$check_bin"; exit "$rc"' EXIT

echo "building route-set check"
go build -o "$check_bin" ./lab/checkms

echo "building lab"
"${compose[@]}" build
"${compose[@]}" up -d

api=http://192.0.2.10:8080/api/leaks
both="198.51.100.0/24 203.0.113.0/24"

edge() { "${compose[@]}" exec -T edge vtysh "$@"; }
ext() { "${compose[@]}" exec -T ext vtysh "$@"; }
creds=lab:lab-only
leaks() { curl -sS -u "$creds" "$api"; }

dump() {
	edge -c 'show bgp summary' -c 'show bgp ipv4 unicast' >&2 || true
	ext -c 'show bgp summary' -c 'show bgp ipv4 unicast' -c 'show bmp' >&2 || true
	leaks >&2 || true
	"${compose[@]}" logs --no-color packeteer >&2 || true
}

# sample sets got to the prefixes Packeteer has on the edge, sorted.
got=
sample() {
	local out
	got="?"
	out=$(edge -c 'show bgp ipv4 unicast json' 2>/dev/null) || return 1
	out=$(printf '%s\n' "$out" | "$check_bin") || return 1
	got=$out
}

want_set() {
	local want i
	want=$(printf '%s\n' "$@" | grep . | sort || true)
	for i in $(seq 1 60); do
		if sample && [ "$got" = "$want" ]; then
			echo "edge has $(printf '%s\n' "$got" | grep -c . || true) Packeteer routes: $(echo $got)"
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

# tagged prefix: Packeteer's path is best here and carries transit-b's next
# hop, local-pref 250, the packeteer community, and no-export.
tagged() {
	local text
	text=$(edge -c "show bgp ipv4 unicast $1" 2>/dev/null || true)
	if [[ "$text" != *"192.0.2.2 from 192.0.2.10"* ]] || [[ "$text" != *"localpref 250"* ]] || [[ "$text" != *"Community: 64512:666 no-export"* ]]; then
		echo "FAIL: $1 from Packeteer is not tagged (next hop, local-pref, community, no-export)" >&2
		printf '%s\n' "$text" >&2
		dump
		exit 1
	fi
}

ext_has() { [[ "$(ext -c "show bgp ipv4 unicast $1" 2>/dev/null || true)" == *"BGP routing table entry for $1"* ]]; }

need_log() {
	local pattern=$1 why=$2 i
	for i in $(seq 1 30); do
		if "${compose[@]}" logs --no-color packeteer 2>/dev/null | grep -Eq "$pattern"; then
			return 0
		fi
		sleep 1
	done
	echo "FAIL: $why (no log matching: $pattern)" >&2
	dump
	exit 1
}

# state wanted: wait for the leak watch to report that state.
state() {
	local i
	for i in $(seq 1 40); do
		if [ "$(leaks | jq -r .state)" = "$1" ]; then
			return 0
		fi
		sleep 1
	done
	echo "FAIL: leak watch state is not $1" >&2
	dump
	return 1
}

echo "1. both /24s are injected and tagged"
# shellcheck disable=SC2086
want_set $both
for p in $both; do
	tagged "$p"
done

echo "2. clean run: ext sees only the own prefix, nothing is flagged"
state watching
for i in $(seq 1 40); do
	for p in $both; do
		if ext_has "$p"; then
			echo "FAIL: ext received $p in a clean run" >&2
			dump
			exit 1
		fi
	done
	sleep 1
done
if ! ext_has 192.0.2.64/26; then
	echo "FAIL: ext did not receive the own prefix 192.0.2.64/26" >&2
	dump
	exit 1
fi
if [ "$(leaks | jq '.leaks | length')" != 0 ]; then
	echo "FAIL: false positive in a clean run" >&2
	dump
	exit 1
fi
# shellcheck disable=SC2086
want_set $both

echo "3. a misconfigured export leaks 203.0.113.0/24: only that route is withdrawn"
edge -c 'configure terminal' \
	-c 'route-map from-packeteer permit 5' -c 'match community packeteer' -c 'set community none' -c 'set weight 40000' -c 'exit' \
	-c 'ip prefix-list ext-ok seq 20 permit 203.0.113.0/24' -c 'end'
edge -c 'clear bgp ipv4 unicast 192.0.2.10 soft in'
edge -c 'clear bgp ipv4 unicast 192.0.2.30 soft out'
want_set 198.51.100.0/24
need_log 'route seen outside the AS; held out until cleared.*prefix=203.0.113.0/24 reason=as_path action=withdrawn' "leak not logged"
body=$(leaks)
if [ "$(printf '%s' "$body" | jq -r '.leaks | map(.prefix) | join(",")')" != 203.0.113.0/24 ] ||
	[ "$(printf '%s' "$body" | jq -r '.leaks[0].reason')" != as_path ] ||
	[ "$(printf '%s' "$body" | jq -r '.leaks[0].action')" != withdrawn ]; then
	echo "FAIL: /api/leaks does not show 203.0.113.0/24 as an as_path leak, withdrawn" >&2
	printf '%s\n' "$body" >&2
	dump
	exit 1
fi
tagged_ok=$(edge -c 'show bgp ipv4 unicast 198.51.100.0/24' 2>/dev/null || true)
if [[ "$tagged_ok" != *"192.0.2.2 from 192.0.2.10"* ]]; then
	echo "FAIL: the unleaked route 198.51.100.0/24 was disturbed" >&2
	dump
	exit 1
fi
stay_set 20 198.51.100.0/24

echo "4. fixed and cleared: the route returns, tagged, and stays inside the AS"
edge -c 'configure terminal' -c 'no route-map from-packeteer permit 5' -c 'no ip prefix-list ext-ok seq 20' -c 'end'
edge -c 'clear bgp ipv4 unicast 192.0.2.10 soft in'
edge -c 'clear bgp ipv4 unicast 192.0.2.30 soft out'
code=$(curl -sS -o /dev/null -w '%{http_code}' -u "$creds" -H 'Content-Type: application/json' -d '{"prefix":"203.0.113.0/24"}' "$api/clear")
if [ "$code" != 204 ]; then
	echo "FAIL: clear answered $code" >&2
	dump
	exit 1
fi
# shellcheck disable=SC2086
want_set $both
for p in $both; do
	tagged "$p"
done
sleep 15
for p in $both; do
	if ext_has "$p"; then
		echo "FAIL: ext sees $p after the fix" >&2
		dump
		exit 1
	fi
done
if [ "$(leaks | jq '.leaks | length')" != 0 ]; then
	echo "FAIL: leak flagged again after the fix" >&2
	dump
	exit 1
fi
# shellcheck disable=SC2086
want_set $both

echo "5. ext stops its BMP feed: unknown, and no route moves"
"${compose[@]}" stop -t 10 ext
state unknown
# shellcheck disable=SC2086
stay_set 10 $both
"${compose[@]}" start ext
state watching
# shellcheck disable=SC2086
want_set $both

echo "6. SIGTERM withdraws every route"
"${compose[@]}" stop -t 20 packeteer
want_set
echo "restarting packeteer"
"${compose[@]}" start packeteer
# shellcheck disable=SC2086
want_set $both

echo "7. SIGKILL: routes drop with the session"
hold=$(awk '$1 == "neighbor" && $2 == "192.0.2.10" && $3 == "timers" { print $5 }' lab/frr-leak-edge/frr.conf)
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

echo "e2e leak watch ok"
