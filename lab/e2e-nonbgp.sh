#!/bin/bash
# Non-BGP mode (#300) against a simulated Linux router with two links and no
# BGP. Packeteer runs in the router's network namespace with the linux
# steerer, as on a real Linux router; the router container keeps the
# namespace, so a killed Packeteer leaves its routes behind. Documentation
# prefixes and a documentation ASN only. Lab only: these routes are derived from
# flow data, not from a learned BGP RIB view.
#
# lab/sendflow sends NetFlow v5 for 203.0.113.7 (allowlisted) and
# 198.51.100.77 (not allowlisted). The fixed prober makes isp-b faster.
# Checked on the router's main table on every step: no route with proto 250
# other than 203.0.113.0/24, and only through isp-b's gateway.
#  1. install: 203.0.113.0/24 via 198.51.100.1 proto 250; the start-up
#     warning is logged;
#  2. withdraw: isp-b's probe source fails, the route is removed; it comes
#     back when the source does;
#  3. SIGTERM removes the route; a restart installs it again;
#  4. crash: after kill -9 the route stays (no lease on the router), and the
#     next start, with no flow, sweeps it before the first round.
set -euo pipefail
export LC_ALL=C

root=$(cd "$(dirname "$0")/.." && pwd)
cd "$root"
compose=(docker compose -f lab/docker-compose-nonbgp.yml)

flow_bin=$(mktemp)
rates=$(mktemp)
PACKETEER_NONBGP_FIXED=$(mktemp -d)
export PACKETEER_NONBGP_FIXED
chmod 755 "$PACKETEER_NONBGP_FIXED"
flow_pid=
trap 'rc=$?; if [ -n "$flow_pid" ]; then kill "$flow_pid" 2>/dev/null || true; fi; if [ "$rc" -ne 0 ]; then echo "---- lab logs ----"; "${compose[@]}" logs --no-color || true; "${compose[@]}" ps || true; fi; "${compose[@]}" down -v --remove-orphans || true; rm -rf "$flow_bin" "$rates" "$rates.tmp" "$PACKETEER_NONBGP_FIXED"; exit "$rc"' EXIT

# set_paths ISP_B_SOURCE_DOWN: isp-a 90ms, isp-b 20ms, isp-b's source up
# (false) or failed (true). Swapped in atomically; the prober re-reads it.
set_paths() {
	printf 'paths:\n  - {provider: isp-a, rtt_ms: 90}\n  - {provider: isp-b, rtt_ms: 20, source_down: %s}\n' "$1" >"$PACKETEER_NONBGP_FIXED/paths.tmp"
	chmod 644 "$PACKETEER_NONBGP_FIXED/paths.tmp"
	mv "$PACKETEER_NONBGP_FIXED/paths.tmp" "$PACKETEER_NONBGP_FIXED/paths.yaml"
}
set_paths false

echo "building flow sender"
go build -o "$flow_bin" ./lab/sendflow

echo "building lab"
"${compose[@]}" build
"${compose[@]}" up -d

routes() { "${compose[@]}" exec -T router ip -4 route show proto 250 2>/dev/null || true; }

dump() {
	"${compose[@]}" exec -T router ip route show >&2 || true
	"${compose[@]}" logs --no-color packeteer >&2 || true
}

# check: the only proto 250 route ever is 203.0.113.0/24 via isp-b.
check() {
	local r
	r=$(routes)
	if [ -n "$r" ] && ! grep -Eq '^203\.0\.113\.0/24 via 198\.51\.100\.1 ' <<<"$r"; then
		echo "FAIL: unexpected Packeteer route on the router: $r" >&2
		dump
		exit 1
	fi
	if [ "$(grep -c . <<<"$r" || true)" -gt 1 ]; then
		echo "FAIL: more than one Packeteer route: $r" >&2
		dump
		exit 1
	fi
}

# want_route yes|no WHY: wait up to 90s for 203.0.113.0/24 to be there or gone.
want_route() {
	local want=$1 why=$2 i r
	for i in $(seq 1 90); do
		check
		r=$(routes)
		if [ "$want" = yes ] && [ -n "$r" ]; then return 0; fi
		if [ "$want" = no ] && [ -z "$r" ]; then return 0; fi
		sleep 1
	done
	echo "FAIL: $why (routes: '$(routes)')" >&2
	dump
	exit 1
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

echo "waiting for iproute2 on the router"
for i in $(seq 1 60); do
	"${compose[@]}" exec -T router test -e /tmp/ready && break
	sleep 2
done
"${compose[@]}" exec -T router ip -V | grep -q iproute2 || {
	echo "FAIL: iproute2 is not installed on the router" >&2
	dump
	exit 1
}

need_log 'non-BGP mode is on. Its static routes are derived from flow data, NOT from a learned BGP RIB view' "no start-up warning"

printf '%s\n' "203.0.113.7 tcp 1" "198.51.100.77 tcp 1" >"$rates.tmp"
mv "$rates.tmp" "$rates"
"$flow_bin" -to 192.0.2.10:2055 -rates "$rates" -every 200ms &
flow_pid=$!

echo "1. install: 203.0.113.0/24 through isp-b's gateway"
want_route yes "no static route for 203.0.113.0/24"
need_log 'non-BGP: steered.*prefix=203.0.113.0/24 provider=isp-b' "install not logged"

echo "2. withdraw: isp-b's probe source fails"
set_paths true
want_route no "the route stayed after isp-b's probe source failed"
need_log 'non-BGP: route removed.*prefix=203.0.113.0/24' "withdraw not logged"
set_paths false
want_route yes "the route did not come back with isp-b's probe source"

echo "3. SIGTERM removes the route"
"${compose[@]}" stop -t 20 packeteer
if [ -n "$(routes)" ]; then
	echo "FAIL: route left after SIGTERM: $(routes)" >&2
	dump
	exit 1
fi
echo "restarting packeteer"
"${compose[@]}" start packeteer
want_route yes "no route after the restart"

echo "4. kill -9 leaves the route; the next start sweeps it"
cid=$("${compose[@]}" ps -q packeteer)
if [ -z "$cid" ]; then
	echo "packeteer is not running" >&2
	exit 1
fi
docker kill -s KILL "$cid"
kill "$flow_pid"
wait "$flow_pid" 2>/dev/null || true
flow_pid=
sleep 3
if [ -z "$(routes)" ]; then
	echo "FAIL: the route vanished after kill -9; the sweep below proves nothing" >&2
	dump
	exit 1
fi
echo "route still on the router after kill -9, as documented: $(routes)"
"${compose[@]}" start packeteer
want_route no "the next start did not sweep the route a killed run left"
need_log 'removed a route left on the router by an earlier run.*prefix=203.0.113.0/24' "sweep not logged"

"${compose[@]}" stop -t 20 packeteer
check
echo "PASS: non-BGP install, withdraw, SIGTERM, and kill -9 sweep"
