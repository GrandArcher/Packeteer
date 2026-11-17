#!/bin/bash
# Shared IX port headroom for performance moves (#643) against the simulated
# FRR routers of the IX lab (lab/docker-compose-ix.yml). Documentation
# prefixes and documentation/private ASNs only.
#
# ix-lab has a 1000 Mbps port with a 600 Mbps commit; its usage is a fixed
# telemetry row the script rewrites. 198.51.100.0/24 carries 60 Mbps and
# ix-peer-a is faster than native transit-a, so a performance move onto
# ix-peer-a is wanted (ix-peer-b is faster still but has no route for the
# /24).
#
# Observe (lab/packeteer-ix-port.yaml as is):
#  1. The port is at 580 Mbps: the move would take it to 640 of 600, so it
#     is not recommended; the decision names the port and the port gate.
#  2. The port falls to 300 Mbps: the move is recommended, nothing reaches
#     the edge.
#  3. The port rises to 700 Mbps: over_commit on /api/exchanges and
#     commit.exceeded naming the exchange; the recommendation stays.
# Lab inject (the same file with mode: inject, after a restart):
#  4. The port is at 580 Mbps: nothing is announced.
#  5. The port falls to 300 Mbps: the route goes to the edge via ix-peer-a
#     with the community and NO_EXPORT.
#  6. The port rises to 700 Mbps: flagged, and the route stays (nothing is
#     moved off a port over its commit).
#  7. SIGTERM withdraws.
#  8. Restart with room, steer, SIGKILL: the route drops with the session
#     (no graceful restart).
set -euo pipefail

root=$(cd "$(dirname "$0")/.." && pwd)
cd "$root"
compose=(docker compose -f lab/docker-compose-ix.yml)

lab_dir=$(mktemp -d)
check_bin=$(mktemp)
trap 'rc=$?; if [ "$rc" -ne 0 ]; then echo "---- lab logs ----"; "${compose[@]}" logs --no-color || true; "${compose[@]}" ps || true; fi; "${compose[@]}" down -v --remove-orphans || true; rm -f "$check_bin"; rm -rf "$lab_dir"; exit "$rc"' EXIT

echo "building path check"
go build -o "$check_bin" ./lab/checkpath

inject=$(sed 's/^mode: observe$/mode: inject/' lab/packeteer-ix-port.yaml)
if [ "$inject" = "$(cat lab/packeteer-ix-port.yaml)" ]; then
	echo "could not build the inject config" >&2
	exit 1
fi

cp lab/probes/ix-equal.yaml "$lab_dir/state.yaml"
cp lab/probes/ix-port-full.yaml "$lab_dir/usage.yaml"
cp lab/packeteer-ix-port.yaml "$lab_dir/config.yaml"
chmod 0755 "$lab_dir"
chmod 0644 "$lab_dir/state.yaml" "$lab_dir/usage.yaml" "$lab_dir/config.yaml"
export PACKETEER_LAB_DIR="$lab_dir"

echo "building lab"
"${compose[@]}" build
"${compose[@]}" up -d

prefix=198.51.100.0/24

router_json() {
	"${compose[@]}" exec -T "$1" vtysh -c "show bgp ipv4 unicast $prefix json" 2>/dev/null || true
}

steered() {
	router_json edge | "$check_bin" -has 64512:666 -has no-export -nexthop 203.0.113.11 -aspath "64501 64501 64501"
}

native() {
	router_json edge | "$check_bin" -aspath 64496 -lacks 64512:666
}

no_packeteer_path() {
	! grep -q '64512:666' <<<"$(router_json edge)"
}

api() {
	"${compose[@]}" exec -T packeteer wget -qO- "http://127.0.0.1:8080$1" 2>/dev/null || true
}

dump() {
	"${compose[@]}" exec -T edge vtysh -c 'show bgp summary' >&2 || true
	"${compose[@]}" exec -T edge vtysh -c "show bgp ipv4 unicast $prefix" >&2 || true
	for p in /api/exchanges /api/telemetry /api/improvements "/api/decisions/$prefix"; do
		echo "---- $p ----" >&2
		api "$p" >&2
		echo >&2
	done
	"${compose[@]}" logs --no-color packeteer >&2 || true
}

fail() {
	echo "$1" >&2
	dump
	exit 1
}

wait_for() {
	local what=$1 tries=$2
	shift 2
	local i
	for i in $(seq 1 "$tries"); do
		if "$@" 2>/dev/null; then
			return 0
		fi
		sleep 2
	done
	fail "timed out waiting for: $what"
}

# api_has <path> <jq>: the response matches.
api_has() {
	api "$1" | jq -e "$2" >/dev/null 2>&1
}

# The logs are read into a variable first: with pipefail, grep -q exiting
# on the first match would SIGPIPE docker compose logs and fail the check.
log_has() {
	local logs
	logs=$("${compose[@]}" logs --no-color packeteer)
	grep -qE -- "$1" <<<"$logs"
}

flip() {
	local tmp
	tmp=$(mktemp "$lab_dir/.flip.XXXXXX")
	cp "$1" "$tmp"
	chmod 0644 "$tmp"
	mv "$tmp" "$lab_dir/$2"
}

# hold <seconds> <what> <check>: the check holds the whole time.
hold() {
	local i
	for i in $(seq 1 "$1"); do
		"$3" || fail "$2"
		sleep 1
	done
}

refused='.action == "none" and .recommended == "ix-peer-a" and (.reason | startswith("exchange port: ix-lab 95th would reach 640 of its 600 Mbps commit")) and .explain.blocked_by == "port"'
recommended='[.improvements[] | select(.prefix == "198.51.100.0/24" and .provider == "ix-peer-a")] | length == 1'
none_recommended='(.improvements | length) == 0'
over_commit='.exchanges[0].port as $p | $p.state == "ok" and $p.over_commit == true and $p.p95_mbps == 700'
exceeded='[.events[] | select(.kind == "commit.exceeded" and .fields.exchange == "ix-lab" and .fields.commit_mbps == "600.0")] | length >= 1'

echo "observe 1. the port is at 580 of its 600 Mbps commit: the move is not recommended"
wait_for "add-path negotiated" 45 log_has 'bgp add-path negotiated'
wait_for "edge on transit-a" 30 native
flip lab/probes/ix.yaml state.yaml
wait_for "decision refused by the port" 30 api_has "/api/decisions/$prefix" "$refused"
api_has /api/improvements "$none_recommended" || fail "a move the port cannot take was recommended"
api_has /api/exchanges '.exchanges[0].port as $p | $p.state == "ok" and $p.over_commit == false and $p.headroom_mbps == 20' || fail "port headroom"

echo "observe 2. the port falls to 300 Mbps: the move is recommended, not announced"
flip lab/probes/ix-port-room.yaml usage.yaml
wait_for "recommendation onto ix-peer-a" 30 api_has /api/improvements "$recommended"
hold 4 "observe announced a route" no_packeteer_path

echo "observe 3. the port rises to 700 Mbps: flagged over its commit, report only"
flip lab/probes/ix-port-over.yaml usage.yaml
wait_for "over_commit on /api/exchanges" 30 api_has /api/exchanges "$over_commit"
wait_for "commit.exceeded for the port" 45 api_has '/api/events?limit=1000' "$exceeded"
api_has /api/improvements "$recommended" || fail "the recommendation was moved off the port"
no_packeteer_path || fail "observe announced a route"

echo "inject 4. restart in lab inject with the port at 580 Mbps: nothing is announced"
"${compose[@]}" stop -t 20 packeteer
flip lab/probes/ix-port-full.yaml usage.yaml
printf '%s\n' "$inject" >"$lab_dir/config.yaml"
"${compose[@]}" start packeteer
wait_for "decision refused by the port in inject" 60 api_has "/api/decisions/$prefix" "$refused"
hold 6 "a move the port cannot take was announced" no_packeteer_path
if log_has "msg=injected .*provider=ix-peer-a "; then
	fail "Packeteer announced toward ix-peer-a while the port was full"
fi

echo "inject 5. the port falls to 300 Mbps: the route goes to the edge via ix-peer-a"
flip lab/probes/ix-port-room.yaml usage.yaml
wait_for "edge best is Packeteer's route via ix-peer-a" 45 steered

echo "inject 6. the port rises to 700 Mbps: flagged, the route stays"
flip lab/probes/ix-port-over.yaml usage.yaml
wait_for "over_commit on /api/exchanges" 30 api_has /api/exchanges "$over_commit"
hold 8 "the route was moved off a port over its commit" steered

echo "inject 7. SIGTERM withdraws"
"${compose[@]}" stop -t 20 packeteer
wait_for "route gone after SIGTERM" 15 no_packeteer_path
wait_for "edge on transit-a" 5 native

echo "inject 8. restart with room, steer, SIGKILL: the route drops with the session"
flip lab/probes/ix-port-room.yaml usage.yaml
"${compose[@]}" start packeteer
wait_for "steer after restart" 60 steered
hold_timer=$(awk '$1 == "neighbor" && $2 == "192.0.2.10" && $3 == "timers" { print $5 }' lab/frr-ix-edge/frr.conf)
case "$hold_timer" in
'' | *[!0-9]*)
	echo "lab hold timer is not an integer: '${hold_timer}'" >&2
	exit 1
	;;
esac
cid=$("${compose[@]}" ps -q packeteer)
[ -n "$cid" ] || fail "packeteer is not running"
docker kill -s KILL "$cid"
wait_for "route gone after SIGKILL" $(((hold_timer + 6) / 2)) no_packeteer_path
wait_for "edge on transit-a after SIGKILL" 5 native

echo "IX port e2e ok"
