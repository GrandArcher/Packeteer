#!/bin/bash
# BMP monitoring station (#26) against a simulated FRR edge that streams BMP
# (pre-policy Adj-RIB-In and Loc-RIB) to Packeteer, plus two simulated eBGP
# transits. Documentation prefixes and documentation/private ASNs only.
#
# Both transits send 198.51.100.0/24; transit-b prepends, so the edge keeps
# its path inactive and the iBGP session to Packeteer only carries
# transit-a's. transit-b (bmp: only) is the faster probed path, so:
#
#  1. Packeteer steers to transit-b because BMP shows its inactive path.
#  2. transit-b withdraws: the edge now hides nothing from BMP, but its best
#     is still Packeteer's own route (the edge reports that back over BMP,
#     and Packeteer must ignore it). The route check retires the
#     improvement at once, inside the 5m hold_time.
#  3. transit-b re-announces: Packeteer steers again.
#  4. The edge drops its BMP session: transit-b has no paths left, so the
#     improvement retires (RIB-source loss withdraws).
#  5. BMP comes back: steer again; SIGTERM withdraws.
set -euo pipefail

root=$(cd "$(dirname "$0")/.." && pwd)
cd "$root"
compose=(docker compose -f lab/docker-compose-bmp.yml)

lab_dir=$(mktemp -d)
check_bin=$(mktemp)
trap 'rc=$?; if [ "$rc" -ne 0 ]; then echo "---- lab logs ----"; "${compose[@]}" logs --no-color || true; "${compose[@]}" ps || true; fi; "${compose[@]}" down -v --remove-orphans || true; rm -f "$check_bin"; rm -rf "$lab_dir"; exit "$rc"' EXIT

echo "building path check"
go build -o "$check_bin" ./lab/checkpath

cp lab/probes/prefer-b.yaml "$lab_dir/state.yaml"
chmod 0644 "$lab_dir/state.yaml"
export PACKETEER_LAB_DIR="$lab_dir"

echo "building lab"
"${compose[@]}" build
"${compose[@]}" up -d

prefix=198.51.100.0/24

edge_json() {
	"${compose[@]}" exec -T edge vtysh -c "show bgp ipv4 unicast $prefix json" 2>/dev/null || true
}

# injected: the edge's best path is Packeteer's route. Packeteer only
# steers this prefix to transit-b (its next hop, 192.0.2.22).
injected() {
	edge_json | "$check_bin" -has 64512:666
}

# native: the edge's best path is transit-a's, and nothing of Packeteer's.
native() {
	edge_json | "$check_bin" -aspath 64496 -lacks 64512:666
}

no_packeteer_path() {
	! grep -q '64512:666' <<<"$(edge_json)"
}

dump_bgp() {
	for r in edge transit-a transit-b; do
		echo "---- $r ----" >&2
		"${compose[@]}" exec -T "$r" vtysh -c 'show bgp summary' >&2 || true
		"${compose[@]}" exec -T "$r" vtysh -c "show bgp ipv4 unicast $prefix" >&2 || true
	done
	"${compose[@]}" exec -T edge vtysh -c 'show bmp' >&2 || true
	"${compose[@]}" logs --no-color packeteer >&2 || true
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
	echo "timed out waiting for: $what" >&2
	"$@" || true
	dump_bgp
	return 1
}

packeteer_logs() { "${compose[@]}" logs --no-color packeteer; }

# The logs are read into a variable first: with pipefail, grep -q exiting
# on the first match would SIGPIPE docker compose logs and fail the check.
log_count() {
	local logs
	logs=$(packeteer_logs)
	grep -cF "$1" <<<"$logs" || true
}

log_has() {
	local logs
	logs=$(packeteer_logs)
	grep -qE "$1" <<<"$logs"
}

need_log() {
	if [ "$(log_count "$1")" -lt "${2:-1}" ]; then
		echo "packeteer log is missing: $1 (want ${2:-1})" >&2
		dump_bgp
		exit 1
	fi
}

transit_b() {
	"${compose[@]}" exec -T transit-b vtysh -c 'configure terminal' -c 'router bgp 64497' \
		-c 'address-family ipv4 unicast' -c "$1"
}

edge_bmp() {
	"${compose[@]}" exec -T edge vtysh -c 'configure terminal' -c 'router bgp 64512' "$@"
}

# Retire must come from the route check, well inside hold_time (5m).
retired_by_route_check() {
	local want=$1
	local n
	n=$(log_count 'no route via provider (bmp)')
	[ "$n" -ge "$want" ]
}

echo "1. inactive transit-b path over BMP: waiting for the steer"
wait_for "bmp session" 45 log_has 'bmp session up'
wait_for "edge best is Packeteer's route via transit-b" 45 injected
need_log 'msg=injected'
# The iBGP feed alone never showed transit-b: the edge only sends its best.
if "${compose[@]}" exec -T edge vtysh -c "show bgp ipv4 unicast neighbors 192.0.2.10 advertised-routes" 2>/dev/null | grep -q '192.0.2.22'; then
	echo "edge advertised transit-b's path over iBGP; the lab does not prove BMP" >&2
	dump_bgp
	exit 1
fi

echo "2. transit-b withdraws: the route check must retire inside hold_time"
start=$(date +%s)
transit_b "no network $prefix"
wait_for "edge back on transit-a" 15 native
wait_for "retire logged from the route check" 5 retired_by_route_check 1
echo "withdrawn $(( $(date +%s) - start ))s after transit-b's withdraw (hold_time 5m)"
# Nothing (including Packeteer's own route reported back over BMP) may
# bring the steer back while transit-b has no path.
for _ in $(seq 1 5); do
	if ! no_packeteer_path; then
		echo "Packeteer re-injected onto transit-b while it had no path" >&2
		dump_bgp
		exit 1
	fi
	sleep 2
done

echo "3. transit-b re-announces: steer again"
transit_b "network $prefix"
wait_for "steer again" 30 injected

echo "4. edge drops its BMP session: the improvement must retire"
edge_bmp -c 'no bmp targets packeteer'
wait_for "edge back on transit-a after BMP loss" 15 native
wait_for "bmp session down logged" 10 log_has 'bmp session (down|ended)'
# Without BMP, transit-b (only) has no path, and the edge hides transit-a
# from iBGP while Packeteer's route is best, so the retire is either the
# route check or the prefix leaving the view.
retires() { [ "$(log_count 'msg="improvement retired"')" -ge "$1" ]; }
wait_for "second retire logged" 5 retires 2
for _ in $(seq 1 3); do
	if ! no_packeteer_path; then
		echo "Packeteer injected onto transit-b without a BMP feed (bmp: only)" >&2
		dump_bgp
		exit 1
	fi
	sleep 2
done

echo "5. BMP back: steer again, then SIGTERM withdraws"
edge_bmp -c 'bmp targets packeteer' -c 'bmp monitor ipv4 unicast pre-policy' \
	-c 'bmp monitor ipv4 unicast loc-rib' -c 'bmp connect 192.0.2.10 port 11019 min-retry 1000 max-retry 2000'
wait_for "steer after BMP returns" 30 injected
"${compose[@]}" kill -s SIGTERM packeteer
wait_for "route gone after SIGTERM" 15 no_packeteer_path
wait_for "edge on transit-a" 5 native

echo "bmp e2e ok"
