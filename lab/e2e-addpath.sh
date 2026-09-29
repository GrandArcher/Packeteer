#!/bin/bash
# BGP add-path on the iBGP session (#26) against a simulated FRR edge that
# sends Packeteer every path (addpath-tx-all-paths), plus two simulated eBGP
# transits. No BMP. Documentation prefixes and documentation/private ASNs
# only.
#
# Both transits send 198.51.100.0/24; transit-b prepends, so the edge keeps
# its path inactive. Without add-path the iBGP session would carry only
# transit-a's. transit-b (add_path route check) is the faster probed path:
#
#  1. Add-path is negotiated; Packeteer sees transit-b's inactive path (path
#     ID) and steers to it. While Packeteer's route is best, the edge still
#     sends transit-a's native path.
#  2. transit-b withdraws: the add-path route check retires the improvement
#     at once, inside the 5m hold_time, and nothing re-injects.
#  3. transit-b re-announces: Packeteer steers again.
#  4. SIGTERM withdraws.
#  5. Restart, steer again, SIGKILL: the route drops with the session (no
#     graceful restart).
set -euo pipefail

root=$(cd "$(dirname "$0")/.." && pwd)
cd "$root"
compose=(docker compose -f lab/docker-compose-addpath.yml)

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

# injected: the edge's best path is Packeteer's route.
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

# glass: Packeteer's looking glass for the prefix (every learned path).
glass() {
	"${compose[@]}" exec -T packeteer wget -qO- "http://127.0.0.1:8080/api/troubleshoot/lookingglass?prefix=$prefix" 2>/dev/null || true
}

# glass_has_path <next hop>: Packeteer holds an add-path path via that hop.
glass_has_path() {
	local g
	g=$(glass)
	grep -qF "\"next_hop\":\"$1\"" <<<"$g" && grep -q '"path_id":[1-9]' <<<"$g"
}

dump_bgp() {
	for r in edge transit-a transit-b; do
		echo "---- $r ----" >&2
		"${compose[@]}" exec -T "$r" vtysh -c 'show bgp summary' >&2 || true
		"${compose[@]}" exec -T "$r" vtysh -c "show bgp ipv4 unicast $prefix" >&2 || true
	done
	"${compose[@]}" exec -T edge vtysh -c 'show bgp neighbors 192.0.2.10' >&2 || true
	"${compose[@]}" exec -T edge vtysh -c 'show bgp ipv4 unicast neighbors 192.0.2.10 advertised-routes' >&2 || true
	echo "---- packeteer looking glass / providers / decisions ----" >&2
	glass >&2
	echo >&2
	"${compose[@]}" exec -T packeteer wget -qO- http://127.0.0.1:8080/api/providers >&2 || true
	echo >&2
	"${compose[@]}" exec -T packeteer wget -qO- http://127.0.0.1:8080/api/decisions >&2 || true
	echo >&2
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

retired_by_route_check() {
	[ "$(log_count 'no route via provider (route check)')" -ge "$1" ]
}

echo "1. add-path: inactive transit-b path on the iBGP session, waiting for the steer"
wait_for "add-path negotiated" 45 log_has 'bgp add-path negotiated'
wait_for "edge best is Packeteer's route via transit-b" 90 injected
need_log 'msg=injected'
# Packeteer learned transit-b's path over add-path (no BMP in this lab),
# and still holds transit-a's native path while its own route is best.
wait_for "transit-b path learned with a path ID" 10 glass_has_path 192.0.2.22
wait_for "native transit-a path still visible while steered" 10 glass_has_path 192.0.2.21

echo "2. transit-b withdraws: the add-path route check must retire inside hold_time"
start=$(date +%s)
transit_b "no network $prefix"
wait_for "edge back on transit-a" 15 native
wait_for "retire logged from the route check" 5 retired_by_route_check 1
echo "withdrawn $(($(date +%s) - start))s after transit-b's withdraw (hold_time 5m)"
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

echo "4. SIGTERM withdraws"
"${compose[@]}" stop -t 20 packeteer
wait_for "route gone after SIGTERM" 15 no_packeteer_path
wait_for "edge on transit-a" 5 native

echo "5. restart, steer again, SIGKILL: the route drops with the session"
"${compose[@]}" start packeteer
wait_for "steer after restart" 60 injected
hold=$(awk '$1 == "neighbor" && $2 == "192.0.2.10" && $3 == "timers" { print $5 }' lab/frr-addpath/frr.conf)
case "$hold" in
'' | *[!0-9]*)
	echo "lab hold timer is not an integer: '${hold}'" >&2
	exit 1
	;;
esac
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
	if [ "$(docker inspect -f '{{.State.Status}}' "$cid" 2>/dev/null || true)" = "exited" ]; then
		break
	fi
	sleep 0.2
done
if [ "$code" != "137" ]; then
	echo "expected SIGKILL exit 137, got ${code:-unknown}" >&2
	dump_bgp
	exit 1
fi
# Bounded by the hold timer (plus slack); usually the TCP reset is sooner.
wait_for "route gone after SIGKILL" $(((hold + 6) / 2)) no_packeteer_path
wait_for "edge on transit-a after SIGKILL" 5 native
echo "route gone $(($(date +%s) - start))s after SIGKILL (hold ${hold}s)"

echo "add-path e2e ok"
