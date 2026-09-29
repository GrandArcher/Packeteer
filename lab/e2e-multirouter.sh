#!/bin/bash
# Multiple edge routers and a route reflector (#27) against simulated FRR
# routers: edge-a (transit-a only), edge-b (transit-b only), a route
# reflector with both edges as clients, and the two simulated eBGP
# transits. Documentation prefixes and documentation/private ASNs only.
#
# Both transits send 198.51.100.0/24; transit-b prepends, so transit-a's
# path is native on both edges. transit-b is the faster probed path.
#
# Part 1, multi-edge (lab/packeteer-multirouter.yaml): Packeteer peers with
# both edges. edge-a reaches transit-b through edge-b.
#  1. The steer reaches edge-b with next hop transit-b and edge-a with next
#     hop edge-b.
#  2. edge-a's session drops: only edge-a loses the route; edge-b keeps it.
#     The session returns and edge-a gets the route again.
#  3. edge-b's session drops: it is transit-b's only egress, so the
#     improvement retires and edge-a is withdrawn too. Nothing re-injects
#     until the session returns; then the steer comes back on both.
#  4. SIGTERM withdraws on both edges.
#  5. Restart, steer, SIGKILL: the route drops on both edges with the
#     sessions (no graceful restart).
#
# Part 2, route reflector (lab/packeteer-rr.yaml): Packeteer peers with the
# route reflector only.
#  6. The steer is reflected to both edges with next hop transit-b.
#  7. SIGTERM withdraws on both edges.
#  8. Restart, steer, SIGKILL: the reflector drops the route with the
#     session and both edges return to transit-a.
set -euo pipefail

root=$(cd "$(dirname "$0")/.." && pwd)
cd "$root"
compose=(docker compose -f lab/docker-compose-multirouter.yml)

lab_dir=$(mktemp -d)
check_bin=$(mktemp)
trap 'rc=$?; if [ "$rc" -ne 0 ]; then echo "---- lab logs ----"; "${compose[@]}" logs --no-color || true; "${compose[@]}" ps || true; fi; "${compose[@]}" down -v --remove-orphans || true; rm -f "$check_bin"; rm -rf "$lab_dir"; exit "$rc"' EXIT

echo "building path check"
go build -o "$check_bin" ./lab/checkpath

cp lab/probes/prefer-b.yaml "$lab_dir/state.yaml"
chmod 0644 "$lab_dir/state.yaml"
export PACKETEER_LAB_DIR="$lab_dir"
export PACKETEER_LAB_CONFIG="$root/lab/packeteer-multirouter.yaml"

echo "building lab"
"${compose[@]}" build
"${compose[@]}" up -d

prefix=198.51.100.0/24

router_json() {
	"${compose[@]}" exec -T "$1" vtysh -c "show bgp ipv4 unicast $prefix json" 2>/dev/null || true
}

# injected <router> <next hop>: the router's best path is Packeteer's
# route with that next hop.
injected() {
	router_json "$1" | "$check_bin" -has 64512:666 -nexthop "$2"
}

# native <router>: the router's best path is transit-a's, and it carries
# nothing of Packeteer's.
native() {
	router_json "$1" | "$check_bin" -aspath 64496 -lacks 64512:666
}

no_packeteer_path() {
	! grep -q '64512:666' <<<"$(router_json "$1")"
}

both_native() { native edge-a && native edge-b; }
both_clean() { no_packeteer_path edge-a && no_packeteer_path edge-b; }

dump_bgp() {
	for r in rr edge-a edge-b transit-a transit-b; do
		echo "---- $r ----" >&2
		"${compose[@]}" exec -T "$r" vtysh -c 'show bgp summary' >&2 || true
		"${compose[@]}" exec -T "$r" vtysh -c "show bgp ipv4 unicast $prefix" >&2 || true
	done
	echo "---- packeteer providers / decisions ----" >&2
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

# The logs are read into a variable first: with pipefail, grep -q exiting
# on the first match would SIGPIPE docker compose logs and fail the check.
log_count() {
	local logs
	logs=$("${compose[@]}" logs --no-color packeteer)
	grep -cF "$1" <<<"$logs" || true
}

# session <router> down|up: shut or re-open the router's iBGP session to
# Packeteer.
session() {
	local cmd="neighbor 192.0.2.10 shutdown"
	if [ "$2" = up ]; then
		cmd="no $cmd"
	fi
	"${compose[@]}" exec -T "$1" vtysh -c 'configure terminal' -c 'router bgp 64512' -c "$cmd"
}

hold=$(awk '$1 == "neighbor" && $2 == "192.0.2.10" && $3 == "timers" { print $5 }' lab/frr-mr-rr/frr.conf)
case "$hold" in
'' | *[!0-9]*)
	echo "lab hold timer is not an integer: '${hold}'" >&2
	exit 1
	;;
esac
for r in edge-a edge-b; do
	if [ "$(awk '$1 == "neighbor" && $2 == "192.0.2.10" && $3 == "timers" { print $5 }' "lab/frr-mr-$r/frr.conf")" != "$hold" ]; then
		echo "$r hold timer differs from the route reflector's" >&2
		exit 1
	fi
done

# sigkill: kill Packeteer without a withdraw and wait until check passes,
# bounded by the hold timer (plus slack).
sigkill() {
	local cid code start
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
	wait_for "route gone on both edges after SIGKILL" $(((hold + 6) / 2)) both_clean
	echo "route gone $(($(date +%s) - start))s after SIGKILL (hold ${hold}s)"
	wait_for "both edges back on transit-a" 10 both_native
}

steered_multi() { injected edge-b 192.0.2.22 && injected edge-a 192.0.2.252; }

echo "== part 1: two edges, peered directly =="
wait_for "both edges on transit-a before the steer" 45 both_native
echo "1. steer: edge-b gets next hop transit-b, edge-a next hop edge-b"
wait_for "steer on both edges" 90 steered_multi
if [ "$(log_count 'announcer router')" -lt 2 ]; then
	echo "per-router export table not logged" >&2
	dump_bgp
	exit 1
fi

echo "2. edge-a's session drops: only edge-a loses the route"
session edge-a down
wait_for "edge-a back on transit-a" 15 native edge-a
for _ in $(seq 1 3); do
	if ! injected edge-b 192.0.2.22; then
		echo "edge-b lost the route when edge-a's session dropped" >&2
		dump_bgp
		exit 1
	fi
	sleep 2
done
session edge-a up
wait_for "edge-a gets the route again" 30 injected edge-a 192.0.2.252
wait_for "edge-b still steered" 5 injected edge-b 192.0.2.22

echo "3. edge-b's session drops: transit-b's only egress, both edges withdrawn"
retired_before=$(log_count 'egress router down')
session edge-b down
wait_for "edge-a withdrawn (transit-b egress down)" 15 native edge-a
wait_for "edge-b back on transit-a" 15 native edge-b
if [ "$(log_count 'egress router down')" -le "$retired_before" ]; then
	echo "retire was not logged as 'egress router down'" >&2
	dump_bgp
	exit 1
fi
for _ in $(seq 1 4); do
	if ! no_packeteer_path edge-a; then
		echo "Packeteer re-injected onto transit-b while its egress was down" >&2
		dump_bgp
		exit 1
	fi
	sleep 2
done
session edge-b up
wait_for "steer again on both edges" 45 steered_multi

echo "4. SIGTERM withdraws on both edges"
"${compose[@]}" stop -t 20 packeteer
wait_for "route gone on both edges after SIGTERM" 15 both_clean
wait_for "both edges on transit-a" 10 both_native

echo "5. restart, steer, SIGKILL"
"${compose[@]}" start packeteer
wait_for "steer after restart" 60 steered_multi
sigkill

echo "== part 2: route reflector =="
export PACKETEER_LAB_CONFIG="$root/lab/packeteer-rr.yaml"
"${compose[@]}" up -d --no-deps --force-recreate packeteer
steered_rr() { injected edge-a 192.0.2.22 && injected edge-b 192.0.2.22; }
echo "6. steer reflected to both edges with next hop transit-b"
wait_for "reflected steer on both edges" 90 steered_rr
if ! "${compose[@]}" exec -T rr vtysh -c "show bgp ipv4 unicast $prefix json" | "$check_bin" -has 64512:666 -nexthop 192.0.2.22; then
	echo "route reflector's best is not Packeteer's route" >&2
	dump_bgp
	exit 1
fi

echo "7. SIGTERM withdraws on both edges"
"${compose[@]}" stop -t 20 packeteer
wait_for "route gone on both edges after SIGTERM" 15 both_clean
wait_for "both edges on transit-a" 10 both_native

echo "8. restart, steer, SIGKILL"
"${compose[@]}" start packeteer
wait_for "reflected steer after restart" 60 steered_rr
sigkill

echo "multi-router e2e ok"
