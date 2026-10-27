#!/bin/bash
# Internet VRF and partial-table providers (#206) against simulated FRR
# routers. Documentation prefixes and documentation/private ASNs only.
# Lab-proven only, not on a public edge.
#
# The edge (lab/frr-vrf/frr.conf, the file docs/vrf.md shows) has its lab
# interface in a kernel VRF named internet (table 10). Both transit
# sessions and Packeteer's iBGP session are in that VRF; the default VRF
# holds a blackhole for 198.51.100.0/24. No provider sends a full table:
# transit-a sends 198.51.100.0/24 and a default route, transit-b a default
# route only. The fixed prober always finds transit-b faster.
#  1. Learn: the VRF's native path for 198.51.100.0/24 is transit-a's.
#  2. Decide and inject: Packeteer's route (next hop transit-b, 64512:666,
#     no-export) is best in the VRF BGP table and in the VRF's kernel
#     table; the main table keeps its blackhole, and transit-b never
#     receives the route.
#  3. Partial table: the default route and 203.0.113.0/24 (covered only by
#     the default route) are measured and never steered; /api/decisions
#     says why, and the edge has no Packeteer path for either.
#  4. SIGTERM withdraws inside the VRF.
#  5. Restart, steer, SIGKILL: the route leaves the VRF with the session,
#     within the hold timer (no graceful restart).
set -euo pipefail

root=$(cd "$(dirname "$0")/.." && pwd)
cd "$root"
compose=(docker compose -f lab/docker-compose-vrf.yml)

# The edge creates the VRF device; the host kernel needs the vrf module.
if ! sudo modprobe vrf 2>/dev/null; then
	sudo apt-get update -qq
	sudo apt-get install -y -qq "linux-modules-extra-$(uname -r)"
	sudo modprobe vrf
fi

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

edge() {
	"${compose[@]}" exec -T edge "$@"
}

api() {
	"${compose[@]}" exec -T packeteer wget -qO- "http://127.0.0.1:8080$1" 2>/dev/null || true
}

vrf_json() {
	edge vtysh -c "show bgp vrf internet ipv4 unicast $1 json" 2>/dev/null || true
}

injected() {
	vrf_json "$prefix" | "$check_bin" -has 64512:666 -has no-export -nexthop 192.0.2.22
}

native() {
	vrf_json "$prefix" | "$check_bin" -aspath 64496 -nexthop 192.0.2.21 -lacks 64512:666
}

no_packeteer_path() {
	! grep -q '64512:666' <<<"$(vrf_json "$1")"
}

# kernel_via <table args> <text>: the kernel route for the prefix in that
# table contains text.
kernel_via() {
	local out
	out=$(edge ip route show "${@:1:$#-1}" "$prefix" 2>/dev/null || true)
	[[ "$out" == *"${*: -1}"* ]]
}

dump_bgp() {
	for r in edge transit-a transit-b; do
		echo "---- $r ----" >&2
		"${compose[@]}" exec -T "$r" vtysh -c 'show bgp vrf all summary' >&2 || true
		"${compose[@]}" exec -T "$r" vtysh -c 'show bgp vrf all ipv4 unicast' >&2 || true
	done
	edge ip -d link show >&2 || true
	edge ip route show vrf internet >&2 || true
	edge ip route show table main >&2 || true
	echo "---- packeteer providers / decisions ----" >&2
	api /api/providers >&2
	echo >&2
	api /api/decisions >&2
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

fail() {
	echo "FAIL: $1" >&2
	dump_bgp
	exit 1
}

hold=$(awk '$1 == "neighbor" && $2 == "192.0.2.10" && $3 == "timers" { print $5 }' lab/frr-vrf/frr.conf)
case "$hold" in
'' | *[!0-9]*)
	echo "lab hold timer is not an integer: '${hold}'" >&2
	exit 1
	;;
esac

sigkill() {
	local cid code start
	cid=$("${compose[@]}" ps -q packeteer)
	[ -n "$cid" ] || fail "packeteer is not running"
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
	[ "$code" = "137" ] || fail "expected SIGKILL exit 137, got ${code:-unknown}"
	wait_for "route gone from the VRF after SIGKILL" $(((hold + 6) / 2)) no_packeteer_path "$prefix"
	echo "route gone $(($(date +%s) - start))s after SIGKILL (hold ${hold}s)"
	wait_for "VRF back on transit-a" 10 native
}

echo "1. learn: the native path in the VRF is transit-a's"
wait_for "native path in the VRF" 45 native
members=$(edge ip link show master internet 2>/dev/null || true)
[[ "$members" == *"master internet"* ]] || fail "the edge's lab interface is not in VRF internet"
wait_for "VRF kernel route via transit-a" 10 kernel_via vrf internet 'via 192.0.2.21'

echo "2. decide and inject inside the VRF"
wait_for "steer in the VRF" 60 injected
wait_for "VRF kernel route via transit-b" 10 kernel_via vrf internet 'via 192.0.2.22'
kernel_via table main blackhole || fail "the main table lost its blackhole for $prefix"
if kernel_via table main 192.0.2.22; then
	fail "Packeteer's route reached the default VRF"
fi
"${compose[@]}" exec -T transit-b vtysh -c "show bgp ipv4 unicast $prefix json" | "$check_bin" -absent ||
	fail "transit-b received Packeteer's route"

echo "3. partial table: the default route and an unlearned prefix stay unsteered"
decisions_ok() {
	api /api/decisions | jq -e '
		([.decisions[] | select(.prefix == "0.0.0.0/0" and .action == "none" and .reason == "default route is never steered")] | length == 1) and
		([.decisions[] | select(.prefix == "203.0.113.0/24" and .action == "none" and .reason == "prefix not in RIB")] | length == 1)' >/dev/null
}
wait_for "decisions for the default route and 203.0.113.0/24" 15 decisions_ok
for _ in $(seq 1 5); do
	no_packeteer_path 0.0.0.0/0 || fail "Packeteer announced the default route"
	vrf_json 203.0.113.0/24 | "$check_bin" -absent || fail "Packeteer announced 203.0.113.0/24, which no provider sends"
	injected || fail "the steer did not hold"
	sleep 2
done

echo "4. SIGTERM withdraws inside the VRF"
"${compose[@]}" stop -t 20 packeteer
wait_for "route gone from the VRF after SIGTERM" 15 no_packeteer_path "$prefix"
wait_for "VRF back on transit-a" 10 native
wait_for "VRF kernel route back via transit-a" 10 kernel_via vrf internet 'via 192.0.2.21'

echo "5. restart, steer, SIGKILL"
"${compose[@]}" start packeteer
wait_for "steer after restart" 60 injected
sigkill

echo "vrf e2e ok"
