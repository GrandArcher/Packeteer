#!/bin/bash
# Steer verification, outbound (#305), against the simulated edge of the
# make-before-break lab. Documentation prefix and private ASN only.
#
# 1. transit-b is faster than native transit-a, so 198.51.100.0/24 is
#    steered to it (40 Mbps of flow volume). The usage file then shows 38 of
#    those Mbps leaving transit-a and arriving on transit-b: after the
#    window the steer is verified (log, /api/verification, steer.verified
#    event) and stays.
# 2. transit-c becomes faster and the improvement moves to it, but the usage
#    does not change. After the window the steer is not moved: it is
#    reported (steer.unverified event) and, as backout names only inbound by
#    default, left in place.
# SIGTERM withdraws.
set -euo pipefail

root=$(cd "$(dirname "$0")/.." && pwd)
cd "$root"
compose=(docker compose -f lab/docker-compose.yml)
prefix=198.51.100.0/24

lab_dir=$(mktemp -d)
trap 'rc=$?; if [ "$rc" -ne 0 ]; then echo "---- lab logs ----"; "${compose[@]}" logs --no-color || true; "${compose[@]}" ps || true; fi; "${compose[@]}" down -v --remove-orphans || true; rm -rf "$lab_dir"; exit "$rc"' EXIT

cp lab/probes/move-b.yaml "$lab_dir/state.yaml"
cp lab/probes/verify-out-before.yaml "$lab_dir/usage.yaml"
chmod 0644 "$lab_dir/state.yaml" "$lab_dir/usage.yaml"
export PACKETEER_LAB_DIR="$lab_dir"
export PACKETEER_LAB_CONFIG="$root/lab/packeteer-verify-outbound.yaml"

echo "building lab"
"${compose[@]}" build
"${compose[@]}" up -d

vtysh() { "${compose[@]}" exec -T edge vtysh "$@"; }
prefix_text() { vtysh -c "show bgp ipv4 unicast $prefix" 2>/dev/null || true; }

dump_bgp() {
	vtysh -c 'show bgp summary' >&2 || true
	vtysh -c "show bgp ipv4 unicast $prefix" >&2 || true
	"${compose[@]}" logs --no-color packeteer >&2 || true
}

fail() {
	echo "$1" >&2
	dump_bgp
	exit 1
}

# ours prints the next hop of each Packeteer path the edge holds for the
# prefix, one per line.
ours() {
	printf '%s\n' "$1" | sed -n 's/^[[:space:]]*\([0-9][0-9.]*\) .*from 192\.0\.2\.10 (.*/\1/p'
}

wait_via() {
	local want=$1 i text paths
	for i in $(seq 1 40); do
		text=$(prefix_text)
		paths=$(ours "$text")
		if [ "$paths" = "$want" ] && [[ "$text" == *"64512:666"* && "$text" == *"no-export"* ]]; then
			return 0
		fi
		sleep 2
	done
	fail "timed out waiting for one Packeteer path via $want (have: ${paths:-none})"
}

wait_absent() {
	local i
	for i in $(seq 1 40); do
		if [ -z "$(ours "$(prefix_text)")" ]; then
			return 0
		fi
		sleep 2
	done
	fail "timed out waiting for Packeteer's path to leave the edge"
}

flip() {
	local tmp
	tmp=$(mktemp "$lab_dir/.flip.XXXXXX")
	cp "$1" "$tmp"
	chmod 0644 "$tmp"
	mv "$tmp" "$lab_dir/$2"
}

# The logs are read into a variable first: with pipefail, grep -q exiting
# on the first match would SIGPIPE docker compose logs and fail the check.
logged() {
	local logs
	logs=$("${compose[@]}" logs --no-color packeteer)
	grep -qE "$1" <<<"$logs"
}

need_log() {
	local i
	for i in $(seq 1 40); do
		if logged "$1"; then
			return 0
		fi
		sleep 2
	done
	fail "packeteer log is missing: $1 ($2)"
}

api() { "${compose[@]}" exec -T packeteer wget -qO- "http://127.0.0.1:8080$1"; }

need_api() {
	local i
	for i in $(seq 1 40); do
		if api "$1" | jq -e "$2" >/dev/null 2>&1; then
			return 0
		fi
		sleep 2
	done
	fail "$1 does not match: $2 ($3)"
}

echo "transit-b is faster: one Packeteer path via 192.0.2.2"
wait_via 192.0.2.2

echo "the traffic moves to transit-b: the steer must be verified and stay"
flip lab/probes/verify-out-moved.yaml usage.yaml
need_log 'msg="steer verification".*kind=outbound.*target=198\.51\.100\.0/24.*provider=transit-b.*status=verified' "outbound steer verified"
wait_via 192.0.2.2
need_api /api/verification '.enabled and ([.results[] | select(.kind == "outbound" and .prefix == "198.51.100.0/24" and .provider == "transit-b" and .from == "transit-a" and .status == "verified" and .expected_mbps == 40 and .moved_pct >= 90)] | length) == 1' "verified outbound result"
need_api '/api/events?limit=1000' '[.events[] | select(.kind == "steer.verified" and .fields.target == "198.51.100.0/24")] | length >= 1' "steer.verified event"

echo "transit-c becomes faster: the improvement moves, the usage does not"
flip lab/probes/move-c.yaml state.yaml
wait_via 192.0.2.4
need_log 'msg="steer verification".*kind=outbound.*provider=transit-c.*status=not_moved.*backed_out=false' "outbound steer not moved, reported only"
need_api /api/verification '[.results[] | select(.kind == "outbound" and .provider == "transit-c" and .status == "not_moved" and (.backed_out | not))] | length == 1' "not moved outbound result"
need_api '/api/events?limit=1000' '[.events[] | select(.kind == "steer.unverified" and .fields.target == "198.51.100.0/24" and .fields.backed_out == "false")] | length >= 1' "steer.unverified event"
wait_via 192.0.2.4

echo "SIGTERM withdraws"
"${compose[@]}" stop -t 20 packeteer
wait_absent

echo "steer verification (outbound) e2e ok"
