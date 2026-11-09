#!/bin/bash
# Overload protection for a provider with no commit (#307), against the
# simulated edge of the make-before-break lab. Documentation prefix and
# private ASN only.
#
# transit-b is faster than native transit-a but has a limit of 85% of its
# 1000 Mbps interface (interface_capacity_threshold_pct) and no commit. The
# prefix carries 60 Mbps of flow volume.
# 1. transit-b is at 800 Mbps: 60 more would pass the limit, so the steer is
#    refused (overload.refused, the decision says so, no Packeteer path).
# 2. transit-b falls to 700 Mbps: the steer fits and is announced
#    (overload.cleared).
# 3. transit-b rises to 900 Mbps: the steer is shed after hold_time
#    (overload.shed, the route leaves the edge) and refused again.
# SIGTERM withdraws.
set -euo pipefail

root=$(cd "$(dirname "$0")/.." && pwd)
cd "$root"
compose=(docker compose -f lab/docker-compose.yml)
prefix=198.51.100.0/24

lab_dir=$(mktemp -d)
trap 'rc=$?; if [ "$rc" -ne 0 ]; then echo "---- lab logs ----"; "${compose[@]}" logs --no-color || true; "${compose[@]}" ps || true; fi; "${compose[@]}" down -v --remove-orphans || true; rm -rf "$lab_dir"; exit "$rc"' EXIT

cp lab/probes/move-b.yaml "$lab_dir/state.yaml"
cp lab/probes/overload-high.yaml "$lab_dir/usage.yaml"
chmod 0644 "$lab_dir/state.yaml" "$lab_dir/usage.yaml"
export PACKETEER_LAB_DIR="$lab_dir"
export PACKETEER_LAB_CONFIG="$root/lab/packeteer-overload.yaml"

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

echo "transit-b is faster but at 80%: the steer would pass the 85% limit and is refused"
need_api '/api/events?limit=1000' '[.events[] | select(.kind == "overload.refused" and .fields.prefix == "198.51.100.0/24" and .fields.provider == "transit-b" and .fields.projected_pct == "86.0" and .fields.limit_pct == "85.0")] | length >= 1' "overload.refused event"
need_api /api/decisions/198.51.100.0/24 '.action == "none" and .recommended == "transit-b" and (.reason | startswith("overload: transit-b would reach 86%")) and .explain.blocked_by == "overload"' "refused decision"
need_api /api/telemetry '[.telemetry[] | select(.provider == "transit-b" and .capacity_mbps == 1000 and ((.utilization_pct - 80) | fabs) < 0.01 and .capacity_threshold_pct == 85 and (.overloaded | not))] | length == 1' "transit-b utilization"
sleep 6
[ -z "$(ours "$(prefix_text)")" ] || fail "a refused steer is on the edge"

echo "transit-b falls to 70%: the steer fits and is announced"
flip lab/probes/overload-room.yaml usage.yaml
wait_via 192.0.2.2
need_api '/api/events?limit=1000' '[.events[] | select(.kind == "overload.cleared" and .fields.provider == "transit-b")] | length >= 1' "overload.cleared event"

echo "transit-b rises to 90%: the steer is shed"
flip lab/probes/overload-over.yaml usage.yaml
wait_absent
need_api '/api/events?limit=1000' '[.events[] | select(.kind == "overload.shed" and .fields.prefix == "198.51.100.0/24" and .fields.provider == "transit-b" and .fields.used_pct == "90.0")] | length >= 1' "overload.shed event"
need_api /api/telemetry '[.telemetry[] | select(.provider == "transit-b" and .overloaded)] | length == 1' "transit-b overloaded"
# After the cooldown the steer is wanted again and refused, not made.
need_api '/api/events?limit=1000' '[.events[] | select(.kind == "overload.refused")] | length >= 2' "refused again after the shed"
sleep 6
[ -z "$(ours "$(prefix_text)")" ] || fail "a shed steer came back while transit-b is over the limit"

echo "SIGTERM withdraws"
flip lab/probes/overload-room.yaml usage.yaml
wait_via 192.0.2.2
"${compose[@]}" stop -t 20 packeteer
wait_absent

echo "overload protection e2e ok"
