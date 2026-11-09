#!/bin/bash
# Steer verification, inbound (#305), against the simulated edge and two
# simulated eBGP transits of the inbound lab. Documentation prefixes and
# documentation/private ASNs only.
#
# 1. transit-a's inbound rate is over its commit, so 203.0.113.0/24 is
#    steered away from it. The usage file then shows the traffic moving to
#    transit-b: after the window the steer is verified, still on transit-a's
#    path, and /api/verification says so.
# 2. After a restart the same steer is made, but the usage does not change.
#    After the window it is not moved: the steer is reverted (transit-a gets
#    the plain path again) and, although the commit trigger is still on, it
#    is not made again during the back-off.
set -euo pipefail

root=$(cd "$(dirname "$0")/.." && pwd)
cd "$root"
compose=(docker compose -f lab/docker-compose-inbound.yml)

lab_dir=$(mktemp -d)
check_bin=$(mktemp)
trap 'rc=$?; if [ "$rc" -ne 0 ]; then echo "---- lab logs ----"; "${compose[@]}" logs --no-color || true; "${compose[@]}" ps || true; fi; "${compose[@]}" down -v --remove-orphans || true; rm -f "$check_bin"; rm -rf "$lab_dir"; exit "$rc"' EXIT

echo "building path check"
go build -o "$check_bin" ./lab/checkpath

cp lab/probes/verify-in-over.yaml "$lab_dir/usage.yaml"
cp lab/probes/inbound-paths-equal.yaml "$lab_dir/paths.yaml"
chmod 0644 "$lab_dir/usage.yaml" "$lab_dir/paths.yaml"
export PACKETEER_LAB_DIR="$lab_dir"
export PACKETEER_LAB_CONFIG="$root/lab/packeteer-verify-inbound.yaml"

echo "building lab"
"${compose[@]}" build
"${compose[@]}" up -d

prefix=203.0.113.0/24

path_json() {
	"${compose[@]}" exec -T "$1" vtysh -c "show bgp ipv4 unicast $prefix json" 2>/dev/null || true
}

a_steered() {
	path_json transit-a | "$check_bin" -aspath "64512 64512 64512" -has 64496:3 \
		-lacks 64512: -lacks 64497: -lacks no-export
}

plain_on() {
	path_json "$1" | "$check_bin" -aspath "64512" -lacks 64512: -lacks 64496: -lacks 64497: -lacks no-export
}

both_plain() { plain_on transit-a && plain_on transit-b; }
steered_only_a() { a_steered && plain_on transit-b; }

dump_bgp() {
	for r in edge transit-a transit-b; do
		echo "---- $r ----" >&2
		"${compose[@]}" exec -T "$r" vtysh -c 'show bgp summary' >&2 || true
		"${compose[@]}" exec -T "$r" vtysh -c "show bgp ipv4 unicast $prefix" >&2 || true
	done
	"${compose[@]}" logs --no-color packeteer >&2 || true
}

wait_for() {
	local what=$1
	shift
	local i
	for i in $(seq 1 45); do
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

set_usage() {
	local tmp
	tmp=$(mktemp "$lab_dir/.usage.XXXXXX")
	cp "$1" "$tmp"
	chmod 0644 "$tmp"
	mv "$tmp" "$lab_dir/usage.yaml"
}

# The logs are read into a variable first: with pipefail, grep -q exiting
# on the first match would SIGPIPE docker compose logs and fail the check.
logged() {
	local logs
	logs=$("${compose[@]}" logs --no-color packeteer)
	grep -qE "$1" <<<"$logs"
}

need_log() {
	if ! wait_for "log line: $2" logged "$1"; then
		exit 1
	fi
}

api() { "${compose[@]}" exec -T packeteer wget -qO- "http://127.0.0.1:8080$1"; }

# verification_is <status>: GET /api/verification lists one inbound result for
# transit-a with that status.
verification_is() {
	api /api/verification | jq -e --arg s "$1" '.enabled and ([.results[] | select(.kind == "inbound" and .provider == "transit-a" and .status == $s)] | length) == 1' >/dev/null
}

echo "commit trigger: waiting for the steer away from transit-a"
wait_for "transit-a steered, transit-b plain" steered_only_a

echo "the traffic moves to transit-b: the steer must be verified and stay"
set_usage lab/probes/verify-in-moved.yaml
need_log 'msg="steer verification".*kind=inbound.*status=verified' "inbound steer verified"
if ! steered_only_a; then
	echo "a verified steer was withdrawn" >&2
	dump_bgp
	exit 1
fi
wait_for "/api/verification shows the verified steer" verification_is verified
api /api/verification | jq -e '.results[] | select(.kind == "inbound") | select(.moved_pct >= 50 and .expected_mbps == 150 and (.backed_out | not))' >/dev/null

echo "restart with the usage unchanged by the steer"
"${compose[@]}" stop -t 20 packeteer
wait_for "both transits plain after SIGTERM" both_plain
set_usage lab/probes/verify-in-over.yaml
"${compose[@]}" start packeteer
wait_for "transit-a steered again" steered_only_a

echo "the traffic does not move: the steer must be reverted after the window"
need_log 'msg="steer verification".*kind=inbound.*status=not_moved.*backed_out=true' "inbound steer not moved and backed out"
wait_for "both transits plain after the revert" both_plain
wait_for "/api/verification shows the reverted steer" verification_is not_moved
api /api/verification | jq -e '.results[] | select(.kind == "inbound" and .status == "not_moved") | .backed_out' >/dev/null
need_log 'msg="steer backed out".*kind=inbound.*target=transit-a.*backoff=1m30s' "the revert is logged with its back-off"

echo "the commit trigger is still on: no new steer during the back-off"
for _ in $(seq 1 12); do
	if ! both_plain 2>/dev/null; then
		echo "the steer came back inside the back-off" >&2
		dump_bgp
		exit 1
	fi
	sleep 2
done
api /api/inbound | jq -e '[.blocked[] | select(.provider == "transit-a" and (.reason | contains("verification")))] | length == 1' >/dev/null

echo "steer verification (inbound) e2e ok"
