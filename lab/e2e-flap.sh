#!/bin/bash
# FRR lab for the flap quarantine (#228): latency that keeps flipping
# between the two providers withdraws Packeteer's route after max_flips
# changes, the edge stays on its native path while the prefix is parked
# even though the second provider stays better, the cool-down releases it,
# and SIGTERM withdraws. Documentation prefix and private ASN only.
set -euo pipefail

root=$(cd "$(dirname "$0")/.." && pwd)
cd "$root"
compose=(docker compose -f lab/docker-compose.yml)

lab_dir=$(mktemp -d)
check_bin=$(mktemp)
trap 'rc=$?; if [ "$rc" -ne 0 ]; then echo "---- lab logs ----"; "${compose[@]}" logs --no-color || true; "${compose[@]}" ps || true; fi; "${compose[@]}" down -v --remove-orphans || true; rm -f "$check_bin"; rm -rf "$lab_dir"; exit "$rc"' EXIT

echo "building route check"
go build -o "$check_bin" ./lab/checkroute

cp lab/probes/prefer-a.yaml "$lab_dir/state.yaml"
cp lab/packeteer-flap.yaml "$lab_dir/config.yaml"
chmod 0644 "$lab_dir/config.yaml"
export PACKETEER_LAB_DIR="$lab_dir"
export PACKETEER_LAB_CONFIG="$lab_dir/config.yaml"

echo "building lab"
"${compose[@]}" build
"${compose[@]}" up -d

bgp_text() {
	"${compose[@]}" exec -T edge vtysh \
		-c 'show bgp ipv4 unicast json' \
		-c 'show bgp ipv4 unicast 198.51.100.0/24' 2>/dev/null || true
}

dump_bgp() {
	"${compose[@]}" exec -T edge vtysh -c 'show bgp summary' >&2 || true
	"${compose[@]}" exec -T edge vtysh -c 'show bgp ipv4 unicast 198.51.100.0/24' >&2 || true
	"${compose[@]}" logs --no-color packeteer >&2 || true
}

route_is() {
	bgp_text | "$check_bin" "$1"
}

wait_route() {
	local mode=$1
	local tries=${2:-40}
	local i
	for i in $(seq 1 "$tries"); do
		if route_is "$mode"; then
			return 0
		fi
		sleep 2
	done
	echo "timed out waiting for route to be $mode" >&2
	dump_bgp
	return 1
}

# stay_absent seconds: Packeteer's route must not return during the window.
stay_absent() {
	local seconds=$1
	local i
	for i in $(seq 1 "$seconds"); do
		if ! route_is absent; then
			echo "route came back while the prefix was quarantined (second $i)" >&2
			dump_bgp
			return 1
		fi
		sleep 1
	done
}

flip() {
	local tmp
	tmp=$(mktemp "$lab_dir/.state.XXXXXX")
	cp "$1" "$tmp"
	mv "$tmp" "$lab_dir/state.yaml"
}

packeteer_logs() { "${compose[@]}" logs --no-color packeteer 2>&1 || true; }

# wait_log <seconds> <fixed string>
wait_log() {
	local seconds=$1 needle=$2
	local i
	for i in $(seq 1 "$seconds"); do
		if packeteer_logs | grep -qF -- "$needle"; then
			return 0
		fi
		sleep 1
	done
	echo "timed out waiting for log: $needle" >&2
	dump_bgp
	return 1
}

echo "waiting for the session; no route while the native provider is best"
sleep 10
route_is absent

echo "change 1: transit-b becomes better, route announced"
flip lab/probes/prefer-b.yaml
wait_route present

echo "change 2: transit-a better again, flip-back withdraws"
flip lab/probes/prefer-a.yaml
wait_route absent

echo "change 3: transit-b better, announced after the flip-back cooldown"
flip lab/probes/prefer-b.yaml
wait_route present

echo "change 4 passes max_flips (3): withdrawn and quarantined"
flip lab/probes/prefer-a.yaml
wait_route absent
wait_log 20 'flap quarantine started'
if packeteer_logs | grep -F 'flap quarantine started' | grep -q 'flips=4'; then :; else
	echo "quarantine log does not report 4 flips" >&2
	dump_bgp
	exit 1
fi

echo "transit-b is better again, but the prefix stays on the native path"
flip lab/probes/prefer-b.yaml
stay_absent 20
native=$("${compose[@]}" exec -T edge vtysh -c 'show bgp ipv4 unicast 198.51.100.0/24' 2>/dev/null || true)
if [[ "$native" != *"198.51.100.0/24"* || "$native" == *"64512:666"* || "$native" != *"0.0.0.0"* ]]; then
	echo "edge is not on its native path for the quarantined prefix" >&2
	printf '%s\n' "$native" >&2
	exit 1
fi

echo "cool-down ends: released, and the still-better path is announced again"
wait_log 60 'flap quarantine released'
wait_route present

echo "stopping packeteer (SIGTERM, WithdrawAll)"
"${compose[@]}" stop -t 20 packeteer
wait_route absent

echo "flap quarantine lab passed"
