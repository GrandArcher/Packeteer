#!/bin/bash
# Bring up the FRR lab and assert announce, flip-back withdraw, and
# withdraw when Packeteer stops. Documentation prefix and private ASN only.
set -euo pipefail

root=$(cd "$(dirname "$0")/.." && pwd)
cd "$root"
compose=(docker compose -f lab/docker-compose.yml)

lab_dir=$(mktemp -d)
trap 'rc=$?; if [ "$rc" -ne 0 ]; then echo "---- lab logs ----"; "${compose[@]}" logs --no-color || true; "${compose[@]}" ps || true; fi; "${compose[@]}" down -v --remove-orphans || true; rm -rf "$lab_dir"; exit "$rc"' EXIT

cp lab/probes/prefer-b.yaml "$lab_dir/state.yaml"
export PACKETEER_LAB_DIR="$lab_dir"

echo "building lab"
"${compose[@]}" build
"${compose[@]}" up -d

wait_route() {
	local mode=$1
	local i
	for i in $(seq 1 40); do
		local json
		json=$("${compose[@]}" exec -T edge vtysh -c 'show bgp ipv4 unicast json' 2>/dev/null || true)
		if printf '%s\n' "$json" | python3 lab/check_route.py "$mode"; then
			return 0
		fi
		sleep 2
	done
	echo "timed out waiting for route to be $mode" >&2
	"${compose[@]}" exec -T edge vtysh -c 'show bgp summary' >&2 || true
	"${compose[@]}" exec -T edge vtysh -c 'show bgp ipv4 unicast json' >&2 || true
	"${compose[@]}" exec -T edge vtysh -c 'show running-config' >&2 || true
	"${compose[@]}" logs --no-color packeteer >&2 || true
	return 1
}

flip() {
	local src=$1
	local tmp
	tmp=$(mktemp "$lab_dir/.state.XXXXXX")
	cp "$src" "$tmp"
	mv "$tmp" "$lab_dir/state.yaml"
}

echo "waiting for injected route"
wait_route present

echo "forcing flip-back"
flip lab/probes/prefer-a.yaml
wait_route absent

echo "restoring the improvement (after flip-back cooldown)"
flip lab/probes/prefer-b.yaml
wait_route present

echo "stopping packeteer"
"${compose[@]}" stop -t 20 packeteer
wait_route absent

echo "e2e ok"
