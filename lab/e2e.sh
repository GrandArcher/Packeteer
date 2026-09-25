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

bgp_text() {
	"${compose[@]}" exec -T edge vtysh \
		-c 'show bgp ipv4 unicast json' \
		-c 'show bgp ipv4 unicast 198.51.100.0/24' 2>/dev/null || true
}

dump_bgp() {
	"${compose[@]}" exec -T edge vtysh -c 'show bgp summary' >&2 || true
	"${compose[@]}" exec -T edge vtysh -c 'show bgp ipv4 unicast 198.51.100.0/24' >&2 || true
	"${compose[@]}" exec -T edge vtysh -c 'show bgp ipv4 unicast json' >&2 || true
	"${compose[@]}" exec -T edge vtysh -c 'show bgp ipv4 unicast neighbors 192.0.2.10 advertised-routes' >&2 || true
	"${compose[@]}" exec -T edge vtysh -c 'show route-map from-packeteer' >&2 || true
	"${compose[@]}" exec -T edge vtysh -c 'show running-config' >&2 || true
	"${compose[@]}" logs --no-color packeteer >&2 || true
}

# route_is present|absent checks once. pause 0 in wait_route uses this.
route_is() {
	local mode=$1
	printf '%s\n' "$(bgp_text)" | python3 lab/check_route.py "$mode"
}

wait_route() {
	local mode=$1
	local tries=${2:-40}
	local pause=${3:-2}
	local i
	for i in $(seq 1 "$tries"); do
		# Summary JSON (FRR 10.2 omits communities) plus the detail text
		# form, which prints "Community: 64512:666 no-export".
		if route_is "$mode"; then
			return 0
		fi
		if [ "$pause" -eq 0 ]; then
			return 1
		fi
		sleep "$pause"
	done
	echo "timed out waiting for route to be $mode" >&2
	dump_bgp
	return 1
}

# stay_present seconds: the injected route must remain the whole time.
# nativePathConfirm in internal/policy is 5s and the lab probe interval is
# 2s, so a real-leave check has to wait longer than both before withdrawing
# the native path.
stay_present() {
	local seconds=$1
	local why=$2
	local i
	for i in $(seq 1 "$seconds"); do
		if ! route_is present; then
			echo "route did not stay present ($why) at second $i" >&2
			dump_bgp
			return 1
		fi
		sleep 1
	done
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

echo "route stays while FRR is still advertising the native path"
stay_present 12 "native path still advertised"

echo "withdrawing the native route on FRR"
"${compose[@]}" exec -T edge vtysh \
	-c 'configure terminal' \
	-c 'router bgp 64512' \
	-c 'address-family ipv4 unicast' \
	-c 'no network 198.51.100.0/24' \
	-c 'end'
echo "waiting for Packeteer's route to disappear"
wait_route absent 20 1

echo "real edge: equal weight, so Packeteer's local-pref becomes best"
# Weight 32768 matches the network statement. Local-pref 250 then wins,
# and FRR withdraws the native advertisement toward Packeteer. The
# improvement must stay; withdrawing it would flap.
"${compose[@]}" exec -T edge vtysh \
	-c 'configure terminal' \
	-c 'route-map from-packeteer permit 10' \
	-c 'match community packeteer' \
	-c 'set weight 32768' \
	-c 'exit' \
	-c 'router bgp 64512' \
	-c 'address-family ipv4 unicast' \
	-c 'network 198.51.100.0/24' \
	-c 'end'

echo "waiting for re-injection after the prefix returns"
wait_route present

echo "waiting until FRR stops advertising 198.51.100.0/24 to Packeteer"
hidden=0
for _ in $(seq 1 15); do
	if ! route_is present; then
		echo "route disappeared while waiting for FRR to hide the native path" >&2
		dump_bgp
		exit 1
	fi
	adv=$("${compose[@]}" exec -T edge vtysh -c 'show bgp ipv4 unicast neighbors 192.0.2.10 advertised-routes' 2>&1) || {
		echo "advertised-routes failed" >&2
		printf '%s\n' "$adv" >&2
		dump_bgp
		exit 1
	}
	if printf '%s\n' "$adv" | grep -Eq 'Unknown command|Invalid'; then
		echo "advertised-routes command not accepted" >&2
		printf '%s\n' "$adv" >&2
		dump_bgp
		exit 1
	fi
	if ! printf '%s\n' "$adv" | grep -q '198.51.100.0/24'; then
		hidden=1
		break
	fi
	sleep 1
done
if [ "$hidden" -ne 1 ]; then
	echo "FRR is still advertising the native path; this step did not model a real edge" >&2
	printf '%s\n' "$adv" >&2
	dump_bgp
	exit 1
fi

echo "native path hidden; injected route must not flap"
stay_present 15 "router selected Packeteer's route"

echo "stopping packeteer"
"${compose[@]}" stop -t 20 packeteer
wait_route absent

echo "e2e ok"
