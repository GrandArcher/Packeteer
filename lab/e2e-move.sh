#!/bin/bash
# FRR lab for make-before-break (#386): an improvement that moves from
# transit-b to transit-c reaches the edge as one replacing UPDATE. The edge
# holds exactly one Packeteer path for the prefix through the move and
# never receives a withdraw for it. A flip-back withdraw afterwards must
# show up in the same update log, so the no-withdraw check cannot pass on
# a log that misses withdraws. SIGTERM withdraws. Documentation prefix and
# private ASN only.
set -euo pipefail

root=$(cd "$(dirname "$0")/.." && pwd)
cd "$root"
compose=(docker compose -f lab/docker-compose.yml)
prefix=198.51.100.0/24
updates_log=/tmp/bgp-updates.log

lab_dir=$(mktemp -d)
trap 'rc=$?; if [ "$rc" -ne 0 ]; then echo "---- lab logs ----"; "${compose[@]}" logs --no-color || true; "${compose[@]}" ps || true; fi; "${compose[@]}" down -v --remove-orphans || true; rm -rf "$lab_dir"; exit "$rc"' EXIT

cp lab/probes/move-b.yaml "$lab_dir/state.yaml"
cp lab/packeteer-move.yaml "$lab_dir/config.yaml"
chmod 0644 "$lab_dir/config.yaml"
export PACKETEER_LAB_DIR="$lab_dir"
export PACKETEER_LAB_CONFIG="$lab_dir/config.yaml"

echo "building lab"
"${compose[@]}" build
"${compose[@]}" up -d

vtysh() { "${compose[@]}" exec -T edge vtysh "$@"; }

prefix_text() { vtysh -c "show bgp ipv4 unicast $prefix" 2>/dev/null || true; }

dump_bgp() {
	vtysh -c 'show bgp summary' >&2 || true
	vtysh -c "show bgp ipv4 unicast $prefix" >&2 || true
	"${compose[@]}" exec -T edge cat "$updates_log" >&2 || true
	"${compose[@]}" logs --no-color packeteer >&2 || true
}

fail() {
	echo "$1" >&2
	dump_bgp
	exit 1
}

# ours prints the next hop of each Packeteer path the edge holds for the
# prefix, one per line. FRR prints a path as "<next hop> ... from 192.0.2.10 (...)".
ours() {
	printf '%s\n' "$1" | sed -n 's/^[[:space:]]*\([0-9][0-9.]*\) .*from 192\.0\.2\.10 (.*/\1/p'
}

# wait_via <next hop>: exactly one Packeteer path, via that next hop, with
# the packeteer community and NO_EXPORT.
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
	tmp=$(mktemp "$lab_dir/.state.XXXXXX")
	cp "$1" "$tmp"
	mv "$tmp" "$lab_dir/state.yaml"
}

updates() { "${compose[@]}" exec -T edge cat "$updates_log" 2>/dev/null || true; }

# FRR logs a received withdraw as "rcvd UPDATE about <prefix> ... -- withdrawn".
withdraws() { updates | grep -F "$prefix" | grep -c 'withdrawn' || true; }
announces() { updates | grep -F "$prefix" | grep 'rcvd' | grep -vc 'withdrawn' || true; }

echo "transit-b is faster: one Packeteer path via 192.0.2.2"
wait_via 192.0.2.2

echo "logging every UPDATE the edge receives"
vtysh -c 'configure terminal' -c "log file $updates_log debugging" -c 'end' -c 'debug bgp updates in' >/dev/null
dbg=$(vtysh -c 'show debugging' 2>&1 || true)
[[ "$dbg" == *"updates"* ]] || fail "FRR update debugging did not turn on: $dbg"

echo "transit-c becomes faster: the improvement moves"
flip lab/probes/move-c.yaml
moved=0
samples=0
for _ in $(seq 1 300); do
	text=$(prefix_text)
	# A failed vtysh call is not a sample; the native path keeps the
	# prefix in the table, so a real sample always lists its paths.
	if [[ "$text" != *"available"* ]]; then
		sleep 0.2
		continue
	fi
	samples=$((samples + 1))
	paths=$(ours "$text")
	n=$(printf '%s' "$paths" | grep -c . || true)
	if [ "$n" -ne 1 ]; then
		fail "edge held $n Packeteer paths during the move (sample $samples): ${paths:-none}"
	fi
	if [ "$paths" = 192.0.2.4 ]; then
		moved=1
		break
	fi
	sleep 0.2
done
[ "$moved" -eq 1 ] || fail "improvement did not move to transit-c"
echo "edge held one Packeteer path in all $samples samples"
wait_via 192.0.2.4
logs=$("${compose[@]}" logs --no-color packeteer 2>&1 || true)
grep -F 'injected' <<<"$logs" | grep -qF 'provider=transit-c' || fail "no injected log line for transit-c"

# FRR may write the log file a little after the table changes.
for _ in $(seq 1 10); do
	[ "$(announces)" -ge 1 ] && break
	sleep 1
done
[ "$(announces)" -ge 1 ] || fail "update log has no UPDATE for $prefix; the no-withdraw check would be empty"
[ "$(withdraws)" -eq 0 ] || fail "edge received a withdraw for $prefix during the move"

echo "native transit-a faster: flip-back withdraw must appear in the update log"
flip lab/probes/move-a.yaml
wait_absent
seen=0
for _ in $(seq 1 10); do
	if [ "$(withdraws)" -ge 1 ]; then
		seen=1
		break
	fi
	sleep 1
done
[ "$seen" -eq 1 ] || fail "flip-back withdraw is missing from the update log"

echo "transit-c faster again; SIGTERM withdraws"
flip lab/probes/move-c.yaml
wait_via 192.0.2.4
"${compose[@]}" stop -t 20 packeteer
wait_absent

echo "make-before-break lab passed"
