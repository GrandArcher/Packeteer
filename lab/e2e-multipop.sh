#!/bin/bash
# Multi-POP federation (#30) against two simulated POPs: edge-a with
# packeteer-a (pop-a) and edge-b with packeteer-b (pop-b), federated over
# mutual TLS with certificates generated for this run. Documentation
# prefixes and a private ASN only.
#
# Carrier X exits in both POPs (x-a, x-b) under one shared 100 Mbps
# commit; y-a is a second carrier in POP A. The fixed prober and fixed
# telemetry read files this script rewrites. Checked on every sample:
# packeteer-a never announces 203.0.113.0/24 (only POP B learned it), and
# packeteer-b never announces anything (its own path is always best, or it
# has nowhere to move). Then:
#  1. central view: each instance sees the other fresh over mTLS;
#  2. inter-DC RTT in the path cost: POP A's carriers are at 80ms, x-b is
#     10ms in POP B + 10ms backbone, so 198.51.100.0/24 is announced to
#     edge-a with next hop 192.0.2.253, local-pref 250, 64512:666, no-export;
#  3. peer loss: SIGTERM packeteer-b and the steer through POP B is
#     withdrawn; start it and the steer returns;
#  4. global commit: paths equal, x-a at 60 of its own 100 but x-b at 60
#     in POP B puts carrier X at 120 of 100. Commit control in POP A moves
#     the prefix to y-a (next hop 192.0.2.2), cause commit;
#  5. POP B's usage drops to 5: the shared commit has room and the commit
#     steer is withdrawn;
#  6. SIGTERM packeteer-a withdraws; SIGKILL drops the route with the session.
set -euo pipefail
export LC_ALL=C

root=$(cd "$(dirname "$0")/.." && pwd)
cd "$root"
compose=(docker compose -f lab/docker-compose-multipop.yml)

lab_dir=$(mktemp -d)
check_bin=$(mktemp)
certs_bin=$(mktemp)
trap 'rc=$?; if [ "$rc" -ne 0 ]; then echo "---- lab logs ----"; "${compose[@]}" logs --no-color || true; "${compose[@]}" ps || true; fi; "${compose[@]}" down -v --remove-orphans || true; rm -f "$check_bin" "$certs_bin"; rm -rf "$lab_dir"; exit "$rc"' EXIT

echo "building route check and lab certificates"
go build -o "$check_bin" ./lab/checkpop
go build -o "$certs_bin" ./lab/mkcerts
mkdir -p "$lab_dir/a" "$lab_dir/b" "$lab_dir/certs"
"$certs_bin" "$lab_dir/certs" pop-a pop-b
chmod 755 "$lab_dir" "$lab_dir/a" "$lab_dir/b" "$lab_dir/certs"
export PACKETEER_LAB_DIR="$lab_dir"

# flip pop file source: replace one instance's file atomically.
flip() {
	local tmp
	tmp=$(mktemp "$lab_dir/$1/.flip.XXXXXX")
	cp "lab/probes/multipop/$3" "$tmp"
	chmod 644 "$tmp"
	mv "$tmp" "$lab_dir/$1/$2"
}
flip a state.yaml a-slow.yaml
flip a usage.yaml a-usage.yaml
flip b state.yaml b-fast.yaml
flip b usage.yaml b-usage-low.yaml

echo "building lab"
"${compose[@]}" build
"${compose[@]}" up -d

vty() {
	local svc=$1
	shift
	"${compose[@]}" exec -T "$svc" vtysh "$@"
}

api() {
	"${compose[@]}" exec -T "$1" wget -qO- "http://127.0.0.1:8080$2" 2>/dev/null || true
}

dump() {
	local s
	for s in edge-a edge-b; do
		vty "$s" -c 'show bgp summary' >&2 || true
		vty "$s" -c 'show bgp ipv4 unicast' >&2 || true
	done
	api packeteer-a /api/federation >&2
	api packeteer-a /api/decisions >&2
	"${compose[@]}" logs --no-color packeteer-a packeteer-b >&2 || true
}

# paths edge peer: "prefix next_hop" lines for the peer's paths, or
# return 1 when the table cannot be read.
paths() {
	local out
	out=$(vty "$1" -c 'show bgp ipv4 unicast json' 2>/dev/null) || return 1
	printf '%s\n' "$out" | "$check_bin" "$2"
}

# sample sets got to packeteer-a's paths on edge-a. Runs in the script's
# shell (never in $(...)) so a guard failure ends the run.
got=
sample() {
	local a b
	got="?"
	a=$(paths edge-a 192.0.2.10) || return 1
	if [[ "$a" == *"203.0.113.0/24"* ]]; then
		echo "FAIL: packeteer-a announced 203.0.113.0/24, which POP A never learned" >&2
		dump
		exit 1
	fi
	if b=$(paths edge-b 192.0.2.20) && [ -n "$b" ]; then
		echo "FAIL: packeteer-b announced [$b]; POP B's own exit is always best here" >&2
		dump
		exit 1
	fi
	got=$a
}

# want lines...: wait until packeteer-a's paths on edge-a are exactly that.
want() {
	local want i
	want=$(printf '%s\n' "$@" | grep . | sort || true)
	for i in $(seq 1 60); do
		if sample && [ "$got" = "$want" ]; then
			echo "edge-a has from packeteer-a: [$(echo $got)]"
			return 0
		fi
		sleep 1
	done
	echo "timed out: edge-a has [$(echo $got)], want [$(echo $want)]" >&2
	dump
	return 1
}

# stay seconds lines...: the set must not change.
stay() {
	local seconds=$1
	shift
	local want i
	want=$(printf '%s\n' "$@" | grep . | sort || true)
	for i in $(seq 1 "$seconds"); do
		if ! sample || [ "$got" != "$want" ]; then
			echo "set changed at second $i: [$(echo $got)], want [$(echo $want)]" >&2
			dump
			return 1
		fi
		sleep 1
	done
}

# tagged prefix next_hop: packeteer-a's path carries the next hop,
# local-pref 250, the packeteer community, and no-export.
tagged() {
	local text
	text=$(vty edge-a -c "show bgp ipv4 unicast $1" 2>/dev/null || true)
	if [[ "$text" != *"$2 from 192.0.2.10"* ]] || [[ "$text" != *"localpref 250"* ]] || [[ "$text" != *"Community: 64512:666 no-export"* ]]; then
		echo "FAIL: $1 from packeteer-a is not tagged (next hop $2, local-pref, community, no-export)" >&2
		printf '%s\n' "$text" >&2
		dump
		exit 1
	fi
}

need_log() {
	local svc=$1 pattern=$2 why=$3 i
	for i in $(seq 1 30); do
		if "${compose[@]}" logs --no-color "$svc" 2>/dev/null | grep -Eq "$pattern"; then
			return 0
		fi
		sleep 1
	done
	echo "FAIL: $why (no $svc log matching: $pattern)" >&2
	dump
	exit 1
}

# need_api svc path jq-filter why: wait until the filter holds.
need_api() {
	local i
	for i in $(seq 1 30); do
		if api "$1" "$2" | jq -e "$3" >/dev/null 2>&1; then
			return 0
		fi
		sleep 1
	done
	echo "FAIL: $4 ($1 $2 does not satisfy: $3)" >&2
	api "$1" "$2" >&2
	dump
	exit 1
}

pfx=198.51.100.0/24

echo "1. central view: both instances see each other over mTLS"
need_api packeteer-a /api/federation '.enabled and .instance == "pop-a" and .domain == "pop-a" and (.peers | length) == 1 and .peers[0].fresh and .peers[0].snapshot.domain == "pop-b" and .peers[0].inter_dc_rtt_ms == 10 and .local.domain == "pop-a"' "pop-a does not see pop-b"
need_api packeteer-b /api/federation '.enabled and .peers[0].fresh and .peers[0].snapshot.instance == "pop-a"' "pop-b does not see pop-a"
need_api packeteer-a /api/providers '[.providers[] | select(.name == "x-b" and .domain == "pop-b")] | length == 1' "remote provider not listed"

echo "2. inter-DC RTT in the path cost: steer through POP B's carrier"
want "$pfx 192.0.2.253"
tagged "$pfx" 192.0.2.253
need_log packeteer-a 'msg="improvement improve".*prefix=198\.51\.100\.0/24 provider=x-b native=x-a.*rtt 80ms→20ms' "steer through x-b (10ms + 10ms inter-DC) not logged"
need_api packeteer-a /api/decisions '[.decisions[] | select(.prefix == "198.51.100.0/24") | .candidates[] | select(.provider == "x-b")] | length == 1' "x-b is not a candidate"
stay 8 "$pfx 192.0.2.253"

echo "3. peer loss withdraws the steer through POP B"
start=$(date +%s)
"${compose[@]}" stop -t 20 packeteer-b
want
echo "withdrawn $(($(date +%s) - start))s after SIGTERM of packeteer-b"
need_log packeteer-a 'msg="improvement retired".*prefix=198\.51\.100\.0/24 provider=x-b' "retire of the x-b steer not logged"
need_api packeteer-a /api/federation '.peers[0].fresh == false' "pop-b still fresh"
stay 6
echo "starting packeteer-b again"
"${compose[@]}" start packeteer-b
want "$pfx 192.0.2.253"
tagged "$pfx" 192.0.2.253

echo "4. global commit: carrier X over its shared commit across POPs"
flip a state.yaml a-equal.yaml
flip b state.yaml b-equal.yaml
flip b usage.yaml b-usage-high.yaml
need_api packeteer-a /api/federation '.global_commit[0] | .name == "carrier-x" and .complete and .over and .total_mbps == 120' "global commit not over at 120"
want "$pfx 192.0.2.2"
tagged "$pfx" 192.0.2.2
need_log packeteer-a 'prefix=198\.51\.100\.0/24 provider=y-a native=x-a cause=commit' "commit steer to y-a not logged"
stay 6 "$pfx 192.0.2.2"

echo "5. POP B's usage drops: the shared commit has room again"
flip b usage.yaml b-usage-low.yaml
need_api packeteer-a /api/federation '.global_commit[0] | .complete and (.over | not) and .total_mbps == 65' "global commit not back under"
want
need_log packeteer-a 'commit relieved' "withdraw was not a commit release"
stay 6

echo "back to the performance steer through POP B"
flip a state.yaml a-slow.yaml
flip b state.yaml b-fast.yaml
want "$pfx 192.0.2.253"

echo "6. SIGTERM packeteer-a withdraws"
"${compose[@]}" stop -t 20 packeteer-a
want
text=$(vty edge-a -c "show bgp ipv4 unicast $pfx" 2>/dev/null || true)
if [[ "$text" != *"$pfx"* ]]; then
	echo "FAIL: edge-a lost its own $pfx" >&2
	dump
	exit 1
fi
echo "restarting packeteer-a"
"${compose[@]}" start packeteer-a
want "$pfx 192.0.2.253"

echo "SIGKILL packeteer-a: the route drops with the session"
hold=$(awk '$1 == "neighbor" && $2 == "192.0.2.10" && $3 == "timers" { print $5 }' lab/frr-mp-edge-a/frr.conf)
case "$hold" in
'' | *[!0-9]*)
	echo "lab hold timer is not an integer: '${hold}'" >&2
	exit 1
	;;
esac
cid=$("${compose[@]}" ps -q packeteer-a)
if [ -z "$cid" ]; then
	echo "packeteer-a is not running" >&2
	exit 1
fi
start=$(date +%s)
docker kill -s KILL "$cid"
deadline=$((start + hold + 6))
dropped=0
while [ "$(date +%s)" -le "$deadline" ]; do
	sample || true
	nbr=$(vty edge-a -c 'show bgp neighbors 192.0.2.10' 2>/dev/null || true)
	if [ -z "$got" ] && [[ "$nbr" == *"BGP state ="* ]] && [[ "$nbr" != *"BGP state = Established"* ]]; then
		dropped=1
		break
	fi
	sleep 1
done
if [ "$dropped" -ne 1 ]; then
	echo "FAIL: packeteer-a routes still on edge-a ${hold}s after SIGKILL: [$(echo $got)]" >&2
	dump
	exit 1
fi
echo "session lost and every route gone $(($(date +%s) - start))s after SIGKILL (hold ${hold}s)"
need_api packeteer-b /api/federation '.peers[0].fresh == false' "pop-b still sees the killed pop-a as fresh"

echo "e2e multi-pop ok"
