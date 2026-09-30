#!/bin/bash
# Active/standby HA (#31) against one simulated FRR edge with two Packeteer
# instances, pk-a (192.0.2.10) and pk-b (192.0.2.20), sharing a lease on
# one Docker volume. Documentation prefix and private ASN only.
#
# Checked on every sample: the edge never holds Packeteer routes from both
# instances at once. Then:
#  1. pk-a starts alone, takes the lease, and announces 198.51.100.0/24
#     (next hop 192.0.2.2, local-pref 250, 64512:666, no-export);
#  2. pk-b starts, stays standby, and announces nothing for longer than a
#     takeover takes;
#  3. backup while running: -backup inside pk-a (config + sqlite history);
#  4. SIGKILL pk-a: nothing is withdrawn, the edge drops pk-a's route with
#     the session (hold 9s), and only then does pk-b take over;
#  5. pk-a restarts and stays standby;
#  6. session loss on the active pk-b (neighbor shutdown on the edge):
#     pk-b steps down and resigns, and pk-a takes over; pk-b recovers and
#     stays standby;
#  7. SIGTERM pk-a: it withdraws and resigns, and pk-b takes over at once;
#  8. SIGTERM pk-b: nothing is left on the edge;
#  9. restore the backup with the stock image into a stopped instance's
#     volume, and the restored config passes -check.
set -euo pipefail
export LC_ALL=C

root=$(cd "$(dirname "$0")/.." && pwd)
cd "$root"
compose=(docker compose -f lab/docker-compose-ha.yml)

lab_dir=$(mktemp -d)
pop_bin=$(mktemp)
trap 'rc=$?; if [ "$rc" -ne 0 ]; then echo "---- lab logs ----"; "${compose[@]}" logs --no-color || true; "${compose[@]}" ps || true; fi; "${compose[@]}" down -v --remove-orphans || true; rm -f "$pop_bin"; rm -rf "$lab_dir"; exit "$rc"' EXIT

echo "building route checks"
go build -o "$pop_bin" ./lab/checkpop
cp lab/probes/prefer-b.yaml "$lab_dir/state.yaml"
chmod 755 "$lab_dir"
chmod 644 "$lab_dir/state.yaml"
export PACKETEER_LAB_DIR="$lab_dir"

echo "building lab"
"${compose[@]}" build
"${compose[@]}" up -d edge packeteer-a

vty() {
	"${compose[@]}" exec -T edge vtysh "$@"
}

api() {
	"${compose[@]}" exec -T "$1" wget -qO- "http://127.0.0.1:8080$2" 2>/dev/null || true
}

dump() {
	vty -c 'show bgp summary' >&2 || true
	vty -c 'show bgp ipv4 unicast 198.51.100.0/24' >&2 || true
	api packeteer-a /api/ha >&2
	api packeteer-b /api/ha >&2
	"${compose[@]}" logs --no-color packeteer-a packeteer-b >&2 || true
}

# on peer: the "prefix next_hop" lines the edge holds from that instance.
on() {
	local out
	out=$(vty -c 'show bgp ipv4 unicast json' 2>/dev/null) || return 1
	printf '%s\n' "$out" | "$pop_bin" "$1"
}

# sample sets a and b to each instance's routes on the edge, and fails the
# run if the edge holds routes from both. It runs in the script's shell
# (never in $(...)) so the guard ends the run.
a=
b=
sample() {
	local sa sb
	a="?"
	b="?"
	sa=$(on 192.0.2.10) || return 1
	sb=$(on 192.0.2.20) || return 1
	if [ -n "$sa" ] && [ -n "$sb" ]; then
		echo "FAIL: the edge holds Packeteer routes from both instances: pk-a [$sa] pk-b [$sb]" >&2
		dump
		exit 1
	fi
	a=$sa
	b=$sb
}

want_route="198.51.100.0/24 192.0.2.2"

# only who: wait until the edge holds the route from exactly that instance
# (a, b, or none).
only() {
	local who=$1 tries=${2:-90} i
	for i in $(seq 1 "$tries"); do
		if sample; then
			case "$who" in
			a) [ "$a" = "$want_route" ] && [ -z "$b" ] && return 0 ;;
			b) [ "$b" = "$want_route" ] && [ -z "$a" ] && return 0 ;;
			none) [ -z "$a" ] && [ -z "$b" ] && return 0 ;;
			esac
		fi
		sleep 0.5
	done
	echo "timed out waiting for the route from $who only: pk-a [$a] pk-b [$b]" >&2
	dump
	return 1
}

# stay who seconds: the edge holds the route from that instance only, the
# whole time.
stay() {
	local who=$1 seconds=$2 end
	end=$(($(date +%s) + seconds))
	while [ "$(date +%s)" -lt "$end" ]; do
		if ! sample; then
			sleep 0.5
			continue
		fi
		case "$who" in
		a) [ "$a" = "$want_route" ] && [ -z "$b" ] && { sleep 0.5; continue; } ;;
		b) [ "$b" = "$want_route" ] && [ -z "$a" ] && { sleep 0.5; continue; } ;;
		esac
		echo "FAIL: expected the route from $who only: pk-a [$a] pk-b [$b]" >&2
		dump
		exit 1
	done
}

# role svc want [holder]: wait for /api/ha to report it.
role() {
	local svc=$1 want=$2 holder=${3:-} i out
	for i in $(seq 1 60); do
		out=$(api "$svc" /api/ha)
		if [[ "$out" == *"\"role\":\"$want\""* ]] && { [ -z "$holder" ] || [[ "$out" == *"\"holder\":\"$holder\""* ]]; }; then
			echo "$svc: $want${holder:+ (holder $holder)}"
			return 0
		fi
		sample || true
		sleep 1
	done
	echo "$svc is not $want${holder:+ with holder $holder}: $out" >&2
	dump
	return 1
}

# attributes peer: the path from that instance carries next hop 192.0.2.2,
# local-pref 250, 64512:666, and no-export (FRR's detail text, one path
# block from "192.0.2.2 from <peer>" to its "Last update").
attributes() {
	local peer=$1 block
	block=$(vty -c 'show bgp ipv4 unicast 198.51.100.0/24' 2>/dev/null |
		awk -v p="192.0.2.2 from $peer " 'index($0, p) { on = 1 } on { print } on && /Last update/ { exit }' || true)
	if [[ "$block" != *"localpref 250"* ]] || [[ "$block" != *"Community: 64512:666 no-export"* ]]; then
		echo "FAIL: the route from $peer lacks next hop 192.0.2.2, local-pref 250, 64512:666, or no-export: [$block]" >&2
		dump
		exit 1
	fi
}

kill9() {
	local svc=$1 cid status code i
	cid=$("${compose[@]}" ps -q "$svc")
	if [ -z "$cid" ]; then
		echo "$svc is not running" >&2
		dump
		exit 1
	fi
	docker kill -s KILL "$cid" >/dev/null
	for i in $(seq 1 25); do
		status=$(docker inspect -f '{{.State.Status}}' "$cid" 2>/dev/null || true)
		code=$(docker inspect -f '{{.State.ExitCode}}' "$cid" 2>/dev/null || true)
		if [ "$status" = "exited" ] && [ "$code" = "137" ]; then
			return 0
		fi
		sleep 0.2
	done
	echo "expected SIGKILL exit 137 for $svc, got status=${status:-unknown} code=${code:-unknown}" >&2
	dump
	exit 1
}

echo "1. pk-a alone takes the lease and announces"
only a
attributes 192.0.2.10
role packeteer-a active pk-a

echo "2. pk-b starts and stays standby"
"${compose[@]}" up -d packeteer-b
role packeteer-b standby pk-a
# Longer than a crash takeover (12s): the standby never announces while
# the active instance renews.
stay a 20
out=$(api packeteer-b /api/ha)
if [[ "$out" != *'"eligible":true'* ]]; then
	echo "FAIL: pk-b is not eligible (its session is not up): $out" >&2
	dump
	exit 1
fi

echo "3. backup while pk-a runs"
"${compose[@]}" exec -T packeteer-a packeteer -backup /var/lib/packeteer/ha/backup.tgz
"${compose[@]}" exec -T packeteer-a sh -c 'test -s /var/lib/packeteer/ha/backup.tgz'

echo "4. SIGKILL pk-a: pk-b takes over only after the edge dropped pk-a's route"
start=$(date +%s)
kill9 packeteer-a
only b 120
took=$(($(date +%s) - start))
echo "pk-b announces ${took}s after SIGKILL"
attributes 192.0.2.20
role packeteer-b active pk-b
if ! "${compose[@]}" logs --no-color packeteer-b | grep -q 'lease expired (held by pk-a)'; then
	echo "FAIL: pk-b did not take over an expired lease" >&2
	dump
	exit 1
fi

echo "5. pk-a restarts and stays standby"
"${compose[@]}" start packeteer-a
role packeteer-a standby pk-b
stay b 15

echo "6. session loss on the active pk-b hands over to pk-a"
vty -c 'configure terminal' -c 'router bgp 64512' -c 'neighbor 192.0.2.20 shutdown' -c 'end'
only a 60
role packeteer-a active pk-a
role packeteer-b standby
vty -c 'configure terminal' -c 'router bgp 64512' -c 'no neighbor 192.0.2.20 shutdown' -c 'end'
role packeteer-b standby pk-a
stay a 15

echo "7. SIGTERM pk-a: withdraw, resign, and pk-b takes over at once"
start=$(date +%s)
"${compose[@]}" stop -t 20 packeteer-a &
stopper=$!
only b 40
wait "$stopper"
took=$(($(date +%s) - start))
echo "pk-b announces ${took}s after SIGTERM"
if [ "$took" -gt 10 ]; then
	echo "FAIL: takeover after a clean shutdown took ${took}s (want at most 10s)" >&2
	dump
	exit 1
fi
if ! "${compose[@]}" logs --no-color packeteer-a | grep -q 'ha: lease released'; then
	echo "FAIL: pk-a did not release the lease on SIGTERM" >&2
	dump
	exit 1
fi
attributes 192.0.2.20

echo "8. SIGTERM pk-b: nothing left on the edge"
"${compose[@]}" stop -t 20 packeteer-b
only none 20

echo "9. restore the backup into pk-b's stopped volume with the stock image"
"${compose[@]}" run --rm --no-deps -T packeteer-b \
	-restore /var/lib/packeteer/ha/backup.tgz -restore-config /var/lib/packeteer/ha/restored.yaml -force
"${compose[@]}" run --rm --no-deps -T packeteer-b -check -config /var/lib/packeteer/ha/restored.yaml | grep -q 'ha: lease id=pk-a'

echo "e2e-ha ok"
