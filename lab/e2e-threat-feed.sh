#!/bin/bash
# Threat feed ingest (#134) against the threat mitigation lab's simulated
# edge and two simulated eBGP transits. Documentation prefixes and
# documentation/private ASNs only; the feed is a static file this script
# writes and a busybox web server serves.
#
# transit-a originates 198.51.100.0/24; the edge learns it, exports it to
# transit-b, and sends it to Packeteer. The feed lists sources; the source
# rule turns each into a FlowSpec drop toward 198.51.100.0/24 under
# max_active 2. Checked on the routers themselves:
#  - three listed sources: only the first two drops reach the edge
#    (max_active), never on transit-b (no-export), and the unicast path is
#    untouched (the marker is checked by the Go daemon test, since FRR's
#    flowspec output does not show communities);
#  - a listed 203.0.113.0/24 (allowlisted, not learned) is never announced,
#    as a blackhole or as a drop destination;
#  - a failed fetch (404) withdraws nothing;
#  - a source leaving the feed is withdrawn and frees a slot for the next;
#  - RIB session loss withdraws the drops; they come back with the session;
#  - SIGTERM withdraws them; a restart fetches the feed again and adds
#    them again from that fresh list;
#  - SIGKILL drops them with the session within the hold timer.
set -euo pipefail

root=$(cd "$(dirname "$0")/.." && pwd)
cd "$root"
compose=(docker compose -f lab/docker-compose-threat-feed.yml)

check_bin=$(mktemp)
FEED_DIR=$(mktemp -d)
export FEED_DIR
chmod 755 "$FEED_DIR"
trap 'rc=$?; if [ "$rc" -ne 0 ]; then echo "---- lab logs ----"; "${compose[@]}" logs --no-color || true; "${compose[@]}" ps || true; fi; "${compose[@]}" down -v --remove-orphans || true; rm -rf "$check_bin" "$FEED_DIR"; exit "$rc"' EXIT

# set_feed LINE...: the list the feed serves, swapped in atomically.
set_feed() {
	printf '%s\n' "$@" >"$FEED_DIR/drop.tmp"
	chmod 644 "$FEED_DIR/drop.tmp"
	mv "$FEED_DIR/drop.tmp" "$FEED_DIR/drop.txt"
}

# 203.0.113.0/24 is listed last: bad-dests (checked first) cannot announce
# it (not learned), and as a source toward 198.51.100.0/24 it stays behind
# the max_active cap for the whole run.
set_feed "192.0.2.101 ; lab bot 1" "192.0.2.102" "192.0.2.103" "203.0.113.0/24 ; not learned"

echo "building path check"
go build -o "$check_bin" ./lab/checkpath

echo "building lab"
"${compose[@]}" build
"${compose[@]}" up -d

prefix=198.51.100.0/24
base=http://192.0.2.10:8080/api

path_json() {
	"${compose[@]}" exec -T "$1" vtysh -c "show bgp ipv4 unicast $2 json" 2>/dev/null || true
}

# native: the edge's best unicast path is transit-a's, with no Packeteer
# community. FlowSpec never touches it.
native() {
	path_json edge "$prefix" | "$check_bin" -aspath "64496" -nexthop 192.0.2.21 -lacks 64512: -lacks blackhole
}

# fs_text R: FlowSpec rules in router R's BGP table.
fs_text() {
	"${compose[@]}" exec -T "$1" vtysh -c 'show bgp ipv4 flowspec detail' 2>/dev/null || true
}

# fs_drops SRC...: exactly these sources have a drop toward
# 198.51.100.0/24 on the edge, nothing toward 203.0.113.0/24, and nothing
# on transit-b (no-export).
fs_drops() {
	local e b s
	e=$(fs_text edge)
	b=$(fs_text transit-b)
	[ "$(grep -c '198\.51\.100\.0/24' <<<"$e" || true)" = "$#" ] || return 1
	grep -Eiq 'rate 0\.0|discard' <<<"$e" || return 1
	! grep -q '203\.0\.113' <<<"$e" || return 1
	! grep -q '198\.51\.100' <<<"$b" || return 1
	for s in "$@"; do
		grep -q "${s//./\\.}" <<<"$e" || return 1
	done
}

# fs_none: no FlowSpec rule from Packeteer on the edge.
fs_none() { ! grep -Eq '198\.51\.100\.|203\.0\.113\.' <<<"$(fs_text edge)"; }

# unlearned: anything for 203.0.113.0/24 from Packeteer on the edge.
unlearned() {
	grep -q '203\.0\.113' <<<"$(fs_text edge)" || grep -q '"prefix":"203.0.113.0/24"' <<<"$(path_json edge 203.0.113.0/24)"
}

# Lab-only basic auth (docker-compose-threat-feed.yml).
auth=(-u lab:lab-only)
api() { curl -sS "${auth[@]}" "$base/$1" 2>/dev/null || true; }
api_up() { curl -sf -o /dev/null "${auth[@]}" "$base/threat-feeds"; }

packeteer_logs() { "${compose[@]}" logs --no-color packeteer; }

dump() {
	for r in edge transit-a transit-b; do
		echo "---- $r ----" >&2
		"${compose[@]}" exec -T "$r" vtysh -c 'show bgp summary' >&2 || true
		echo "---- $r flowspec ----" >&2
		fs_text "$r" >&2
	done
	echo "---- threat feeds ----" >&2
	api threat-feeds >&2
	echo "---- mitigations ----" >&2
	api mitigations >&2
	echo "---- feed ----" >&2
	cat "$FEED_DIR/drop.txt" >&2 || true
	packeteer_logs >&2 || true
}

wait_for() {
	local what=$1
	shift
	local i
	for i in $(seq 1 60); do
		if "$@" 2>/dev/null; then
			return 0
		fi
		sleep 2
	done
	echo "timed out waiting for: $what" >&2
	"$@" || true
	dump
	return 1
}

# never SECONDS WHAT CMD...: CMD must stay false for SECONDS.
never() {
	local secs=$1 what=$2
	shift 2
	local i
	for i in $(seq 1 "$secs"); do
		if "$@" 2>/dev/null; then
			echo "unexpected: $what" >&2
			dump
			exit 1
		fi
		sleep 1
	done
}

# The logs are read into a variable first: with pipefail, grep -q exiting
# on the first match would SIGPIPE docker compose logs and fail the check.
log_has() {
	local logs
	logs=$(packeteer_logs)
	grep -qE "$1" <<<"$logs"
}

log_count() {
	local logs
	logs=$(packeteer_logs)
	grep -cE "$1" <<<"$logs" || true
}

need_log() {
	if ! log_has "$1"; then
		echo "packeteer log is missing: $1 ($2)" >&2
		dump
		exit 1
	fi
}

session_text() {
	"${compose[@]}" exec -T edge vtysh -c 'show bgp neighbors 192.0.2.10' 2>/dev/null || true
}

session_up() { [[ "$(session_text)" == *"BGP state = Established"* ]]; }

echo "waiting for the native path, the Packeteer session, and the ops API"
wait_for "native path" native
wait_for "packeteer session" session_up
wait_for "ops API" api_up

echo "three listed sources: two drops on the edge (max_active 2)"
wait_for "drops for .101 and .102" fs_drops 192.0.2.101 192.0.2.102
need_log 'threat feed mitigation added.*rule=bad-sources.*entry=192.0.2.101/32.*prefix=198.51.100.0/24.*action=flowspec_drop' "no add log"
need_log 'threat feed mitigations waiting.*max_active \(2\)' "the cap was not reported"
grep -q 'threat feed lab-drop (rule bad-sources): 192.0.2.101/32 listed: lab bot 1' <<<"$(api mitigations)" ||
	{ echo "the mitigation rule does not name the feed and entry" >&2; dump; exit 1; }
never 6 "a listed destination that is not learned was announced" unlearned
if log_has 'threat feed mitigation (added|refused).*rule=bad-dests'; then
	echo "the destination rule acted on an unlearned prefix" >&2
	dump
	exit 1
fi
fs_drops 192.0.2.101 192.0.2.102 || { echo "a third drop passed max_active" >&2; dump; exit 1; }
native || { echo "FlowSpec changed the unicast path" >&2; dump; exit 1; }

echo "the feed fails (404): nothing is withdrawn"
rm -f "$FEED_DIR/drop.txt"
wait_for "the failed fetch" log_has 'threat feed fetch failed.*feed=lab-drop.*404'
grep -q '"error":"feed answered 404' <<<"$(api threat-feeds)" || { echo "the failure is not on the API" >&2; dump; exit 1; }
fs_drops 192.0.2.101 192.0.2.102 || { echo "a failed fetch withdrew a drop" >&2; dump; exit 1; }

echo "the feed answers without .101: its drop is withdrawn and .103 takes the slot"
set_feed "192.0.2.102" "192.0.2.103" "203.0.113.0/24"
wait_for "drops for .102 and .103" fs_drops 192.0.2.102 192.0.2.103
need_log 'threat feed entry delisted; mitigation removed.*entry=192.0.2.101/32' "no delist log"

echo "RIB session loss withdraws the drops"
"${compose[@]}" exec -T edge vtysh -c 'configure terminal' -c 'router bgp 64512' -c 'neighbor 192.0.2.10 shutdown'
wait_for "packeteer to see the RIB go away" log_has 'rib not ready; withdrawing mitigation routes'
wait_for "no drop while the session is down" fs_none
"${compose[@]}" exec -T edge vtysh -c 'configure terminal' -c 'router bgp 64512' -c 'no neighbor 192.0.2.10 shutdown'
wait_for "session back" session_up
wait_for "the drops back with the session" fs_drops 192.0.2.102 192.0.2.103

echo "SIGTERM withdraws the drops"
withdrawn_before=$(log_count 'mitigation routes withdrawn')
"${compose[@]}" stop -t 20 packeteer
wait_for "no drop after SIGTERM" fs_none
if [ "$(log_count 'mitigation routes withdrawn')" -le "$withdrawn_before" ]; then
	echo "SIGTERM did not withdraw the drops while the session was up" >&2
	dump
	exit 1
fi

echo "restart: the feed is fetched again and its drops come back"
"${compose[@]}" start packeteer
wait_for "ops API after restart" api_up
wait_for "packeteer session after restart" session_up
wait_for "the drops from the fresh fetch" fs_drops 192.0.2.102 192.0.2.103

hold=$(awk '$1 == "neighbor" && $2 == "192.0.2.10" && $3 == "timers" { print $5 }' lab/frr-mit-edge/frr.conf)
case "$hold" in
'' | *[!0-9]*)
	echo "lab hold timer is not an integer: '${hold}'" >&2
	exit 1
	;;
esac
if [ "$hold" -lt 3 ] || [ "$hold" -gt 30 ]; then
	echo "lab hold timer ${hold}s is not a bounded crash-test value (want 3-30)" >&2
	exit 1
fi

echo "SIGKILL packeteer (no WithdrawAll)"
cid=$("${compose[@]}" ps -q packeteer)
if [ -z "$cid" ]; then
	echo "packeteer is not running" >&2
	dump
	exit 1
fi
start=$(date +%s)
docker kill -s KILL "$cid"
code=
for _ in $(seq 1 25); do
	code=$(docker inspect -f '{{.State.ExitCode}}' "$cid" 2>/dev/null || true)
	if [ "$(docker inspect -f '{{.State.Status}}' "$cid" 2>/dev/null || true)" = "exited" ] && [ "$code" = "137" ]; then
		break
	fi
	sleep 0.2
done
if [ "$code" != "137" ]; then
	echo "expected SIGKILL exit 137, got ${code:-unknown}" >&2
	dump
	exit 1
fi

echo "waiting for the edge to drop the FlowSpec rules after session loss (hold ${hold}s)"
deadline=$((start + hold + 10))
cleared=0
while [ "$(date +%s)" -le "$deadline" ]; do
	nbr=$(session_text)
	if [[ "$nbr" == *"BGP state = Established"* ]]; then
		if ! fs_drops 192.0.2.102 192.0.2.103 2>/dev/null; then
			echo "the drops cleared while the session to the dead process is still Established" >&2
			dump
			exit 1
		fi
	elif [[ "$nbr" == *"BGP state ="* ]] && fs_none; then
		cleared=1
		break
	fi
	sleep 1
done
if [ "$cleared" -ne 1 ]; then
	echo "FlowSpec drops still on the edge after SIGKILL past the ${hold}s hold timer" >&2
	dump
	exit 1
fi
echo "session lost and drops gone $(($(date +%s) - start))s after SIGKILL (hold ${hold}s)"

echo "threat feed e2e ok"
