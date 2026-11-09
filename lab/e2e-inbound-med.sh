#!/bin/bash
# Inbound MED steering (#303) against a simulated edge with two sessions to
# one simulated transit (AS 64496). Documentation prefixes and
# documentation/private ASNs only.
#
# link-1's inbound 95th is over commit, so Packeteer re-announces
# 203.0.113.0/24 to the edge with link-1's MED signal (64512:1301). The
# edge must then send the prefix on link 1 with MED 100 and on link 2 with
# MED 0, and the transit must pick link 2. Release puts MED 0 back on link 1.
# A second steer is withdrawn by SIGTERM, and after a restart a third by
# SIGKILL within the BGP hold timer. Every step is checked on the transit.
set -euo pipefail

root=$(cd "$(dirname "$0")/.." && pwd)
cd "$root"
compose=(docker compose -f lab/docker-compose-inbound-med.yml)

lab_dir=$(mktemp -d)
check_bin=$(mktemp)
trap 'rc=$?; if [ "$rc" -ne 0 ]; then echo "---- lab logs ----"; "${compose[@]}" logs --no-color || true; "${compose[@]}" ps || true; fi; "${compose[@]}" down -v --remove-orphans || true; rm -f "$check_bin"; rm -rf "$lab_dir"; exit "$rc"' EXIT

echo "building path check"
go build -o "$check_bin" ./lab/checkpath

cp lab/probes/inbound-med-over.yaml "$lab_dir/usage.yaml"
cp lab/probes/inbound-med-paths.yaml "$lab_dir/paths.yaml"
chmod 0644 "$lab_dir/usage.yaml" "$lab_dir/paths.yaml"
export PACKETEER_LAB_DIR="$lab_dir"

echo "building lab"
"${compose[@]}" build
"${compose[@]}" up -d

prefix=203.0.113.0/24
link1=192.0.2.254
link2=198.51.100.254

path_json() {
	"${compose[@]}" exec -T transit-m vtysh -c "show bgp ipv4 unicast $prefix json" 2>/dev/null || true
}

# steered: MED 100 on link 1, MED 0 on link 2, the transit's best path on
# link 2, and no Packeteer community on either session.
steered() {
	local raw
	raw=$(path_json)
	"$check_bin" -from "$link1" -aspath 64512 -med 100 -lacks 64512: -lacks no-export <<<"$raw" &&
		"$check_bin" -from "$link2" -aspath 64512 -med 0 -lacks 64512: -lacks no-export <<<"$raw" &&
		"$check_bin" -nexthop "$link2" -med 0 <<<"$raw"
}

# plain: both sessions carry the prefix with MED 0 and no Packeteer
# community.
plain() {
	local raw
	raw=$(path_json)
	"$check_bin" -from "$link1" -aspath 64512 -med 0 -lacks 64512: -lacks no-export <<<"$raw" &&
		"$check_bin" -from "$link2" -aspath 64512 -med 0 -lacks 64512: -lacks no-export <<<"$raw"
}

dump_bgp() {
	for r in edge transit-m; do
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

flip_usage() {
	local tmp
	tmp=$(mktemp "$lab_dir/.flip.XXXXXX")
	cp "$1" "$tmp"
	chmod 0644 "$tmp"
	mv "$tmp" "$lab_dir/usage.yaml"
}

packeteer_logs() { "${compose[@]}" logs --no-color packeteer; }

# The logs are read into a variable first: with pipefail, grep -q exiting
# on the first match would SIGPIPE docker compose logs and fail the check.
need_log() {
	local logs
	logs=$(packeteer_logs)
	if ! grep -qE "$1" <<<"$logs"; then
		echo "packeteer log is missing: $1 ($2)" >&2
		dump_bgp
		exit 1
	fi
}

session_text() {
	"${compose[@]}" exec -T edge vtysh -c 'show bgp neighbors 192.0.2.10' 2>/dev/null || true
}

echo "link-1 over commit: waiting for MED 100 on link 1 and the transit on link 2"
wait_for "MED steer away from link-1" steered
need_log 'msg="inbound steer".*trigger=commit.*provider=link-1.*med=100' "steer was not link-1's MED action"
need_log 'msg="inbound announced".*away=link-1 communities="64512:666 64512:667 64512:1301"' "steer route did not carry link-1's MED signal"
logs=$(packeteer_logs)
if grep -q 'msg="inbound steer".*provider=link-2\|msg=injected' <<<"$logs"; then
	echo "link-2 was steered or an outbound improvement was made" >&2
	dump_bgp
	exit 1
fi

echo "link-1 back under release_pct: MED 0 on both links"
flip_usage lab/probes/inbound-med-under.yaml
wait_for "both links plain after release" plain
need_log 'msg="inbound release".*provider=link-1' "withdraw was not an inbound release"

echo "over commit again, then SIGTERM (WithdrawAll)"
flip_usage lab/probes/inbound-med-over.yaml
wait_for "MED steer again" steered
"${compose[@]}" stop -t 20 packeteer
wait_for "both links plain after SIGTERM" plain
need_log 'inbound steer routes withdrawn' "SIGTERM did not withdraw the steer route"

echo "restart over commit: MED steer for the crash path"
"${compose[@]}" start packeteer
wait_for "MED steer after restart" steered

hold=$(awk '$1 == "neighbor" && $2 == "192.0.2.10" && $3 == "timers" { print $5 }' lab/frr-inbound-med/frr.conf)
case "$hold" in
''|*[!0-9]*)
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
	dump_bgp
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
	dump_bgp
	exit 1
fi

echo "waiting for the edge to drop the steer after session loss (hold ${hold}s)"
deadline=$((start + hold + 10))
cleared=0
while [ "$(date +%s)" -le "$deadline" ]; do
	nbr=$(session_text)
	if [[ "$nbr" == *"BGP state = Established"* ]]; then
		if ! steered 2>/dev/null; then
			echo "steer cleared while the session to the dead process is still Established" >&2
			dump_bgp
			exit 1
		fi
	elif [[ "$nbr" == *"BGP state ="* ]] && plain 2>/dev/null; then
		cleared=1
		break
	fi
	sleep 1
done
if [ "$cleared" -ne 1 ]; then
	echo "MED still on link 1 after SIGKILL past the ${hold}s hold timer" >&2
	dump_bgp
	exit 1
fi
echo "session lost and both links plain $(($(date +%s) - start))s after SIGKILL (hold ${hold}s)"

echo "inbound MED e2e ok"
