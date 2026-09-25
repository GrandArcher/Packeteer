#!/bin/bash
# Commit-cause injection against the same FRR edge as lab/e2e.sh.
# The fixed prober stays inside the latency threshold, so the route is a
# commit steer. Documentation prefix and private ASN only.
set -euo pipefail

root=$(cd "$(dirname "$0")/.." && pwd)
cd "$root"
export PACKETEER_LAB_CONFIG="$root/lab/packeteer-commit.yaml"
compose=(docker compose -f lab/docker-compose.yml)

lab_dir=$(mktemp -d)
check_bin=$(mktemp)
trap 'rc=$?; if [ "$rc" -ne 0 ]; then echo "---- lab logs ----"; "${compose[@]}" logs --no-color || true; "${compose[@]}" ps || true; fi; "${compose[@]}" down -v --remove-orphans || true; rm -f "$check_bin"; rm -rf "$lab_dir"; exit "$rc"' EXIT

echo "building route check"
go build -o "$check_bin" ./lab/checkroute

cp lab/probes/commit-equal.yaml "$lab_dir/state.yaml"
cp lab/probes/usage-over.yaml "$lab_dir/usage.yaml"
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
	"${compose[@]}" logs --no-color packeteer >&2 || true
}

route_is() {
	local mode=$1
	printf '%s\n' "$(bgp_text)" | "$check_bin" "$mode"
}

neighbor_text() {
	"${compose[@]}" exec -T edge vtysh -c 'show bgp neighbors 192.0.2.10' 2>/dev/null || true
}

session_established() {
	local out
	out=$(neighbor_text)
	[[ "$out" == *"BGP state = Established"* ]]
}

session_down() {
	local out
	out=$(neighbor_text)
	[[ "$out" == *"BGP state ="* ]] || return 1
	[[ "$out" != *"BGP state = Established"* ]]
}

wait_route() {
	local mode=$1
	local tries=${2:-40}
	local pause=${3:-2}
	local i
	for i in $(seq 1 "$tries"); do
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

flip_usage() {
	local src=$1
	local tmp
	tmp=$(mktemp "$lab_dir/.usage.XXXXXX")
	cp "$src" "$tmp"
	mv "$tmp" "$lab_dir/usage.yaml"
}

echo "waiting for the commit steer"
wait_route present
logs=$("${compose[@]}" logs --no-color packeteer)
if ! printf '%s\n' "$logs" | grep -q 'cause=commit'; then
	echo "announced route was not a commit improvement" >&2
	dump_bgp
	exit 1
fi
if printf '%s\n' "$logs" | grep -q 'cause=performance'; then
	echo "commit lab produced a performance improvement" >&2
	dump_bgp
	exit 1
fi

echo "usage back under commit; the steer must withdraw"
flip_usage lab/probes/usage-under.yaml
wait_route absent
logs=$("${compose[@]}" logs --no-color packeteer)
if ! printf '%s\n' "$logs" | grep -q 'commit relieved'; then
	echo "withdraw was not a commit release" >&2
	dump_bgp
	exit 1
fi

echo "usage over commit again (after the release cooldown)"
flip_usage lab/probes/usage-over.yaml
wait_route present

echo "stopping packeteer (SIGTERM, WithdrawAll)"
"${compose[@]}" stop -t 20 packeteer
wait_route absent

echo "starting packeteer again for the crash path"
"${compose[@]}" start packeteer
wait_route present

hold=$(awk '$1 == "neighbor" && $2 == "192.0.2.10" && $3 == "timers" { print $5 }' lab/frr/frr.conf)
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
nbr=$(neighbor_text)
negotiated=$(printf '%s\n' "$nbr" | sed -n 's/^[[:space:]]*Hold time is \([0-9][0-9]*\) seconds.*/\1/p')
negotiated=${negotiated%%$'\n'*}
if [ "$negotiated" != "$hold" ]; then
	echo "negotiated hold '${negotiated}' != configured ${hold}s" >&2
	printf '%s\n' "$nbr" >&2
	dump_bgp
	exit 1
fi

if ! route_is present; then
	echo "route gone before SIGKILL" >&2
	dump_bgp
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
killed=0
status=
code=
for _ in $(seq 1 25); do
	status=$(docker inspect -f '{{.State.Status}}' "$cid" 2>/dev/null || true)
	code=$(docker inspect -f '{{.State.ExitCode}}' "$cid" 2>/dev/null || true)
	if [ "$status" = "exited" ] && [ "$code" = "137" ]; then
		killed=1
		break
	fi
	sleep 0.2
done
if [ "$killed" -ne 1 ]; then
	echo "expected SIGKILL exit 137, got status=${status:-unknown} code=${code:-unknown}" >&2
	dump_bgp
	exit 1
fi

echo "waiting for FRR to drop the route after session loss (hold ${hold}s)"
deadline=$((start + hold + 6))
dropped=0
while [ "$(date +%s)" -le "$deadline" ]; do
	if session_established; then
		if ! route_is present; then
			if session_established; then
				echo "route withdrawn while the BGP session is still Established" >&2
				dump_bgp
				exit 1
			fi
		fi
	fi
	snap=$(bgp_text)
	if [[ "$snap" == *"198.51.100.0/24"* ]] \
		&& printf '%s\n' "$snap" | "$check_bin" absent \
		&& session_down; then
		dropped=1
		break
	fi
	sleep 1
done
if [ "$dropped" -ne 1 ]; then
	echo "injected route still present after SIGKILL past the ${hold}s hold timer" >&2
	dump_bgp
	exit 1
fi
echo "session lost and injected route gone $(($(date +%s) - start))s after SIGKILL (hold ${hold}s)"

echo "commit e2e ok"
