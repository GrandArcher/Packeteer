#!/bin/bash
# Threat mitigation (#28, first half: RTBH and BGP redirect) against a
# simulated edge with two simulated eBGP transits. Documentation prefixes
# and documentation/private ASNs only.
#
# transit-a originates 198.51.100.0/24; the edge learns it, exports it to
# transit-b, and sends it to Packeteer. Rules come in through the ops API.
# Checked on the routers themselves:
#  - a rule outside the mitigation allowlist is refused; an allowlisted
#    more-specific that is not in the learned RIB is held and never
#    announced; max_rules refuses a third prefix;
#  - RTBH: the edge's best path is Packeteer's, next hop 192.0.2.66 with
#    BLACKHOLE, the marker, and no-export, and its FIB drops the prefix;
#    no-export keeps it off transit-b;
#  - redirect replaces it in place (next hop 192.0.2.77 in the FIB);
#  - DELETE restores the native path; a short TTL expires on its own;
#  - SIGTERM withdraws; a restart holds no rule (no stale intent);
#  - SIGKILL drops the route with the session within the hold timer.
set -euo pipefail

root=$(cd "$(dirname "$0")/.." && pwd)
cd "$root"
compose=(docker compose -f lab/docker-compose-mitigation.yml)

check_bin=$(mktemp)
trap 'rc=$?; if [ "$rc" -ne 0 ]; then echo "---- lab logs ----"; "${compose[@]}" logs --no-color || true; "${compose[@]}" ps || true; fi; "${compose[@]}" down -v --remove-orphans || true; rm -f "$check_bin"; exit "$rc"' EXIT

echo "building path check"
go build -o "$check_bin" ./lab/checkpath

echo "building lab"
"${compose[@]}" build
"${compose[@]}" up -d

prefix=198.51.100.0/24
api=http://192.0.2.10:8080/api/mitigations

path_json() {
	"${compose[@]}" exec -T "$1" vtysh -c "show bgp ipv4 unicast $2 json" 2>/dev/null || true
}

# fib is zebra's view of the prefix on the edge. A recursive route prints
# "via <next hop> (recursive)" and then the resolved next hop, flagged "*"
# when it is in the FIB; the discard address resolves to
# "unreachable (blackhole)".
fib() {
	"${compose[@]}" exec -T edge vtysh -c "show ip route $prefix" 2>/dev/null || true
}

# native: the edge uses transit-a with no Packeteer community, forwards
# to transit-a, and transit-b gets the prefix with no Packeteer community.
# fib output is read into a variable first: with pipefail, grep -q exiting
# early could SIGPIPE docker compose and fail the check.
native() {
	local f
	f=$(fib)
	path_json edge "$prefix" | "$check_bin" -aspath "64496" -nexthop 192.0.2.21 -lacks 64512: -lacks blackhole &&
		grep -Eq '\*.*via 192\.0\.2\.21' <<<"$f" &&
		path_json transit-b "$prefix" | "$check_bin" -aspath "64512 64496" -lacks 64512: -lacks blackhole -lacks no-export
}

# blackholed: Packeteer's RTBH route is the edge's best, the FIB drops the
# prefix, and no-export keeps it off transit-b.
blackholed() {
	local f
	f=$(fib)
	path_json edge "$prefix" | "$check_bin" -nexthop 192.0.2.66 -has 64512:666 -has 64512:668 -has blackhole -has no-export -lacks 64512:777 &&
		grep -q 'via 192.0.2.66' <<<"$f" && grep -Eq '\*.*blackhole' <<<"$f" &&
		path_json transit-b "$prefix" | "$check_bin" -absent
}

redirected() {
	local f
	f=$(fib)
	path_json edge "$prefix" | "$check_bin" -nexthop 192.0.2.77 -has 64512:666 -has 64512:668 -has 64512:777 -has no-export -lacks blackhole &&
		grep -Eq '\*.*via 192\.0\.2\.77' <<<"$f" &&
		path_json transit-b "$prefix" | "$check_bin" -absent
}

dump_bgp() {
	for r in edge transit-a transit-b; do
		echo "---- $r ----" >&2
		"${compose[@]}" exec -T "$r" vtysh -c 'show bgp summary' >&2 || true
		"${compose[@]}" exec -T "$r" vtysh -c "show bgp ipv4 unicast $prefix" >&2 || true
	done
	echo "---- edge fib ----" >&2
	fib >&2
	"${compose[@]}" exec -T edge ip route show >&2 || true
	curl -sS -u lab:lab-only "$api" >&2 || true
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

# post BODY: prints the HTTP status, and the body to $lab_body.
lab_body=$(mktemp)
post() {
	curl -sS -o "$lab_body" -w '%{http_code}' -u lab:lab-only -H 'Content-Type: application/json' -d "$1" "$api"
}

expect_post() {
	local want=$1 body=$2 got
	got=$(post "$body")
	if [ "$got" != "$want" ]; then
		echo "POST $body: HTTP $got, want $want" >&2
		cat "$lab_body" >&2
		dump_bgp
		exit 1
	fi
}

rule_id() { sed -n 's/.*"id":"\([0-9a-f]*\)".*/\1/p' "$lab_body"; }

delete_rule() {
	local got
	got=$(curl -sS -o /dev/null -w '%{http_code}' -u lab:lab-only -X DELETE "$api/$1")
	if [ "$got" != "204" ]; then
		echo "DELETE $1: HTTP $got, want 204" >&2
		dump_bgp
		exit 1
	fi
}

api_up() { curl -sf -o /dev/null -u lab:lab-only "$api"; }

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

session_up() { [[ "$(session_text)" == *"BGP state = Established"* ]]; }

echo "waiting for the native path, the Packeteer session, and the ops API"
wait_for "native path" native
wait_for "packeteer session" session_up
wait_for "ops API" api_up

echo "refusals: outside the mitigation allowlist, and without credentials"
expect_post 400 '{"prefix":"203.0.113.0/24","action":"blackhole"}'
got=$(curl -sS -o /dev/null -w '%{http_code}' -H 'Content-Type: application/json' -d '{"prefix":"198.51.100.0/24","action":"blackhole"}' "$api")
if [ "$got" != "401" ]; then
	echo "POST without credentials: HTTP $got, want 401" >&2
	exit 1
fi

echo "allowlisted more-specific that is not in the RIB: held, never announced"
expect_post 201 '{"prefix":"198.51.100.128/25","action":"blackhole","ttl":"30m"}'

echo "RTBH for $prefix"
expect_post 201 '{"prefix":"198.51.100.0/24","action":"blackhole","ttl":"30m","reason":"lab"}'
echo "max_rules 2: a third prefix is refused"
expect_post 409 '{"prefix":"198.51.100.0/26","action":"blackhole"}'
wait_for "RTBH on the edge (BGP, FIB) and nothing on transit-b" blackholed
need_log 'msg="mitigation announced".*prefix=198.51.100.0/24.*action=blackhole' "no RTBH announce log"
need_log 'mitigation rule waits: prefix is not in the learned RIB.*198.51.100.128/25' "more-specific was not held back"
for _ in 1 2 3; do
	if "${compose[@]}" exec -T edge vtysh -c 'show bgp ipv4 unicast 198.51.100.128/25 json' | "$check_bin" -has 64512:666 2>/dev/null; then
		echo "a prefix that is not in the learned RIB was announced" >&2
		dump_bgp
		exit 1
	fi
	sleep 1
done

echo "redirect to the scrubber replaces it in place"
expect_post 201 '{"prefix":"198.51.100.0/24","action":"redirect","target":"scrubber","ttl":"30m"}'
redirect_id=$(rule_id)
wait_for "redirect on the edge" redirected

echo "DELETE restores the native path"
delete_rule "$redirect_id"
wait_for "native after DELETE" native
need_log 'msg="mitigation withdrawn".*prefix=198.51.100.0/24' "no withdraw log"

echo "TTL: an 8s blackhole expires on its own"
expect_post 201 '{"prefix":"198.51.100.0/24","action":"blackhole","ttl":"8s"}'
wait_for "RTBH with a short TTL" blackholed
wait_for "native after TTL expiry" native
need_log 'msg="mitigation rule expired".*prefix=198.51.100.0/24' "no expiry log"

echo "SIGTERM withdraws"
expect_post 201 '{"prefix":"198.51.100.0/24","action":"blackhole","ttl":"30m"}'
wait_for "RTBH before SIGTERM" blackholed
"${compose[@]}" stop -t 20 packeteer
wait_for "native after SIGTERM" native
need_log 'mitigation routes withdrawn' "SIGTERM did not withdraw the mitigation route"

echo "restart: rules are in memory only; nothing comes back"
"${compose[@]}" start packeteer
wait_for "ops API after restart" api_up
wait_for "packeteer session after restart" session_up
rules=$(curl -sS -u lab:lab-only "$api")
if ! grep -q '"rules":\[\]' <<<"$rules"; then
	echo "rules survived a restart: $rules" >&2
	dump_bgp
	exit 1
fi
for _ in $(seq 1 8); do
	if ! native 2>/dev/null; then
		echo "a mitigation route came back after a restart" >&2
		dump_bgp
		exit 1
	fi
	sleep 1
done

echo "RTBH for the crash path"
wait_for "prefix learned again after restart" native
expect_post 201 '{"prefix":"198.51.100.0/24","action":"blackhole","ttl":"30m"}'
wait_for "RTBH before SIGKILL" blackholed

hold=$(awk '$1 == "neighbor" && $2 == "192.0.2.10" && $3 == "timers" { print $5 }' lab/frr-mit-edge/frr.conf)
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

echo "waiting for the edge to drop the RTBH route after session loss (hold ${hold}s)"
deadline=$((start + hold + 10))
cleared=0
while [ "$(date +%s)" -le "$deadline" ]; do
	nbr=$(session_text)
	if [[ "$nbr" == *"BGP state = Established"* ]]; then
		if ! blackholed 2>/dev/null; then
			echo "RTBH cleared while the session to the dead process is still Established" >&2
			dump_bgp
			exit 1
		fi
	elif [[ "$nbr" == *"BGP state ="* ]] && native 2>/dev/null; then
		cleared=1
		break
	fi
	sleep 1
done
if [ "$cleared" -ne 1 ]; then
	echo "RTBH still on the edge after SIGKILL past the ${hold}s hold timer" >&2
	dump_bgp
	exit 1
fi
echo "session lost and native path back $(($(date +%s) - start))s after SIGKILL (hold ${hold}s)"
rm -f "$lab_body"

echo "mitigation e2e ok"
