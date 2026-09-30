#!/bin/bash
# Threat mitigation (#28: RTBH, BGP redirect, and FlowSpec) against a
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
#  - FlowSpec: a rule for an allowlisted prefix that is not learned is
#    never announced; a drop by source country (GeoIP, test countries
#    from lab/mkgeoip) reaches the edge as one rule per country network
#    and never reaches transit-b (no-export); max_rules counts those
#    routes; a rate limit replaces it in place; DELETE withdraws; a
#    redirect to a VRF route target;
#  - SIGTERM withdraws RTBH and FlowSpec; a restart holds no rule (no
#    stale intent);
#  - SIGKILL drops RTBH and FlowSpec with the session within the hold
#    timer.
set -euo pipefail

root=$(cd "$(dirname "$0")/.." && pwd)
cd "$root"
compose=(docker compose -f lab/docker-compose-mitigation.yml)

check_bin=$(mktemp)
geo_db=lab/mitigation-country.mmdb
trap 'rc=$?; if [ "$rc" -ne 0 ]; then echo "---- lab logs ----"; "${compose[@]}" logs --no-color || true; "${compose[@]}" ps || true; fi; "${compose[@]}" down -v --remove-orphans || true; rm -f "$check_bin" "$geo_db"; exit "$rc"' EXIT

echo "building path check"
go build -o "$check_bin" ./lab/checkpath

# Test countries: XA is 203.0.113.0/26 + 203.0.113.64/26 (merged to
# 203.0.113.0/25) and 192.0.2.224/27, so two FlowSpec rules; XB is one
# network. Documentation prefixes only.
echo "writing the lab GeoIP database"
go run ./lab/mkgeoip -o "$geo_db" 203.0.113.0/26=XA 203.0.113.64/26=XA 192.0.2.224/27=XA 203.0.113.128/25=XB
chmod 0644 "$geo_db"

echo "building lab"
"${compose[@]}" build
"${compose[@]}" up -d

prefix=198.51.100.0/24
api=http://192.0.2.10:8080/api/mitigations

path_json() {
	"${compose[@]}" exec -T "$1" vtysh -c "show bgp ipv4 unicast $2 json" 2>/dev/null || true
}

# fib is zebra's detail view of the prefix on the edge plus the kernel
# table. A FIB check passes on either: zebra prints "* 192.0.2.21, via
# eth0" for an installed next hop, and a route resolved through the
# discard address as "192.0.2.66 (recursive)" plus "* unreachable
# (blackhole)"; the kernel prints "198.51.100.0/24 ... via 192.0.2.21" or
# "blackhole 198.51.100.0/24".
fib() {
	"${compose[@]}" exec -T edge vtysh -c "show ip route $prefix" 2>/dev/null || true
	echo "---- kernel ----"
	"${compose[@]}" exec -T edge ip route show 2>/dev/null || true
}

# fib_via F NH: the prefix is installed toward next hop NH. Zebra's part
# is before the kernel marker, the kernel's after it.
fib_via() {
	local z=${1%%---- kernel ----*} k=${1#*---- kernel ----} nh=${2//./\\.}
	grep -Eq "^ *\* +${nh}[, ]" <<<"$z" || grep -Eq "^198\.51\.100\.0/24 .*via ${nh} " <<<"$k"
}

# fib_drop F: the prefix resolves to the discard address and is dropped.
fib_drop() {
	local z=${1%%---- kernel ----*} k=${1#*---- kernel ----}
	{ grep -q '192\.0\.2\.66' <<<"$z" && grep -Eq '^ *\*.*blackhole' <<<"$z"; } ||
		grep -Eq '^blackhole 198\.51\.100\.0/24' <<<"$k"
}

# native: the edge uses transit-a with no Packeteer community, forwards
# to transit-a, and transit-b gets the prefix with no Packeteer community.
# fib output is read into a variable first: with pipefail, grep -q exiting
# early could SIGPIPE docker compose and fail the check.
native() {
	local f
	f=$(fib)
	path_json edge "$prefix" | "$check_bin" -aspath "64496" -nexthop 192.0.2.21 -lacks 64512: -lacks blackhole &&
		fib_via "$f" 192.0.2.21 &&
		path_json transit-b "$prefix" | "$check_bin" -aspath "64512 64496" -lacks 64512: -lacks blackhole -lacks no-export
}

# blackholed: Packeteer's RTBH route is the edge's best, the FIB drops the
# prefix, and no-export keeps it off transit-b.
blackholed() {
	local f
	f=$(fib)
	path_json edge "$prefix" | "$check_bin" -nexthop 192.0.2.66 -has 64512:666 -has 64512:668 -has blackhole -has no-export -lacks 64512:777 &&
		fib_drop "$f" &&
		path_json transit-b "$prefix" | "$check_bin" -absent
}

redirected() {
	local f
	f=$(fib)
	path_json edge "$prefix" | "$check_bin" -nexthop 192.0.2.77 -has 64512:666 -has 64512:668 -has 64512:777 -has no-export -lacks blackhole &&
		fib_via "$f" 192.0.2.77 &&
		path_json transit-b "$prefix" | "$check_bin" -absent
}

# fs_text R: FlowSpec rules in router R's BGP table.
fs_text() {
	"${compose[@]}" exec -T "$1" vtysh -c 'show bgp ipv4 flowspec detail' 2>/dev/null || true
}

# fs_count T: FlowSpec rules toward 198.51.100.0/24 in text T.
fs_count() { grep -c '198\.51\.100\.0/24' <<<"$1" || true; }

# fs_country_drop: two drop rules from the XA networks for UDP port 53 on
# the edge; nothing on transit-b.
fs_country_drop() {
	local e b
	e=$(fs_text edge)
	b=$(fs_text transit-b)
	[ "$(fs_count "$e")" = 2 ] && grep -q '203\.0\.113\.0/25' <<<"$e" && grep -q '192\.0\.2\.224/27' <<<"$e" &&
		grep -Eiq 'rate 0\.0|discard' <<<"$e" && ! grep -q '198\.51\.100' <<<"$b"
}

fs_rate_limited() {
	local e b
	e=$(fs_text edge)
	b=$(fs_text transit-b)
	[ "$(fs_count "$e")" = 2 ] && [ "$(grep -c 'rate 1000000' <<<"$e" || true)" = 2 ] && ! grep -q '198\.51\.100' <<<"$b"
}

fs_redirected() {
	local e b
	e=$(fs_text edge)
	b=$(fs_text transit-b)
	[ "$(fs_count "$e")" = 1 ] && grep -q '64512:779' <<<"$e" && ! grep -q '198\.51\.100' <<<"$b"
}

fs_dropping() {
	local e
	e=$(fs_text edge)
	[ "$(fs_count "$e")" = 1 ] && grep -Eiq 'rate 0\.0|discard' <<<"$e"
}

fs_none() {
	local e
	e=$(fs_text edge)
	[ "$(fs_count "$e")" = 0 ]
}

dump_bgp() {
	for r in edge transit-a transit-b; do
		echo "---- $r ----" >&2
		"${compose[@]}" exec -T "$r" vtysh -c 'show bgp summary' >&2 || true
		"${compose[@]}" exec -T "$r" vtysh -c "show bgp ipv4 unicast $prefix" >&2 || true
		echo "---- $r flowspec ----" >&2
		fs_text "$r" >&2
	done
	echo "---- edge fib ----" >&2
	fib >&2
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
pending_id=$(rule_id)

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

echo "FlowSpec: free the cap (remove the waiting more-specific RTBH rule)"
delete_rule "$pending_id"

log_has() {
	local logs
	logs=$(packeteer_logs)
	grep -qE "$1" <<<"$logs"
}

echo "FlowSpec for an allowlisted prefix that is not learned: held, never announced"
expect_post 201 '{"prefix":"198.51.100.128/25","action":"flowspec_drop","ttl":"30m"}'
fs_pending_id=$(rule_id)
wait_for "the FlowSpec rule to wait for the RIB" log_has 'mitigation flowspec rule waits: prefix is not in the learned RIB.*198.51.100.128/25'
for _ in 1 2 3; do
	e=$(fs_text edge)
	if grep -q '198\.51\.100\.128/25' <<<"$e"; then
		echo "a FlowSpec rule for a prefix that is not in the learned RIB was announced" >&2
		dump_bgp
		exit 1
	fi
	sleep 1
done
delete_rule "$fs_pending_id"

echo "FlowSpec drop by source country XA (two networks: two rules)"
expect_post 201 '{"prefix":"198.51.100.0/24","action":"flowspec_drop","source_countries":["XA"],"match":{"protocols":["udp"],"destination_ports":[53]},"ttl":"30m","reason":"lab"}'
wait_for "country drop on the edge and nothing on transit-b" fs_country_drop
need_log 'msg="mitigation flowspec announced".*action=flowspec_drop' "no FlowSpec announce log"
echo "max_rules 2 counts routes: one more FlowSpec rule is refused"
expect_post 409 '{"prefix":"198.51.100.0/24","action":"flowspec_drop","match":{"protocols":["tcp"]}}'

echo "FlowSpec rate limit (8 Mbit/s = 1000000 bytes/s) replaces the drop in place"
expect_post 201 '{"prefix":"198.51.100.0/24","action":"flowspec_rate_limit","rate_mbps":8,"source_countries":["XA"],"match":{"protocols":["udp"],"destination_ports":["53"]},"ttl":"30m"}'
country_id=$(rule_id)
wait_for "rate limit on the edge" fs_rate_limited

echo "DELETE withdraws the FlowSpec rules"
delete_rule "$country_id"
wait_for "no FlowSpec after DELETE" fs_none
wait_for "native path untouched by FlowSpec" native

echo "FlowSpec redirect to the scrubbing VRF (route target 64512:779)"
expect_post 201 '{"prefix":"198.51.100.0/24","action":"flowspec_redirect","target":"scrub-vrf","match":{"protocols":["tcp"],"destination_ports":["80","443"]},"ttl":"30m"}'
wait_for "FlowSpec redirect on the edge" fs_redirected

echo "SIGTERM withdraws RTBH and FlowSpec"
expect_post 201 '{"prefix":"198.51.100.0/24","action":"blackhole","ttl":"30m"}'
wait_for "RTBH before SIGTERM" blackholed
fs_redirected || { echo "FlowSpec redirect gone before SIGTERM" >&2; dump_bgp; exit 1; }
"${compose[@]}" stop -t 20 packeteer
wait_for "native after SIGTERM" native
wait_for "no FlowSpec after SIGTERM" fs_none
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
	if ! native 2>/dev/null || ! fs_none; then
		echo "a mitigation route came back after a restart" >&2
		dump_bgp
		exit 1
	fi
	sleep 1
done

echo "RTBH and a FlowSpec drop for the crash path"
wait_for "prefix learned again after restart" native
expect_post 201 '{"prefix":"198.51.100.0/24","action":"blackhole","ttl":"30m"}'
expect_post 201 '{"prefix":"198.51.100.0/24","action":"flowspec_drop","match":{"protocols":["udp"]},"ttl":"30m"}'
wait_for "RTBH before SIGKILL" blackholed
wait_for "FlowSpec drop before SIGKILL" fs_dropping

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

echo "waiting for the edge to drop the RTBH route and the FlowSpec rule after session loss (hold ${hold}s)"
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
	elif [[ "$nbr" == *"BGP state ="* ]] && native 2>/dev/null && fs_none; then
		cleared=1
		break
	fi
	sleep 1
done
if [ "$cleared" -ne 1 ]; then
	echo "RTBH or FlowSpec still on the edge after SIGKILL past the ${hold}s hold timer" >&2
	dump_bgp
	exit 1
fi
echo "session lost and native path back $(($(date +%s) - start))s after SIGKILL (hold ${hold}s)"
rm -f "$lab_body"

echo "mitigation e2e ok"
