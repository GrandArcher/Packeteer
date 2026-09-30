#!/bin/bash
# Traffic anomaly detection (#33) against the threat mitigation lab's
# simulated edge and two simulated eBGP transits. Documentation prefixes
# and documentation/private ASNs only; the traffic is synthetic NetFlow v5
# (lab/sendflow) sent from the host to Packeteer's flow source.
#
# transit-a originates 198.51.100.0/24; the edge learns it, exports it to
# transit-b, and sends it to Packeteer. The only anomaly rule turns a udp
# flood toward 198.51.100.0/24 or 203.0.113.0/24 into a FlowSpec drop.
# Checked on the routers themselves:
#  - sensitivity: steady traffic and a 1.6x rise raise nothing;
#  - a tcp flood on the learned prefix is detected but has no rule:
#    nothing is announced;
#  - a udp flood toward 203.0.113.0/24, which has a rule but is not in the
#    learned RIB, is detected and never announced;
#  - a udp flood on 198.51.100.0/24 becomes a FlowSpec drop (udp, the
#    marker, no-export) on the edge, never reaches transit-b, and leaves
#    the unicast path alone; it is withdrawn when the flood stops, and
#    comes back for a second flood;
#  - RIB session loss withdraws it; it comes back with the session while
#    the flood lasts;
#  - SIGTERM withdraws it; a restart holds no rule and no anomaly (a flood
#    in progress is learned, not acted on) until a flood past max_mbps;
#  - SIGKILL drops it with the session within the hold timer.
set -euo pipefail

root=$(cd "$(dirname "$0")/.." && pwd)
cd "$root"
compose=(docker compose -f lab/docker-compose-anomaly.yml)

check_bin=$(mktemp)
flow_bin=$(mktemp)
rates=$(mktemp)
lab_body=$(mktemp)
flow_pid=
trap 'rc=$?; if [ -n "$flow_pid" ]; then kill "$flow_pid" 2>/dev/null || true; fi; if [ "$rc" -ne 0 ]; then echo "---- lab logs ----"; "${compose[@]}" logs --no-color || true; "${compose[@]}" ps || true; fi; "${compose[@]}" down -v --remove-orphans || true; rm -f "$check_bin" "$flow_bin" "$rates" "$rates.tmp" "$lab_body"; exit "$rc"' EXIT

echo "building path check and flow sender"
go build -o "$check_bin" ./lab/checkpath
go build -o "$flow_bin" ./lab/sendflow

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

# fs_drop: one drop rule toward 198.51.100.0/24 for udp on the edge and
# nothing on transit-b (no-export).
fs_drop() {
	local e b
	e=$(fs_text edge)
	b=$(fs_text transit-b)
	[ "$(grep -c '198\.51\.100\.0/24' <<<"$e" || true)" = 1 ] && grep -Eiq 'rate 0\.0|discard' <<<"$e" &&
		grep -Eiq 'protocol[^0-9]*17|udp' <<<"$e" && ! grep -q '198\.51\.100' <<<"$b"
}

# fs_none: no FlowSpec rule from Packeteer on the edge; fs_any: some.
fs_none() {
	local e
	e=$(fs_text edge)
	! grep -Eq '198\.51\.100\.|203\.0\.113\.' <<<"$e"
}

fs_any() { ! fs_none; }

# fs_unlearned: a FlowSpec rule toward 203.0.113.0/24 on the edge.
fs_unlearned() { grep -q '203\.0\.113' <<<"$(fs_text edge)"; }

api() { curl -sS -u lab:lab-only "$base/$1" 2>/dev/null || true; }
anomalies() { api anomalies; }
api_up() { curl -sf -o /dev/null -u lab:lab-only "$base/anomalies"; }

packeteer_logs() { "${compose[@]}" logs --no-color packeteer; }

dump() {
	for r in edge transit-a transit-b; do
		echo "---- $r ----" >&2
		"${compose[@]}" exec -T "$r" vtysh -c 'show bgp summary' >&2 || true
		echo "---- $r flowspec ----" >&2
		fs_text "$r" >&2
	done
	echo "---- anomalies ----" >&2
	anomalies >&2
	echo "---- mitigations ----" >&2
	api mitigations >&2
	echo "---- rates ----" >&2
	cat "$rates" >&2 || true
	packeteer_logs >&2 || true
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

# set_rates LINE...: "destination protocol mbps" per line, swapped in
# atomically; lab/sendflow re-reads the file before every export.
set_rates() {
	printf '%s\n' "$@" >"$rates.tmp"
	mv "$rates.tmp" "$rates"
}

steady=("198.51.100.10 udp 1" "198.51.100.10 tcp 4" "203.0.113.10 udp 1")

has() { grep -q "$1" <<<"$(anomalies)"; }
no_anomalies() { has '"anomalies":\[\]'; }
any_anomaly() { has '"anomalies":\[{'; }
baselines() { has '"baselines":3'; }
no_rules() { grep -q '"rules":\[\]' <<<"$(api mitigations)"; }

echo "waiting for the native path, the Packeteer session, and the ops API"
wait_for "native path" native
wait_for "packeteer session" session_up
wait_for "ops API" api_up

echo "steady synthetic traffic"
set_rates "${steady[@]}"
"$flow_bin" -to 192.0.2.10:2055 -rates "$rates" -every 200ms &
flow_pid=$!
wait_for "three baselines" baselines
# warmup 5 rounds of 2s, then steady traffic must stay quiet.
never 16 "steady traffic raised an anomaly" any_anomaly

echo "sensitivity: a 1.6x tcp rise (4 -> 6.4 Mbit/s) raises nothing"
set_rates "198.51.100.10 udp 1" "198.51.100.10 tcp 6.4" "203.0.113.10 udp 1"
never 12 "a 1.6x rise raised an anomaly" any_anomaly
set_rates "${steady[@]}"

echo "tcp flood (60 Mbit/s): detected, no rule, nothing announced"
set_rates "198.51.100.10 udp 1" "198.51.100.10 tcp 60" "203.0.113.10 udp 1"
wait_for "the tcp anomaly" has '"prefix":"198.51.100.0/24","protocol":"tcp"'
need_log 'anomaly detected.*prefix=198.51.100.0/24 protocol=tcp' "no detection log"
need_log 'anomaly: no rule matches; alert only.*protocol=tcp' "tcp flood was not alert-only"
never 8 "a flood with no rule was announced" fs_any
wait_for "no mitigation rule for the tcp flood" no_rules
set_rates "${steady[@]}"
wait_for "the tcp anomaly to clear" no_anomalies

echo "udp flood toward 203.0.113.0/24 (a rule, but not learned): never announced"
set_rates "198.51.100.10 udp 1" "198.51.100.10 tcp 4" "203.0.113.10 udp 60"
wait_for "the 203.0.113.0/24 anomaly" has '"prefix":"203.0.113.0/24","protocol":"udp"'
wait_for "held: not in the learned RIB" log_has 'anomaly mitigation held back.*prefix=203.0.113.0/24.*not an exact prefix in the learned RIB'
never 8 "a prefix that is not in the learned RIB was announced" fs_unlearned
no_rules || { echo "a mitigation rule was added for an unlearned prefix" >&2; dump; exit 1; }
set_rates "${steady[@]}"
wait_for "the 203.0.113.0/24 anomaly to clear" no_anomalies

echo "udp flood on $prefix: FlowSpec drop on the edge"
set_rates "198.51.100.10 udp 60" "198.51.100.10 tcp 4" "203.0.113.10 udp 1"
wait_for "the udp drop on the edge and nothing on transit-b" fs_drop
need_log 'anomaly mitigation added.*prefix=198.51.100.0/24.*rule=udp-flood.*action=flowspec_drop' "no mitigation log"
need_log 'msg="mitigation flowspec announced"' "no FlowSpec announce log"
grep -q 'rule udp-flood' <<<"$(api mitigations)" || { echo "the mitigation rule does not name the anomaly rule" >&2; dump; exit 1; }
native || { echo "FlowSpec changed the unicast path" >&2; dump; exit 1; }

echo "flood ends: the anomaly clears and the drop is withdrawn"
set_rates "${steady[@]}"
wait_for "drop withdrawn" fs_none
need_log 'anomaly cleared.*mitigation rule [0-9a-f]+ removed' "no clear log"
wait_for "no mitigation rule" no_rules

echo "second udp flood: mitigated again"
set_rates "198.51.100.10 udp 60" "198.51.100.10 tcp 4" "203.0.113.10 udp 1"
wait_for "the drop again" fs_drop

echo "RIB session loss withdraws the drop"
"${compose[@]}" exec -T edge vtysh -c 'configure terminal' -c 'router bgp 64512' -c 'neighbor 192.0.2.10 shutdown'
wait_for "packeteer to see the RIB go away" log_has 'rib not ready; withdrawing mitigation routes'
wait_for "no drop while the session is down" fs_none
"${compose[@]}" exec -T edge vtysh -c 'configure terminal' -c 'router bgp 64512' -c 'no neighbor 192.0.2.10 shutdown'
wait_for "session back" session_up
wait_for "the drop back with the session while the flood lasts" fs_drop

echo "SIGTERM withdraws the drop"
withdrawn_before=$(log_count 'mitigation routes withdrawn')
"${compose[@]}" stop -t 20 packeteer
wait_for "no drop after SIGTERM" fs_none
if [ "$(log_count 'mitigation routes withdrawn')" -le "$withdrawn_before" ]; then
	echo "SIGTERM did not withdraw the drop while the session was up" >&2
	dump
	exit 1
fi

echo "restart: no rule and no anomaly; the flood in progress is learned"
"${compose[@]}" start packeteer
wait_for "ops API after restart" api_up
wait_for "packeteer session after restart" session_up
no_rules || { echo "a mitigation rule survived a restart" >&2; dump; exit 1; }
no_anomalies || { echo "an anomaly survived a restart" >&2; dump; exit 1; }
never 16 "a drop came back after a restart" fs_any

echo "a flood past max_mbps (150 Mbit/s) is mitigated whatever the baseline"
set_rates "198.51.100.10 udp 150" "198.51.100.10 tcp 4" "203.0.113.10 udp 1"
wait_for "the drop for a flood past max_mbps" fs_drop

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

echo "waiting for the edge to drop the FlowSpec rule after session loss (hold ${hold}s)"
deadline=$((start + hold + 10))
cleared=0
while [ "$(date +%s)" -le "$deadline" ]; do
	nbr=$(session_text)
	if [[ "$nbr" == *"BGP state = Established"* ]]; then
		if ! fs_drop 2>/dev/null; then
			echo "the drop cleared while the session to the dead process is still Established" >&2
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
	echo "FlowSpec drop still on the edge after SIGKILL past the ${hold}s hold timer" >&2
	dump
	exit 1
fi
echo "session lost and drop gone $(($(date +%s) - start))s after SIGKILL (hold ${hold}s)"

echo "anomaly e2e ok"
