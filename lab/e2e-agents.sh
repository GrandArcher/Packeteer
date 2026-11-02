#!/bin/bash
# Distributed probe agents (#230, #478): the controller in observe mode and
# two packeteer-agent containers at two sites over mutual TLS, certificates
# and revocation lists generated for this run. agent-a (site dc-a) measures
# transit-a through a 40ms netem delay, agent-b (site dc-b) measures
# transit-b; both probe 198.51.100.1, which one FRR edge learns as
# 198.51.100.0/24 with transit-a as the native exit. Documentation prefixes
# and a private ASN only. Nothing is announced: on every check the edge
# holds only its own path for the prefix. Checked in order:
#  1. probes are split across both agents and attributed: transit-a's row
#     names site dc-a and agent-a with the delayed RTT, transit-b's names
#     dc-b and agent-b with the fast one, and the controller recommends
#     transit-b;
#  2. SIGKILL agent-b: transit-b fails closed ("no usable probe agent"), its
#     data is no longer fresh, decisions mark it unusable and the
#     recommendation goes away, while agent-a keeps measuring; starting
#     agent-b brings it all back;
#  3. the CA revokes agent-b's certificate (CRL swapped on the running
#     controller): the controller refuses it on its open connection, the
#     provider fails closed again, and a restarted agent-b is refused too;
#     agent-a is not affected.
set -euo pipefail
export LC_ALL=C

root=$(cd "$(dirname "$0")/.." && pwd)
cd "$root"
compose=(docker compose -f lab/docker-compose-agents.yml)

lab_dir=$(mktemp -d)
certs_bin=$(mktemp)
trap 'rc=$?; if [ "$rc" -ne 0 ]; then echo "---- lab logs ----"; "${compose[@]}" logs --no-color || true; "${compose[@]}" ps || true; fi; "${compose[@]}" down -v --remove-orphans || true; rm -f "$certs_bin"; rm -rf "$lab_dir"; exit "$rc"' EXIT

echo "building lab certificates"
go build -o "$certs_bin" ./lab/mkcerts
certs="$lab_dir/certs"
mkdir -p "$certs"
"$certs_bin" -revoke agent-b "$certs" controller agent-a agent-b
cp "$certs/empty.crl" "$certs/agents.crl"
chmod 755 "$lab_dir" "$certs"
export PACKETEER_LAB_DIR="$lab_dir"

echo "building lab"
"${compose[@]}" build
"${compose[@]}" up -d

prefix=198.51.100.0/24

api() {
	"${compose[@]}" exec -T packeteer wget -qO- "http://127.0.0.1:8080$1" 2>/dev/null || true
}

logs() {
	"${compose[@]}" logs --no-color "$1" 2>&1 || true
}

fail() {
	echo "FAIL: $*" >&2
	echo "---- providers ----" >&2
	api /api/providers >&2
	echo "---- decisions ----" >&2
	api /api/decisions >&2
	echo "---- improvements ----" >&2
	api /api/improvements >&2
	echo "---- edge ----" >&2
	"${compose[@]}" exec -T edge vtysh -c 'show bgp summary' -c "show bgp ipv4 unicast $prefix" >&2 || true
	exit 1
}

# wait_for desc seconds cmd...: poll until cmd succeeds.
wait_for() {
	local desc=$1 secs=$2 i
	shift 2
	for i in $(seq 1 "$secs"); do
		if "$@"; then
			return 0
		fi
		sleep 1
	done
	fail "timed out waiting for: $desc"
}

# holds desc seconds cmd...: cmd must succeed on every second.
holds() {
	local desc=$1 secs=$2 i
	shift 2
	for i in $(seq 1 "$secs"); do
		"$@" || fail "$desc stopped holding"
		sleep 1
	done
}

# Observe mode announces nothing: the edge holds its own path only.
edge_native_only() {
	"${compose[@]}" exec -T edge vtysh -c "show bgp ipv4 unicast $prefix json" 2>/dev/null |
		jq -e '(.paths | length) == 1 and (.paths[0].peer.peerId // "") != "192.0.2.10"' >/dev/null
}

probe_row() {
	api /api/prefixes | jq -c --arg p "$prefix" --arg n "$1" \
		'[.prefixes[] | select(.prefix == $p) | .probes[] | select(.provider == $n)][0] // empty'
}

provider_up() {
	api /api/providers | jq -e --arg n "$1" '[.providers[] | select(.name == $n and .up)] | length == 1' >/dev/null
}

provider_down() {
	api /api/providers | jq -e --arg n "$1" --arg r "$2" \
		'[.providers[] | select(.name == $n and (.up | not) and (.reason | contains($r)))] | length == 1' >/dev/null
}

# attributed provider site agent min max: a good measurement taken by that
# agent at that site, with an average RTT in [min, max) ms.
attributed() {
	probe_row "$1" | jq -e --arg s "$2" --arg a "$3" --argjson lo "$4" --argjson hi "$5" \
		'.site == $s and .agent == $a and .ok and .received > 0 and .rtt_avg_ms >= $lo and .rtt_avg_ms < $hi' >/dev/null
}

recommends() {
	api /api/improvements | jq -e --arg p "$prefix" --arg n "$1" \
		'[.improvements[] | select(.prefix == $p and .provider == $n)] | length == 1' >/dev/null
}

recommends_nothing() {
	api /api/improvements | jq -e '(.improvements | length) == 0' >/dev/null
}

# No decision counts the provider as usable.
unusable() {
	api /api/decisions | jq -e --arg p "$prefix" --arg n "$1" \
		'[.decisions[] | select(.prefix == $p) | .candidates[] | select(.provider == $n and .usable)] | length == 0' >/dev/null
}

revoked_refusals() {
	logs packeteer | grep -c 'probe agent refused: certificate revoked' || true
}

refusals_over() {
	[ "$(revoked_refusals)" -gt "$1" ]
}

# The agent logs once per process when the controller refuses it.
agent_b_failures() {
	logs agent-b | grep -c 'controller answered 403: certificate revoked' || true
}

agent_b_failures_over() {
	[ "$(agent_b_failures)" -gt "$1" ]
}

# measured_after provider time: a good measurement newer than time.
measured_after() {
	probe_row "$1" | jq -e --arg t "$2" '.ok and .time > $t' >/dev/null
}

echo "1. probes are split across both agents and attributed to their sites"
wait_for "transit-a measured by agent-a at dc-a" 150 attributed transit-a dc-a agent-a 30 200
wait_for "transit-b measured by agent-b at dc-b" 60 attributed transit-b dc-b agent-b 0 20
api /api/providers | jq -e '
	([.providers[] | select(.name == "transit-a" and .site == "dc-a" and .up)] | length == 1) and
	([.providers[] | select(.name == "transit-b" and .site == "dc-b" and .up)] | length == 1)' >/dev/null ||
	fail "providers do not name their sites"
logs packeteer | grep -q 'probe agent online.*agent=agent-a.*site=dc-a' || fail "controller never saw agent-a at dc-a"
logs packeteer | grep -q 'probe agent online.*agent=agent-b.*site=dc-b' || fail "controller never saw agent-b at dc-b"
wait_for "transit-b recommended (transit-a is 40ms slower)" 60 recommends transit-b
holds "observe mode: the edge keeps only its native path" 5 edge_native_only

echo "2. a killed agent's data goes stale and decisions stop using it"
"${compose[@]}" kill -s KILL agent-b
wait_for "transit-b failed closed" 30 provider_down transit-b "no usable probe agent"
wait_for "transit-b unusable in decisions" 30 unusable transit-b
wait_for "no recommendation without transit-b" 30 recommends_nothing
b_time=$(probe_row transit-b | jq -r '.time // ""')
a_time=$(probe_row transit-a | jq -r '.time')
sleep 6
if [ -n "$b_time" ] && measured_after transit-b "$b_time"; then
	fail "transit-b got a new good measurement with its agent dead"
fi
measured_after transit-a "$a_time" || fail "transit-a stopped being measured when agent-b died"
provider_up transit-a || fail "agent-b's death took transit-a down"
unusable transit-b || fail "transit-b is usable in decisions again"
recommends_nothing || fail "a recommendation came back without transit-b"
edge_native_only || fail "something was announced"
"${compose[@]}" start agent-b
wait_for "transit-b measured by agent-b again" 60 attributed transit-b dc-b agent-b 0 20
wait_for "transit-b recommended again" 60 recommends transit-b
edge_native_only || fail "something was announced"

echo "3. an agent with a revoked certificate is rejected"
revoked_before=$(revoked_refusals)
mv "$certs/revoked.crl" "$certs/agents.crl"
wait_for "controller refuses agent-b's certificate" 30 refusals_over "$revoked_before"
wait_for "transit-b failed closed after the revocation" 30 provider_down transit-b "no usable probe agent"
wait_for "no recommendation without transit-b" 30 recommends_nothing
wait_for "revoked agent-b logs that the controller refuses it" 30 agent_b_failures_over 0
failures_before=$(agent_b_failures)
"${compose[@]}" restart agent-b
wait_for "restarted agent-b is refused too" 30 agent_b_failures_over "$failures_before"
holds "agent-b stays refused and transit-b stays closed" 10 provider_down transit-b "no usable probe agent"
provider_up transit-a || fail "the revocation took transit-a down"
attributed transit-a dc-a agent-a 30 200 || fail "agent-a stopped being measured"
recommends_nothing || fail "a recommendation came back for a revoked agent"
edge_native_only || fail "something was announced"

echo "agents e2e ok"
