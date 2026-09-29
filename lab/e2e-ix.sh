#!/bin/bash
# Internet exchange peers as providers, AS-path behavior, and online
# reconfiguration (#27, second half) against simulated FRR routers: one
# edge with transit-a on the lab LAN and three exchange members on a
# simulated peering LAN (203.0.113.0/24), plus a second iBGP router that
# joins only through a reload. Documentation prefixes and
# documentation/private ASNs only.
#
# transit-a is native for 198.51.100.0/24. ix-peer-a and ix-peer-c send it
# prepended (inactive paths); ix-peer-b sends only 198.51.100.128/25. The
# edge sends Packeteer every path (add-path). Packeteer's exchange lists
# ix-peer-a and ix-peer-b; ix-peer-b is the fastest probed path.
#
#  1. The steer goes to ix-peer-a, not the faster ix-peer-b (no route for
#     the /24), with next hop 203.0.113.11 and ix-peer-a's AS path
#     (bgp.as_path: provider). /api/exchanges counts each peer's prefixes
#     and the improvement, and lists ix-peer-c as discovered.
#  2. ix-peer-a withdraws: the route check retires the improvement at once
#     (hold_time is 5m), and nothing goes to ix-peer-b or ix-peer-c. It
#     re-announces and the steer comes back.
#  3. SIGHUP with the collector added to bgp.neighbors: it gets the steer,
#     and the edge's session is not reset and never loses the route.
#  4. SIGHUP with a restart-only change (local_pref) is refused; nothing
#     moves.
#  5. SIGHUP with the collector removed: its session closes and the route
#     leaves it; the edge is untouched.
#  6. SIGTERM withdraws.
#  7. Restart, steer, SIGKILL: the route drops with the session (no
#     graceful restart).
set -euo pipefail

root=$(cd "$(dirname "$0")/.." && pwd)
cd "$root"
compose=(docker compose -f lab/docker-compose-ix.yml)

lab_dir=$(mktemp -d)
check_bin=$(mktemp)
trap 'rc=$?; if [ "$rc" -ne 0 ]; then echo "---- lab logs ----"; "${compose[@]}" logs --no-color || true; "${compose[@]}" ps || true; fi; "${compose[@]}" down -v --remove-orphans || true; rm -f "$check_bin"; rm -rf "$lab_dir"; exit "$rc"' EXIT

echo "building path check"
go build -o "$check_bin" ./lab/checkpath

cp lab/probes/ix-equal.yaml "$lab_dir/state.yaml"
cp lab/packeteer-ix.yaml "$lab_dir/config.yaml"
chmod 0755 "$lab_dir"
chmod 0644 "$lab_dir/state.yaml" "$lab_dir/config.yaml"
export PACKETEER_LAB_DIR="$lab_dir"

# Config variants for the reloads. with_collector adds the second iBGP
# router; refused also changes local_pref, which needs a restart.
# bgp.neighbors is not the last block of the file: insert after the edge.
with_collector=$(awk '
	{ print }
	/^      add_path: true$/ && !done { print "    - address: 192.0.2.253"; print "      description: collector"; done = 1 }
' lab/packeteer-ix.yaml)
refused=$(sed 's/^local_pref: 250$/local_pref: 300/' <<<"$with_collector")
if [ "$with_collector" = "$(cat lab/packeteer-ix.yaml)" ] || [ "$refused" = "$with_collector" ]; then
	echo "could not build the reload configs" >&2
	exit 1
fi

echo "building lab"
"${compose[@]}" build
"${compose[@]}" up -d

prefix=198.51.100.0/24
provider_path="64501 64501 64501"

router_json() {
	"${compose[@]}" exec -T "$1" vtysh -c "show bgp ipv4 unicast $prefix json" 2>/dev/null || true
}

# steered <router>: the router's best path is Packeteer's route via
# ix-peer-a, with ix-peer-a's AS path.
steered() {
	router_json "$1" | "$check_bin" -has 64512:666 -nexthop 203.0.113.11 -aspath "$provider_path"
}

# native: the edge's best path is transit-a's, and nothing of Packeteer's.
native() {
	router_json edge | "$check_bin" -aspath 64496 -lacks 64512:666
}

no_packeteer_path() {
	! grep -q '64512:666' <<<"$(router_json "$1")"
}

api() {
	"${compose[@]}" exec -T packeteer wget -qO- "http://127.0.0.1:8080$1" 2>/dev/null || true
}

# established_count: how many times the edge's session to Packeteer has
# come up. A reload must not reset it.
established_count() {
	"${compose[@]}" exec -T edge vtysh -c 'show bgp neighbors 192.0.2.10 json' 2>/dev/null |
		jq -r '.["192.0.2.10"].connectionsEstablished // empty'
}

dump_bgp() {
	for r in edge collector transit-a ix-peer-a ix-peer-b ix-peer-c; do
		echo "---- $r ----" >&2
		"${compose[@]}" exec -T "$r" vtysh -c 'show bgp summary' >&2 || true
		"${compose[@]}" exec -T "$r" vtysh -c "show bgp ipv4 unicast $prefix" >&2 || true
	done
	echo "---- packeteer exchanges / providers / decisions ----" >&2
	api /api/exchanges >&2
	echo >&2
	api /api/providers >&2
	echo >&2
	api /api/decisions >&2
	echo >&2
	"${compose[@]}" logs --no-color packeteer >&2 || true
}

wait_for() {
	local what=$1 tries=$2
	shift 2
	local i
	for i in $(seq 1 "$tries"); do
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

fail() {
	echo "$1" >&2
	dump_bgp
	exit 1
}

packeteer_logs() { "${compose[@]}" logs --no-color packeteer; }

# The logs are read into a variable first: with pipefail, grep -q exiting
# on the first match would SIGPIPE docker compose logs and fail the check.
log_count() {
	local logs
	logs=$(packeteer_logs)
	grep -cF -- "$1" <<<"$logs" || true
}

log_has() {
	local logs
	logs=$(packeteer_logs)
	grep -qE -- "$1" <<<"$logs"
}

# never_injected <provider>: no route was ever announced toward it.
never_injected() {
	if log_has "msg=injected .*provider=$1 "; then
		fail "Packeteer announced a route toward $1"
	fi
}

# exchange_stats: /api/exchanges shows ix-peer-a's path and improvement,
# ix-peer-b's /25, and ix-peer-c as discovered.
exchange_stats() {
	api /api/exchanges | jq -e '
		.exchanges[0] as $x
		| $x.name == "ix-lab"
		and ([$x.peers[] | select(.name == "ix-peer-a" and .prefixes >= 1 and .improvements == 1 and .asn == 64501)] | length == 1)
		and ([$x.peers[] | select(.name == "ix-peer-b" and .prefixes == 1 and .improvements == 0)] | length == 1)
		and ([$x.discovered[] | select(.next_hop == "203.0.113.13" and .asn == 64503 and .prefixes == 1)] | length == 1)
	' >/dev/null
}

# flip_probes <file>: atomically replace the fixed prober's state.
flip_probes() {
	local tmp
	tmp=$(mktemp "$lab_dir/.state.XXXXXX")
	cp "$1" "$tmp"
	chmod 0644 "$tmp"
	mv "$tmp" "$lab_dir/state.yaml"
}

ix_peer_a() {
	"${compose[@]}" exec -T ix-peer-a vtysh -c 'configure terminal' -c 'router bgp 64501' \
		-c 'address-family ipv4 unicast' -c "$1"
}

hup() {
	local cid
	cid=$("${compose[@]}" ps -q packeteer)
	[ -n "$cid" ] || fail "packeteer is not running"
	docker kill -s HUP "$cid" >/dev/null
}

# still_steered <seconds>: the edge keeps the route the whole time.
still_steered() {
	local i
	for i in $(seq 1 "$1"); do
		steered edge || fail "the edge lost Packeteer's route during a reload"
		sleep 1
	done
}

echo "1. exchange peers: the steer goes to ix-peer-a with its AS path"
wait_for "add-path negotiated" 45 log_has 'bgp add-path negotiated'
# The probes start equal so the native check cannot race the steer.
wait_for "edge on transit-a before the steer" 30 native
flip_probes lab/probes/ix.yaml
wait_for "edge best is Packeteer's route via ix-peer-a" 90 steered edge
never_injected ix-peer-b
wait_for "exchange statistics" 15 exchange_stats
if ! api /metrics | grep -qF 'packeteer_exchange_peer_improvements{exchange="ix-lab",peer="ix-peer-a"} 1'; then
	fail "exchange metrics missing"
fi
if ! api /api/decisions | jq -e '[.decisions[].candidates[] | select(.provider == "ix-peer-b" and .usable == false and ((.why // "") | test("route check")))] | length >= 1' >/dev/null; then
	fail "ix-peer-b was not refused by the route check"
fi

echo "2. ix-peer-a withdraws: the route check retires at once"
retired_before=$(log_count 'no route via provider (route check)')
start=$(date +%s)
ix_peer_a "no network $prefix"
wait_for "edge back on transit-a" 15 native
echo "withdrawn $(($(date +%s) - start))s after ix-peer-a's withdraw (hold_time 5m)"
if [ "$(log_count 'no route via provider (route check)')" -le "$retired_before" ]; then
	fail "retire was not logged from the route check"
fi
for _ in $(seq 1 5); do
	no_packeteer_path edge || fail "Packeteer injected while no configured peer had a route"
	sleep 2
done
never_injected ix-peer-b
ix_peer_a "network $prefix"
wait_for "steer again" 45 steered edge

echo "3. SIGHUP adds the collector: online, the edge untouched"
est=$(established_count)
[ -n "$est" ] || fail "could not read the edge's session count"
printf '%s\n' "$with_collector" >"$lab_dir/config.yaml"
hup
wait_for "config reloaded" 15 log_has 'msg="config reloaded".*neighbors_added=192.0.2.253'
wait_for "collector gets the steer" 30 steered collector
still_steered 4
[ "$(established_count)" = "$est" ] || fail "the edge's session was reset by the reload"

echo "4. SIGHUP with a restart-only change is refused"
printf '%s\n' "$refused" >"$lab_dir/config.yaml"
hup
wait_for "reload refused" 15 log_has 'config reload refused.*changed local_pref'
still_steered 3
steered collector || fail "the collector lost the route on a refused reload"

echo "5. SIGHUP removes the collector"
cp lab/packeteer-ix.yaml "$lab_dir/config.yaml"
hup
wait_for "config reloaded" 15 log_has 'msg="config reloaded".*neighbors_removed=192.0.2.253'
wait_for "route gone from the collector" 15 no_packeteer_path collector
still_steered 3
[ "$(established_count)" = "$est" ] || fail "the edge's session was reset by the reload"

echo "6. SIGTERM withdraws"
"${compose[@]}" stop -t 20 packeteer
wait_for "route gone after SIGTERM" 15 no_packeteer_path edge
wait_for "edge on transit-a" 5 native

echo "7. restart, steer again, SIGKILL: the route drops with the session"
"${compose[@]}" start packeteer
wait_for "steer after restart" 60 steered edge
hold=$(awk '$1 == "neighbor" && $2 == "192.0.2.10" && $3 == "timers" { print $5 }' lab/frr-ix-edge/frr.conf)
case "$hold" in
'' | *[!0-9]*)
	echo "lab hold timer is not an integer: '${hold}'" >&2
	exit 1
	;;
esac
cid=$("${compose[@]}" ps -q packeteer)
[ -n "$cid" ] || fail "packeteer is not running"
start=$(date +%s)
docker kill -s KILL "$cid"
code=
for _ in $(seq 1 25); do
	code=$(docker inspect -f '{{.State.ExitCode}}' "$cid" 2>/dev/null || true)
	if [ "$(docker inspect -f '{{.State.Status}}' "$cid" 2>/dev/null || true)" = "exited" ]; then
		break
	fi
	sleep 0.2
done
[ "$code" = "137" ] || fail "expected SIGKILL exit 137, got ${code:-unknown}"
wait_for "route gone after SIGKILL" $(((hold + 6) / 2)) no_packeteer_path edge
wait_for "edge on transit-a after SIGKILL" 5 native
echo "route gone $(($(date +%s) - start))s after SIGKILL (hold ${hold}s)"

echo "IX e2e ok"
