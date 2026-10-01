#!/bin/bash
# Router interop matrix (#53): one scenario per (router, feature) cell, run
# against a simulated edge of that router type. Lab only: documentation
# prefixes and documentation/private ASNs, simulated routers in Docker.
#
#	bash lab/e2e-interop.sh frr|bird2|bird3|gobgp ibgp|addpath|bmp
#
# The edge (192.0.2.254, AS 64512) learns 198.51.100.0/24 from two FRR
# eBGP transits; transit-b prepends, so transit-a is native. transit-b is
# the faster probed path. Packeteer allowlists and probes 203.0.113.0/24 and
# 198.51.100.128/25 too, which no router ever advertises: on every sample
# of every wait the edge must hold no Packeteer route for either.
#
# ibgp     best-path iBGP session (lab/interop/packeteer.yaml):
#          1. the edge's best is Packeteer's route: next hop 192.0.2.22,
#             local-pref 250, 64512:666, no-export; no transit is sent it.
#          2. it stays while the edge no longer sends the native path.
#          3. flip-back withdraws it; restoring the probes injects it again.
#          4. SIGTERM withdraws it.
#          5. a frozen process (docker pause, TCP stays open) loses the route
#             when the edge's 9s hold timer expires, not before 3s.
#          6. SIGKILL: the route drops with the session (no graceful restart).
# addpath  add-path receive (lab/interop/packeteer-addpath.yaml): add-path
#          is negotiated and transit-b's inactive path arrives with a path
#          ID; transit-b withdraws and the route check retires the
#          improvement inside the 5m hold_time; it re-announces and the
#          steer returns; SIGTERM withdraws; restart and SIGKILL.
# bmp      BMP post-policy (lab/interop/packeteer-bmp.yaml): transit-b's
#          path is seen only over BMP; the same withdraw/re-announce and
#          SIGTERM checks; then a restarted station must be refed (FRR,
#          GoBGP) and SIGKILL drops the route. BIRD 3 does not refeed
#          sessions that were already up when the station reconnects, so
#          that step is skipped there (docs/routers.md).
set -euo pipefail

router=${1:-}
feature=${2:-}
case "$router" in
frr) format=frr ;;
bird2 | bird3) format=bird ;;
gobgp) format=gobgp ;;
*)
	echo "usage: $0 frr|bird2|bird3|gobgp ibgp|addpath|bmp" >&2
	exit 2
	;;
esac
case "$feature" in
ibgp) config=packeteer.yaml ;;
addpath) config=packeteer-addpath.yaml ;;
bmp) config=packeteer-bmp.yaml ;;
*)
	echo "usage: $0 frr|bird2|bird3|gobgp ibgp|addpath|bmp" >&2
	exit 2
	;;
esac
if [ "$router$feature" = bird2bmp ]; then
	echo "BIRD 2 packages are built without the BMP protocol; use bird3" >&2
	exit 2
fi

root=$(cd "$(dirname "$0")/.." && pwd)
cd "$root"
edge=edge-$router
compose=(docker compose -f lab/interop/docker-compose.yml --profile "$router")

lab_dir=$(mktemp -d)
check_bin=$(mktemp)
trap 'rc=$?; if [ "$rc" -ne 0 ]; then echo "---- lab logs ----"; dump_bgp || true; "${compose[@]}" logs --no-color || true; "${compose[@]}" ps -a || true; fi; "${compose[@]}" down -v --remove-orphans || true; rm -f "$check_bin"; rm -rf "$lab_dir"; exit "$rc"' EXIT

echo "interop: $router / $feature"
echo "building route check"
go build -o "$check_bin" ./lab/interopcheck

mkdir -p "$lab_dir/probes"
cp lab/probes/prefer-b.yaml "$lab_dir/probes/state.yaml"
chmod 0755 "$lab_dir/probes"
chmod 0644 "$lab_dir/probes/state.yaml"
export PACKETEER_LAB_DIR="$lab_dir/probes"
export INTEROP_PACKETEER_CONFIG="./$config"
export INTEROP_BIRD_CONF=bird.conf
if [ "$feature" = bmp ]; then
	INTEROP_BIRD_CONF=bird-bmp.conf
fi
if [ "$router" = gobgp ]; then
	# The edge runs the GoBGP release Packeteer itself links (go.mod).
	ver=$(go list -m -f '{{.Version}}' github.com/osrg/gobgp/v3)
	echo "building gobgpd $ver"
	mkdir -p "$lab_dir/gobgp"
	GOBIN="$lab_dir/gobgp" CGO_ENABLED=0 go install "github.com/osrg/gobgp/v3/cmd/gobgpd@$ver" "github.com/osrg/gobgp/v3/cmd/gobgp@$ver"
	cp lab/interop/gobgp/gobgpd.toml "$lab_dir/gobgp/gobgpd.toml"
	if [ "$feature" = bmp ]; then
		cat lab/interop/gobgp/bmp.toml >>"$lab_dir/gobgp/gobgpd.toml"
	fi
	chmod -R a+rX "$lab_dir/gobgp"
	export INTEROP_GOBGP_DIR="$lab_dir/gobgp"
fi

prefix=198.51.100.0/24
# Allowlisted and probed, never in any router's table.
unlearned=(203.0.113.0/24 198.51.100.128/25)

edge_show() {
	case "$router" in
	frr) "${compose[@]}" exec -T "$edge" vtysh -c "show bgp ipv4 unicast $1 json" ;;
	bird*) "${compose[@]}" exec -T "$edge" birdc -s /run/bird/bird.ctl show route all "$1" ;;
	gobgp) "${compose[@]}" exec -T "$edge" /opt/gobgp/gobgp global rib -a ipv4 "$1" -j ;;
	esac
}

# edge_is <prefix> <want> [next hop]
edge_is() {
	local out
	out=$(edge_show "$1" 2>&1) || true
	if [ "$2" = injected ]; then
		"$check_bin" -format "$format" -prefix "$1" -want injected -nexthop "$3" <<<"$out"
	else
		"$check_bin" -format "$format" -prefix "$1" -want "$2" <<<"$out"
	fi
}

injected() { edge_is "$prefix" injected 192.0.2.22; }
native() { edge_is "$prefix" native; }

# transits_clean: the edge exported nothing to either transit (both keep
# what they receive: soft-reconfiguration inbound).
transits_clean() {
	local t out
	for t in transit-a transit-b; do
		out=$("${compose[@]}" exec -T "$t" vtysh -c 'show bgp ipv4 unicast neighbors 192.0.2.254 received-routes json' 2>&1) || return 1
		if grep -qE '198\.51\.100\.|203\.0\.113\.' <<<"$out"; then
			echo "$t received a route from the edge: $out" >&2
			return 1
		fi
	done
}

dump_bgp() {
	echo "---- $router edge ----" >&2
	case "$router" in
	frr) "${compose[@]}" exec -T "$edge" vtysh -c 'show bgp summary' -c "show bgp ipv4 unicast $prefix" -c 'show bgp neighbors 192.0.2.10' -c 'show bmp' >&2 || true ;;
	bird*) "${compose[@]}" exec -T "$edge" birdc -s /run/bird/bird.ctl show protocols all >&2 || true
		"${compose[@]}" exec -T "$edge" birdc -s /run/bird/bird.ctl show route all >&2 || true ;;
	gobgp) "${compose[@]}" exec -T "$edge" /opt/gobgp/gobgp neighbor >&2 || true
		"${compose[@]}" exec -T "$edge" /opt/gobgp/gobgp neighbor 192.0.2.10 >&2 || true
		"${compose[@]}" exec -T "$edge" /opt/gobgp/gobgp global rib -a ipv4 >&2 || true ;;
	esac
	echo "---- packeteer looking glass / decisions ----" >&2
	glass >&2 || true
	echo >&2
	"${compose[@]}" exec -T packeteer wget -qO- http://127.0.0.1:8080/api/decisions >&2 || true
	echo >&2
}

# guard: on every sample, nothing Packeteer never learned is on the edge.
guard() {
	local p
	for p in "${unlearned[@]}"; do
		if ! edge_is "$p" absent 2>"$lab_dir/guard.err"; then
			if grep -q "Packeteer path" "$lab_dir/guard.err"; then
				echo "SAFETY: Packeteer announced $p, which no router advertised" >&2
				cat "$lab_dir/guard.err" >&2
				dump_bgp
				exit 1
			fi
		fi
	done
}

wait_for() {
	local what=$1 tries=$2
	shift 2
	local i
	for i in $(seq 1 "$tries"); do
		guard
		if "$@" 2>/dev/null; then
			return 0
		fi
		sleep 1
	done
	echo "timed out waiting for: $what" >&2
	"$@" || true
	dump_bgp
	return 1
}

# hold_for <seconds> <what> <check...>: the check holds on every sample.
hold_for() {
	local secs=$1 what=$2
	shift 2
	local end=$(($(date +%s) + secs))
	while [ "$(date +%s)" -lt "$end" ]; do
		guard
		if ! "$@"; then
			echo "did not hold for ${secs}s: $what" >&2
			dump_bgp
			exit 1
		fi
		sleep 1
	done
}

glass() {
	"${compose[@]}" exec -T packeteer wget -qO- "http://127.0.0.1:8080/api/troubleshoot/lookingglass?prefix=$prefix" 2>/dev/null || true
}

# glass_has <next hop> <source>: Packeteer's view holds a path via that hop
# from that source (ibgp or bmp); with add-path the path has an ID.
glass_has() {
	local g
	g=$(glass)
	if [ "$feature" = addpath ]; then
		grep -qE "\"next_hop\":\"$1\",[^}]*\"source\":\"$2\",\"path_id\":[1-9]" <<<"$g"
	else
		grep -qE "\"next_hop\":\"$1\",[^}]*\"source\":\"$2\"" <<<"$g"
	fi
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

route_check_retires() { [ "$(log_count 'no route via provider (route check)')" -ge "$1" ]; }

transit_b() {
	"${compose[@]}" exec -T transit-b vtysh -c 'configure terminal' -c 'router bgp 64497' \
		-c 'address-family ipv4 unicast' -c "$1"
}

hold=9
packeteer_cid() {
	local cid
	cid=$("${compose[@]}" ps -q packeteer)
	if [ -z "$cid" ]; then
		echo "packeteer is not running" >&2
		exit 1
	fi
	echo "$cid"
}

sigterm() {
	"${compose[@]}" stop -t 20 packeteer
	wait_for "route gone after SIGTERM" 15 native
	need_log 'msg="withdrew all"'
}

need_log() {
	if [ "$(log_count "$1")" -lt 1 ]; then
		echo "packeteer log is missing: $1" >&2
		exit 1
	fi
}

sigkill() {
	local cid code start
	cid=$(packeteer_cid)
	start=$(date +%s)
	docker kill -s KILL "$cid"
	code=
	for _ in $(seq 1 25); do
		if [ "$(docker inspect -f '{{.State.Status}}' "$cid" 2>/dev/null || true)" = "exited" ]; then
			code=$(docker inspect -f '{{.State.ExitCode}}' "$cid")
			break
		fi
		sleep 0.2
	done
	if [ "$code" != "137" ]; then
		echo "expected SIGKILL exit 137, got ${code:-unknown}" >&2
		exit 1
	fi
	wait_for "route gone after SIGKILL" $((hold + 6)) native
	echo "route gone $(($(date +%s) - start))s after SIGKILL (hold ${hold}s)"
}

echo "building lab"
"${compose[@]}" build
# Packeteer (and its BMP station) first: BIRD 3 only sends BMP peer up for
# sessions that come up while the station is connected.
"${compose[@]}" up -d transit-a transit-b packeteer
"${compose[@]}" up -d "$edge"
case "$router" in
bird*) "${compose[@]}" exec -T "$edge" bird --version || true ;;
gobgp) "${compose[@]}" exec -T "$edge" /opt/gobgp/gobgpd --version || true ;;
frr) "${compose[@]}" exec -T "$edge" vtysh -c 'show version' | head -2 || true ;;
esac

case "$feature" in
ibgp)
	echo "1. steer: the edge accepts Packeteer's route with its community and no-export"
	wait_for "edge best is Packeteer's route via transit-b" 90 injected
	need_log 'msg=injected'
	wait_for "nothing exported to the transits" 10 transits_clean

	echo "2. the route stays while the edge no longer sends the native path"
	hold_for 10 "Packeteer's route" injected

	echo "3. flip-back withdraws; restoring the probes injects again"
	cp lab/probes/prefer-a.yaml "$lab_dir/probes/state.yaml.new"
	mv "$lab_dir/probes/state.yaml.new" "$lab_dir/probes/state.yaml"
	wait_for "flip-back to transit-a" 45 native
	cp lab/probes/prefer-b.yaml "$lab_dir/probes/state.yaml.new"
	mv "$lab_dir/probes/state.yaml.new" "$lab_dir/probes/state.yaml"
	wait_for "steer again" 45 injected

	echo "4. SIGTERM withdraws"
	sigterm

	echo "5. frozen process: the route goes when the edge's hold timer expires"
	"${compose[@]}" start packeteer
	wait_for "steer after restart" 60 injected
	cid=$(packeteer_cid)
	start=$(date +%s)
	docker pause "$cid"
	# Keepalives stop but TCP stays open: nothing changes before the hold
	# timer, and the route is gone once it expires.
	hold_for 3 "route while the session is still up" injected
	wait_for "route gone after the hold timer" $((hold + 8)) native
	gone=$(($(date +%s) - start))
	echo "route gone ${gone}s after the freeze (hold ${hold}s)"
	if [ "$gone" -lt 5 ]; then
		echo "route went in ${gone}s, before the ${hold}s hold timer could expire" >&2
		exit 1
	fi
	docker unpause "$cid"
	wait_for "steer after the session returns" 60 injected

	echo "6. SIGKILL: the route drops with the session"
	sigkill
	;;
addpath)
	echo "1. add-path: transit-b's inactive path arrives with a path ID"
	wait_for "add-path negotiated" 45 log_has 'bgp add-path negotiated'
	wait_for "edge best is Packeteer's route via transit-b" 90 injected
	wait_for "transit-b path with a path ID" 10 glass_has 192.0.2.22 ibgp
	wait_for "transit-a native path still sent while steered" 10 glass_has 192.0.2.21 ibgp
	wait_for "nothing exported to the transits" 10 transits_clean

	echo "2. transit-b withdraws: the add-path route check retires at once"
	start=$(date +%s)
	transit_b "no network $prefix"
	wait_for "edge back on transit-a" 20 native
	wait_for "retire logged from the route check" 5 route_check_retires 1
	echo "withdrawn $(($(date +%s) - start))s after transit-b's withdraw (hold_time 5m)"
	hold_for 8 "no re-inject while transit-b has no path" native

	echo "3. transit-b re-announces: steer again"
	transit_b "network $prefix"
	wait_for "steer again" 45 injected

	echo "4. SIGTERM withdraws"
	sigterm

	echo "5. restart, steer, SIGKILL"
	"${compose[@]}" start packeteer
	wait_for "steer after restart" 60 injected
	sigkill
	;;
bmp)
	echo "1. BMP: transit-b's inactive path is seen only over BMP"
	wait_for "bmp session" 45 log_has 'bmp session up'
	wait_for "edge best is Packeteer's route via transit-b" 90 injected
	wait_for "transit-b path from BMP" 10 glass_has 192.0.2.22 bmp
	if glass_has 192.0.2.22 ibgp; then
		echo "the edge sent transit-b's path over iBGP; this cell does not prove BMP" >&2
		exit 1
	fi
	wait_for "nothing exported to the transits" 10 transits_clean

	echo "2. transit-b withdraws: the route check retires at once"
	start=$(date +%s)
	transit_b "no network $prefix"
	wait_for "edge back on transit-a" 20 native
	wait_for "retire logged from the route check" 5 route_check_retires 1
	echo "withdrawn $(($(date +%s) - start))s after transit-b's withdraw (hold_time 5m)"
	hold_for 8 "no re-inject while transit-b has no path" native

	echo "3. transit-b re-announces: steer again"
	transit_b "network $prefix"
	wait_for "steer again" 45 injected

	echo "4. SIGTERM withdraws"
	sigterm

	if [ "$router" = bird3 ]; then
		echo "5. skipped: BIRD 3 does not refeed BMP for sessions already up when the station reconnects"
	else
		echo "5. restarted station: the edge refeeds BMP, steer, SIGKILL"
		"${compose[@]}" start packeteer
		wait_for "steer after restart (BMP refeed)" 60 injected
		wait_for "transit-b path from BMP after restart" 10 glass_has 192.0.2.22 bmp
		sigkill
	fi
	;;
esac

echo "interop $router/$feature ok"
