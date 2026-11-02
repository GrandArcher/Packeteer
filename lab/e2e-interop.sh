#!/bin/bash
# Router interop matrix (#53): one scenario per (router, feature) cell, run
# against a simulated edge of that router type. Lab only: documentation
# prefixes and documentation/private ASNs, simulated routers in Docker.
#
#	bash lab/e2e-interop.sh frr|bird2|bird3|gobgp ibgp|addpath|bmp
#	bash lab/e2e-interop.sh frr|bird3|gobgp bmponly
#	bash lab/e2e-interop.sh bird2|bird3 external
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
# external external policy feed, BIRD only (#232,
#          lab/interop/packeteer-external.yaml): no announcer, the session
#          only learns; packeteer-policy on the edge renders the feed into
#          static routes and runs birdc configure.
#          1. the edge's best is the feed's static route, with what inject
#             would send (next hop 192.0.2.22, local-pref 250, 64512:666,
#             no-export); the feed lists exactly that route; nothing
#             arrives on the BGP session.
#          2. it stays while the edge no longer sends the native path.
#          3. flip-back removes it; restoring the probes brings it back.
#          4. SIGTERM: the feed goes and the edge drops the route.
#          5. SIGKILL: the route stays until the feed's 10s TTL, then goes.
# bmponly  RIB view from BMP alone (#237, lab/interop/packeteer-bmponly.yaml):
#          no bgp.neighbors and no announcer; the decision is published on
#          the external policy feed.
#          1. both transits' paths arrive over BMP, none over iBGP; the
#             feed lists exactly the route inject would send.
#          2. the edge stops: the BMP feed drops, the view is not ready,
#             and the feed empties.
#          3. the edge comes back: BMP reconnects and the route returns.
set -euo pipefail

router=${1:-}
feature=${2:-}
case "$router" in
frr) format=frr ;;
bird2 | bird3) format=bird ;;
gobgp) format=gobgp ;;
*)
	echo "usage: $0 frr|bird2|bird3|gobgp ibgp|addpath|bmp|bmponly" >&2
	exit 2
	;;
esac
case "$feature" in
ibgp) config=packeteer.yaml ;;
addpath) config=packeteer-addpath.yaml ;;
bmp) config=packeteer-bmp.yaml ;;
external) config=packeteer-external.yaml ;;
bmponly) config=packeteer-bmponly.yaml ;;
*)
	echo "usage: $0 frr|bird2|bird3|gobgp ibgp|addpath|bmp|bmponly" >&2
	exit 2
	;;
esac
if [ "$feature" = external ] && [ "$format" != bird ]; then
	echo "the external cell runs on bird2 and bird3 only" >&2
	exit 2
fi
if [ "$router$feature" = bird2bmp ] || [ "$router$feature" = bird2bmponly ]; then
	echo "BIRD 2 packages are built without the BMP protocol; use bird3" >&2
	exit 2
fi

# BMP cells: the edge streams BMP to Packeteer's station. Feed cells:
# Packeteer publishes the external policy feed over TLS.
bmp_feed=false
if [ "$feature" = bmp ] || [ "$feature" = bmponly ]; then
	bmp_feed=true
fi
feed=false
if [ "$feature" = external ] || [ "$feature" = bmponly ]; then
	feed=true
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
if $bmp_feed; then
	INTEROP_BIRD_CONF=bird-bmp.conf
fi
# The external cell checks the edge's static route from the feed, not a
# path on the Packeteer session.
check_args=()
feed_url=https://192.0.2.10:9443
if $feed; then
	# Lab-only certificate and token, made fresh for each run.
	openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 -nodes -days 1 \
		-subj /CN=packeteer-lab -addext subjectAltName=IP:192.0.2.10 \
		-keyout "$lab_dir/probes/key.pem" -out "$lab_dir/probes/cert.pem" 2>/dev/null
	chmod 0644 "$lab_dir/probes/key.pem" "$lab_dir/probes/cert.pem"
	INTEROP_POLICY_TOKEN=$(openssl rand -hex 24)
	export INTEROP_POLICY_TOKEN
fi
if [ "$feature" = external ]; then
	INTEROP_BIRD_CONF=bird-external.conf
	check_args=(-protocol packeteer_feed4 -peer packeteer_feed4)
	echo "building packeteer-policy"
	mkdir -p "$lab_dir/feed"
	CGO_ENABLED=0 go build -o "$lab_dir/feed/packeteer-policy" ./cmd/policy
	cp examples/external-policy/bird.conf.tmpl "$lab_dir/probes/cert.pem" "$lab_dir/feed/"
	: >"$lab_dir/feed/routes.conf"
	chmod 0777 "$lab_dir/feed"
	chmod a+r "$lab_dir/feed"/*
	export INTEROP_FEED_DIR="$lab_dir/feed"
fi
if [ "$router" = gobgp ]; then
	# The edge runs the GoBGP release Packeteer itself links (go.mod).
	ver=$(go list -m -f '{{.Version}}' github.com/osrg/gobgp/v3)
	echo "building gobgpd $ver"
	mkdir -p "$lab_dir/gobgp"
	GOBIN="$lab_dir/gobgp" CGO_ENABLED=0 go install "github.com/osrg/gobgp/v3/cmd/gobgpd@$ver" "github.com/osrg/gobgp/v3/cmd/gobgp@$ver"
	cp lab/interop/gobgp/gobgpd.toml "$lab_dir/gobgp/gobgpd.toml"
	if $bmp_feed; then
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
		"$check_bin" -format "$format" -prefix "$1" "${check_args[@]}" -want injected -nexthop "$3" <<<"$out"
	else
		"$check_bin" -format "$format" -prefix "$1" "${check_args[@]}" -want "$2" <<<"$out"
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
		# JSON or nothing was read: an error message is not "clean".
		if ! grep -q '{' <<<"$out" || grep -q '%' <<<"$out"; then
			echo "$t: no received-routes table: $out" >&2
			return 1
		fi
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
	if $feed; then
		echo "---- external policy feed ----" >&2
		feed_doc >&2 || true
	fi
	if [ "$feature" = external ]; then
		echo "---- packeteer-policy ----" >&2
		cat "$lab_dir/feed/consumer.log" >&2 || true
		cat "$lab_dir/feed/routes.conf" >&2 || true
	fi
	echo "---- packeteer looking glass / decisions ----" >&2
	glass >&2 || true
	echo >&2
	"${compose[@]}" exec -T packeteer wget -qO- http://127.0.0.1:8080/api/decisions >&2 || true
	echo >&2
}

# feed_doc prints the feed's JSON document, read with the lab token.
feed_doc() {
	curl -sS --max-time 3 --cacert "$lab_dir/probes/cert.pem" \
		-H "Authorization: Bearer $INTEROP_POLICY_TOKEN" "$feed_url/v1/recommendations"
}

# feed_lists_unlearned: the feed carries a prefix no router advertised.
feed_lists_unlearned() {
	local doc p
	doc=$(feed_doc 2>/dev/null) || return 1
	for p in "${unlearned[@]}"; do
		if jq -e --arg p "$p" '.routes[] | select(.prefix == $p)' <<<"$doc" >/dev/null; then
			echo "$doc"
			return 0
		fi
	done
	return 1
}

# guard: on every sample, nothing Packeteer never learned is on the edge.
guard() {
	local p
	if $feed && feed_lists_unlearned >"$lab_dir/guard.feed"; then
		echo "SAFETY: the feed lists a prefix no router advertised" >&2
		cat "$lab_dir/guard.feed" >&2
		dump_bgp
		exit 1
	fi
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

# feed_is_inject: the feed lists exactly the route inject mode sends in the
# ibgp cell, with time left on it.
feed_is_inject() {
	feed_doc | jq -e '.expires_in_ms > 0 and (.routes | length) == 1 and (.routes[0] | del(.reason)) == {
		prefix: "198.51.100.0/24", provider: "transit-b", next_hop: "192.0.2.22", local_pref: 250,
		communities: ["64512:666", "65535:65281"], cause: "performance"}' >/dev/null
}

# feed_empty: the feed lists no route.
feed_empty() {
	feed_doc | jq -e '(.routes | length) == 0' >/dev/null
}

# rib_ready <0|1>: packeteer_bgp_ready, which with BMP alone follows the
# BMP feed.
rib_ready() {
	"${compose[@]}" exec -T packeteer wget -qO- http://127.0.0.1:8080/metrics 2>/dev/null | grep -qx "packeteer_bgp_ready $1"
}

# no_ibgp_paths: Packeteer's view holds no path learned over iBGP.
no_ibgp_paths() { ! glass | grep -q '"source":"ibgp"'; }

# session_quiet: no route arrived on the Packeteer session.
session_quiet() {
	local out
	out=$("${compose[@]}" exec -T "$edge" birdc -s /run/bird/bird.ctl show route protocol packeteer 2>&1) || return 1
	if grep -q 'via' <<<"$out"; then
		echo "a route arrived on the Packeteer session: $out" >&2
		return 1
	fi
}

start_consumer() {
	"${compose[@]}" exec -d -e PACKETEER_POLICY_TOKEN="$INTEROP_POLICY_TOKEN" "$edge" sh -c \
		"exec /opt/feed/packeteer-policy -url $feed_url -ca-file /opt/feed/cert.pem -template /opt/feed/bird.conf.tmpl -out /opt/feed/routes.conf -reload 'birdc -s /run/bird/bird.ctl configure' >>/opt/feed/consumer.log 2>&1"
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
external)
	start_consumer
	echo "1. the edge applies the feed's route, which is the route inject sends"
	wait_for "edge best is the feed's route via transit-b" 90 injected
	wait_for "the feed lists exactly the inject route" 10 feed_is_inject
	wait_for "nothing on the Packeteer session" 10 session_quiet
	wait_for "nothing exported to the transits" 10 transits_clean

	echo "2. the route stays while the edge no longer sends the native path"
	hold_for 10 "the feed's route" injected

	echo "3. flip-back removes the route; restoring the probes brings it back"
	cp lab/probes/prefer-a.yaml "$lab_dir/probes/state.yaml.new"
	mv "$lab_dir/probes/state.yaml.new" "$lab_dir/probes/state.yaml"
	wait_for "flip-back to transit-a" 45 native
	cp lab/probes/prefer-b.yaml "$lab_dir/probes/state.yaml.new"
	mv "$lab_dir/probes/state.yaml.new" "$lab_dir/probes/state.yaml"
	wait_for "the feed's route again" 45 injected

	echo "4. SIGTERM: the feed goes and the edge drops the route"
	"${compose[@]}" stop -t 20 packeteer
	wait_for "route gone after SIGTERM" 20 native

	echo "5. SIGKILL: the route stays until the feed's TTL, then goes"
	"${compose[@]}" start packeteer
	wait_for "the feed's route after restart" 60 injected
	cid=$(packeteer_cid)
	start=$(date +%s)
	docker kill -s KILL "$cid"
	# The consumer's expiry is the TTL from the renewal it last read: a
	# round renews at least every 2s probe interval and a change or a 3.3s
	# heartbeat brings it, so at least 10 - 2 - 3.3s are left at the kill.
	hold_for 3 "route before the TTL" injected
	wait_for "route gone after the TTL" 20 native
	gone=$(($(date +%s) - start))
	echo "route gone ${gone}s after SIGKILL (ttl 10s)"
	if [ "$gone" -lt 5 ]; then
		echo "route went in ${gone}s, before the feed's TTL could expire" >&2
		exit 1
	fi
	;;
bmponly)
	echo "1. BMP alone: both transits' paths arrive over BMP; the feed lists the inject route"
	wait_for "bmp session" 45 log_has 'bmp session up'
	wait_for "view ready on the BMP feed" 45 rib_ready 1
	wait_for "transit-a path from BMP" 30 glass_has 192.0.2.21 bmp
	wait_for "transit-b path from BMP" 10 glass_has 192.0.2.22 bmp
	if ! no_ibgp_paths; then
		echo "Packeteer learned a path over iBGP; this cell does not prove BMP alone" >&2
		exit 1
	fi
	wait_for "the feed lists exactly the inject route" 90 feed_is_inject
	hold_for 5 "the edge keeps its native path (nothing announces)" native

	echo "2. the edge stops: the BMP feed drops, the view is not ready, the feed empties"
	start=$(date +%s)
	"${compose[@]}" stop -t 10 "$edge"
	wait_for "view not ready without the BMP feed" 30 rib_ready 0
	wait_for "feed empty without the BMP feed" 15 feed_empty
	echo "feed empty $(($(date +%s) - start))s after the edge stopped"
	need_log 'bmp session down'

	echo "3. the edge returns: BMP reconnects and the route comes back"
	"${compose[@]}" start "$edge"
	wait_for "view ready again" 60 rib_ready 1
	wait_for "transit-b path from BMP after reconnect" 30 glass_has 192.0.2.22 bmp
	wait_for "the feed lists the inject route again" 90 feed_is_inject
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
