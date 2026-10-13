#!/bin/bash
# Failure-mode matrix (#234): one injection surface against the failures
# that must leave the router with exactly the Packeteer routes the safety
# rules allow. Documentation prefixes and private ASNs only; simulated FRR
# routers only.
#
#   lab/e2e-failure-matrix.sh SURFACE [FAILURE...]
#
# A surface is a file in lab/failure-matrix/, one per way Packeteer puts a
# route on a router. Every surface answers every failure in FAILURES below,
# either with a case_<failure> function or with na_<failure>, a sentence on
# why the failure cannot happen there. A new surface adds its file and its
# entry in the failure-matrix CI job; lab/failure-matrix/matrix_test.go
# fails until it does.
#
# Each case starts from a fresh Packeteer and the surface's baseline route
# set, injects one failure, and asserts on the router, from
# `show bgp ipv4 unicast json`, never from Packeteer's own view:
#   - on every sample, no prefix outside EVER (the learned RIB view) and no
#     more than MAX_ROUTES routes;
#   - the routes are withdrawn, or kept, exactly as the case says, within
#     its bound, and then stay that way.
# MATRIX_BREAK=<failure> skips the config edit that triggers that failure's
# withdraw path, as a controller whose withdraw path is broken would; the case
# must then fail on the routes left on the router.
#
# What a surface file provides:
#   COMPOSE        compose files, base first
#   ROUTERS        compose services started once and left running
#   SVCS           Packeteer compose services; ACTIVE is the one that
#                  announces first, ACTIVE_TAG its tag in surface_routes
#   HOLD_FILE      FRR config whose `neighbor 192.0.2.10 timers K H` bounds
#                  a crash withdraw
#   SESSION_PEERS  the edge's neighbors that session loss shuts down
#   EVER, MAX_ROUTES   the router's allowed prefixes and route cap
#   surface_routes   prints "TAG ROUTE" lines for what Packeteer has on the router
#                  (unicast_routes TAG PEER lists what the edge learned from PEER)
#   surface_seed VARIANT   writes the lab dir (configs, probe files)
#   surface_baseline VARIANT   returns once the baseline routes are up
# and optionally surface_reset, surface_check, variant_<failure> (a seed
# variant for that case), KILL_FINAL and SESSION_FINAL (the routes left
# after SIGKILL and after session loss; none unless a standby takes over),
# CLEANUP_FILES.
set -euo pipefail
# checkpop sorts bytewise; sort here must agree.
export LC_ALL=C

FAILURES=(sigkill session-loss stale-measurements source-gone reload-observe lowered-cap)

root=$(cd "$(dirname "$0")/.." && pwd)
cd "$root"

surface=${1:-}
if [ -z "$surface" ] || [ ! -f "lab/failure-matrix/$surface.sh" ]; then
	echo "usage: $0 SURFACE [FAILURE...]" >&2
	echo "surfaces: $(cd lab/failure-matrix && ls ./*.sh | sed 's#^\./##; s#\.sh$##' | tr '\n' ' ')" >&2
	exit 2
fi
shift
cases=("$@")
if [ "${#cases[@]}" -eq 0 ]; then
	cases=("${FAILURES[@]}")
fi
for c in "${cases[@]}"; do
	if [[ " ${FAILURES[*]} " != *" $c "* ]]; then
		echo "unknown failure $c; known: ${FAILURES[*]}" >&2
		exit 2
	fi
done

lab_dir=$(mktemp -d)
chmod 755 "$lab_dir"
pop_bin=$(mktemp)
cfg_bin=$(mktemp)
export PACKETEER_LAB_DIR="$lab_dir"

SESSION_PEERS=(192.0.2.10)
KILL_FINAL=()
SESSION_FINAL=()
CLEANUP_FILES=()
# Both mode lines go to observe: inbound and mitigation need the top-level
# mode to be inject too, and a reload that only changed one is refused.
OBSERVE_SED='s/^\( *\)mode: inject/\1mode: observe/'
# shellcheck source=/dev/null
source "lab/failure-matrix/$surface.sh"

dc=(docker compose)
for f in "${COMPOSE[@]}"; do
	dc+=(-f "$f")
done
trap 'rc=$?; if [ "$rc" -ne 0 ]; then echo "---- lab logs ----"; "${dc[@]}" logs --no-color || true; "${dc[@]}" ps || true; fi; "${dc[@]}" down -v --remove-orphans || true; rm -f "$pop_bin" "$cfg_bin" "${CLEANUP_FILES[@]}"; rm -rf "$lab_dir"; exit "$rc"' EXIT

echo "building route list and config tools"
go build -o "$pop_bin" ./lab/checkpop
go build -o "$cfg_bin" ./lab/matrixcfg

hold=$(awk '$1 == "neighbor" && $2 == "192.0.2.10" && $3 == "timers" { print $5 }' "$HOLD_FILE")
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

current_case=
over_cap_grace=3
got=

edge_vty() {
	"${dc[@]}" exec -T edge vtysh "$@"
}

dump() {
	edge_vty -c 'show bgp summary' >&2 || true
	edge_vty -c 'show bgp ipv4 unicast' >&2 || true
	"${dc[@]}" logs --no-color "${SVCS[@]}" >&2 || true
}

fail() {
	echo "FAIL: $surface / $current_case: $*" >&2
	dump
	exit 1
}

count_lines() {
	printf '%s\n' "$1" | grep -c . || true
}

# unicast_routes TAG PEER prints "TAG PREFIX" for each prefix the edge holds
# a path for from PEER.
unicast_routes() {
	local out
	out=$(edge_vty -c 'show bgp ipv4 unicast json' 2>/dev/null) || return 1
	out=$(printf '%s\n' "$out" | "$pop_bin" "$2") || return 1
	printf '%s\n' "$out" | awk -v t="$1" 'NF { print t, $1 }'
}

# read_routes sets got to the sorted "TAG ROUTE" lines Packeteer has on the
# router. It runs in the script's shell (never in $(...)), so an unlearned
# prefix ends the run. A failed read returns 1.
read_routes() {
	local out tag p
	out=$(surface_routes) || return 1
	got=$(printf '%s\n' "$out" | grep . | sort -u || true)
	while read -r tag p; do
		[ -n "$p" ] || continue
		if [[ " $EVER " != *" $p "* ]]; then
			fail "Packeteer announced $p, which is not in the learned RIB view"
		fi
	done <<<"$got"
	if declare -F surface_check >/dev/null; then
		surface_check "$got"
	fi
}

# sample is read_routes plus the route cap. A withdraw in flight can show
# next to the route that replaces it for one read, so the cap fails only if
# it is still exceeded over_cap_grace re-reads later.
sample() {
	local i
	got="?"
	read_routes || return 1
	for i in $(seq 1 "$over_cap_grace"); do
		[ "$(count_lines "$got")" -gt "$MAX_ROUTES" ] || break
		sleep 1
		read_routes || return 1
	done
	if [ "$(count_lines "$got")" -gt "$MAX_ROUTES" ]; then
		fail "$(count_lines "$got") Packeteer routes on the router, the cap is $MAX_ROUTES: [$(echo $got)]"
	fi
}

# wait_routes SECONDS WHAT ROUTE...: wait until the router has exactly those
# routes (none when none are given).
wait_routes() {
	local within=$1 what=$2 want i
	shift 2
	want=$(printf '%s\n' "$@" | grep . | sort -u || true)
	for i in $(seq 1 "$within"); do
		if sample && [ "$got" = "$want" ]; then
			echo "ok: $what: the router has [$(echo $got)]"
			return 0
		fi
		sleep 1
	done
	if [ -z "$want" ]; then
		fail "$what: Packeteer routes still on the router after ${within}s: [$(echo $got)]"
	fi
	fail "$what: after ${within}s the router has [$(echo $got)], want [$(echo $want)]"
}

# stay_routes SECONDS WHAT ROUTE...: the routes must not change.
stay_routes() {
	local seconds=$1 what=$2 want end
	shift 2
	want=$(printf '%s\n' "$@" | grep . | sort -u || true)
	end=$(($(date +%s) + seconds))
	while [ "$(date +%s)" -lt "$end" ]; do
		if sample && [ "$got" != "$want" ]; then
			fail "$what: the routes changed within ${seconds}s: [$(echo $got)], want [$(echo $want)]"
		fi
		sleep 1
	done
	echo "ok: $what: [$(echo $want)] for ${seconds}s"
}

# wait_tag_gone DEADLINE TAG WHAT: no route of that instance is left by the
# epoch-second DEADLINE.
wait_tag_gone() {
	local deadline=$1 tag=$2 what=$3
	while true; do
		if sample && ! grep -q "^$tag " <<<"$got"; then
			echo "ok: $what: nothing of $tag is left"
			return 0
		fi
		if [ "$(date +%s)" -gt "$deadline" ]; then
			fail "$what: Packeteer routes of $tag still on the router: [$(echo $got)]"
		fi
		sleep 1
	done
}

# edit_config FILE SED-EXPR rewrites a config in the lab dir without
# replacing its inode, so the container's bind mount sees the new bytes. An
# edit that changes nothing is a broken case, not a quiet pass.
edit_config() {
	local file=$1 expr=$2 tmp
	if [ "${MATRIX_BREAK:-}" = "$current_case" ]; then
		echo "MATRIX_BREAK: not applying the $current_case edit to $file"
		return 0
	fi
	tmp=$(mktemp "$lab_dir/.cfg.XXXXXX")
	sed "$expr" "$lab_dir/$file" >"$tmp"
	if cmp -s "$tmp" "$lab_dir/$file"; then
		rm -f "$tmp"
		fail "sed '$expr' did not change $file"
	fi
	cat "$tmp" >"$lab_dir/$file"
	rm -f "$tmp"
}

hup() {
	local svc cid
	for svc in "$@"; do
		cid=$("${dc[@]}" ps -q "$svc")
		[ -n "$cid" ] || fail "$svc is not running"
		docker kill -s HUP "$cid" >/dev/null
	done
}

# need_log SECONDS SERVICE FIXED-STRING
need_log() {
	local seconds=$1 svc=$2 needle=$3 i logs
	for i in $(seq 1 "$seconds"); do
		logs=$("${dc[@]}" logs --no-color "$svc" 2>&1 || true)
		if grep -qF -- "$needle" <<<"$logs"; then
			return 0
		fi
		sleep 1
	done
	fail "$svc never logged: $needle"
}

# place_config DEST SRC places a lab Packeteer config in the lab dir with
# a fixed prober that reads $lab_dir/state.yaml (matrixcfg). Results the
# config carried inline become that file.
place_config() {
	"$cfg_bin" "$2" "$lab_dir/$1" "$lab_dir/state.yaml" /etc/packeteer/probes/state.yaml
	chmod 644 "$lab_dir/$1"
}

# seed_file DEST SRC copies a probe file into the lab dir.
seed_file() {
	cp "$2" "$lab_dir/$1"
	chmod 644 "$lab_dir/$1"
}

kill9() {
	local svc=$1 cid status code i
	cid=$("${dc[@]}" ps -q "$svc")
	[ -n "$cid" ] || fail "$svc is not running"
	docker kill -s KILL "$cid" >/dev/null
	for i in $(seq 1 25); do
		status=$(docker inspect -f '{{.State.Status}}' "$cid" 2>/dev/null || true)
		code=$(docker inspect -f '{{.State.ExitCode}}' "$cid" 2>/dev/null || true)
		if [ "$status" = "exited" ] && [ "$code" = "137" ]; then
			return 0
		fi
		sleep 0.2
	done
	fail "expected SIGKILL exit 137 for $svc, got status=${status:-unknown} code=${code:-unknown}"
}

shutdown_peers() {
	local verb=$1 peer
	for peer in "${SESSION_PEERS[@]}"; do
		edge_vty -c 'configure terminal' -c 'router bgp 64512' -c "${verb}neighbor $peer shutdown" -c 'end' >/dev/null
	done
}

# do_sigkill: SIGKILL runs no WithdrawAll. The killed instance's routes have to
# be gone once the router's hold timer has run out, and KILL_FINAL is what the
# router holds afterwards (a standby's route, or nothing).
do_sigkill() {
	local start
	start=$(date +%s)
	kill9 "$ACTIVE"
	wait_tag_gone $((start + hold + 6)) "$ACTIVE_TAG" "SIGKILL, hold timer ${hold}s"
	wait_routes 120 "after SIGKILL" "${KILL_FINAL[@]}"
	stay_routes 10 "after SIGKILL" "${KILL_FINAL[@]}"
}

# do_session_loss: the router shuts the session. Packeteer keeps running, so
# this is the RIB session loss path, not the hold timer.
do_session_loss() {
	local start
	start=$(date +%s)
	shutdown_peers ""
	wait_tag_gone $((start + 20)) "$ACTIVE_TAG" "session loss"
	wait_routes 60 "after session loss" "${SESSION_FINAL[@]}"
	stay_routes 10 "after session loss" "${SESSION_FINAL[@]}"
	shutdown_peers "no "
}

wait_edge() {
	local i
	for i in $(seq 1 60); do
		if edge_vty -c 'show bgp summary' >/dev/null 2>&1; then
			return 0
		fi
		sleep 1
	done
	echo "the edge never answered vtysh" >&2
	exit 1
}

bootstrap() {
	echo "building lab"
	"${dc[@]}" build
	"${dc[@]}" up -d --no-deps "${ROUTERS[@]}"
	wait_edge
}

# reset starts every case from a fresh Packeteer and the baseline routes.
reset() {
	local variant=${1:-}
	if declare -F surface_reset >/dev/null; then
		surface_reset "$variant"
	else
		"${dc[@]}" rm -sf "${SVCS[@]}" >/dev/null
		shutdown_peers "no "
		surface_seed "$variant"
		"${dc[@]}" up -d --no-deps "${SVCS[@]}"
	fi
	surface_baseline "$variant"
}

run_case() {
	local c=$1 id na vn
	id=${c//-/_}
	na="na_$id"
	vn="variant_$id"
	current_case=$c
	echo "==== $surface / $c ===="
	if [ -n "${!na:-}" ]; then
		echo "n/a: ${!na}"
		return 0
	fi
	if ! declare -F "case_$id" >/dev/null; then
		fail "the $surface surface has neither case_$id nor $na"
	fi
	reset "${!vn:-}"
	"case_$id"
	echo "PASS $surface / $c"
}

bootstrap
for c in "${cases[@]}"; do
	run_case "$c"
done
echo "failure matrix $surface ok"
