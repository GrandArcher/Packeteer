#!/bin/bash
# MikroTik CHR lab (#52). Boots the free RouterOS CHR image in QEMU (no
# GNS3, no license: the free level is enough for BGP), configures it with
# lab/chr/edge.rsc over the REST API, and runs Packeteer in inject mode
# against it. Asserts that RouterOS:
#
#   - accepts Packeteer's iBGP route (exact learned prefix, community
#     64512:666 + NO_EXPORT, local-pref 250) and makes it active
#   - rejects an iBGP route without the community on the same filter
#   - never exports the Packeteer route to an eBGP peer
#   - never receives an allowlisted prefix that is not in the learned RIB
#   - drops the route on flip-back, SIGTERM, a frozen process (hold timer),
#     and SIGKILL. Graceful restart stays off.
#
# Then the read-only router check (#637): Packeteer in observe with
# preflight.router_check type routeros, logged in as a read-group user made
# for this run, passes import_filter on edge.rsc and fails it with the fix
# once an eBGP connection's output chain lacks the reject. The router's
# /export is the same before and after each read, and the login is in no
# API answer or log line.
#
# Documentation prefixes and private/documentation ASNs only. Lab/CI only.
#
# Needs: sudo (tap device and lab addresses), qemu-system-x86_64, qemu-img,
# curl, jq, unzip, openssl, go. Packeteer runs from the container image with
# --network host and a mounted config (docker build unless PACKETEER_IMAGE
# names an image). PACKETEER_BIN runs a local binary instead (development
# without Docker). CHR_ACCEL=kvm|tcg overrides accelerator detection.
set -euo pipefail

root=$(cd "$(dirname "$0")/.." && pwd)
cd "$root"

# Pinned long-term release of the free CHR image, fetched from MikroTik at
# run time. Nothing from the image is committed or cached by CI.
chr_version=${CHR_VERSION:-7.23.7}
chr_sha256=${CHR_SHA256:-781cdc538decc0c56dc141df129288cdfd874332b23ffc38052675cc56dc58be}
chr_url="https://download.mikrotik.com/routeros/${chr_version}/chr-${chr_version}.img.zip"

tap=pkchr0
rest_port=18780
pk_http=127.0.0.1:18090
prefix=198.51.100.0/24
unlearned=203.0.113.0/24
community=64512:666

work=$(mktemp -d)
mkdir -p "$work/probes"
pk_pid=
pk_name=pkchr
peer_pids=()

log() { echo "== $*"; }

rest() {
	local path=$1
	shift
	curl -sS -m 10 -u admin: -H 'content-type: application/json' "$@" "http://127.0.0.1:${rest_port}/rest${path}"
}

pk_logs() {
	if [ -n "${PACKETEER_BIN:-}" ]; then
		cat "$work/packeteer.log" 2>/dev/null || true
	else
		docker logs "$pk_name" 2>&1 || true
	fi
}

dump() {
	echo "---- CHR routes ----" >&2
	rest '/routing/route' 2>/dev/null | jq -c '.[] | select(."dst-address" | test("^(198\\.51\\.100|203\\.0\\.113)"))' >&2 || true
	echo "---- CHR BGP sessions ----" >&2
	rest '/routing/bgp/session' 2>/dev/null | jq -c '.[] | {name, "remote.address", established, "hold-time", "last-stopped"}' >&2 || true
	echo "---- CHR log ----" >&2
	rest '/log' 2>/dev/null | jq -r '.[] | "\(.time) \(.topics) \(.message)"' 2>/dev/null | tail -n 60 >&2 || true
	for f in "$work"/*.routes; do
		echo "---- $(basename "$f") ----" >&2
		cat "$f" >&2 || true
	done
	for f in "$work"/peer-*.log; do
		echo "---- $(basename "$f") ----" >&2
		tail -n 20 "$f" >&2 || true
	done
	echo "---- packeteer ----" >&2
	pk_logs | tail -n 80 >&2
	echo "---- CHR serial (tail) ----" >&2
	tail -c 2000 "$work/serial.log" 2>/dev/null >&2 || true
}

cleanup() {
	local rc=$?
	set +e
	if [ "$rc" -ne 0 ]; then
		dump
	fi
	for p in "${peer_pids[@]}"; do kill "$p" 2>/dev/null; done
	if [ -n "${PACKETEER_BIN:-}" ]; then
		[ -n "$pk_pid" ] && kill -CONT "$pk_pid" 2>/dev/null && kill -KILL "$pk_pid" 2>/dev/null
	else
		docker rm -f "$pk_name" >/dev/null 2>&1
	fi
	if [ -f "$work/qemu.pid" ]; then
		kill "$(cat "$work/qemu.pid")" 2>/dev/null
	fi
	sudo ip link del "$tap" 2>/dev/null
	rm -rf "$work"
	exit "$rc"
}
trap cleanup EXIT

fail() {
	echo "FAIL: $*" >&2
	exit 1
}

# ---- CHR image (free, fetched from MikroTik, checksum pinned) ----
cache=${CHR_CACHE:-$work}
mkdir -p "$cache"
zip="$cache/chr-${chr_version}.img.zip"
if [ ! -f "$zip" ]; then
	log "downloading free CHR ${chr_version}"
	curl -fsSL --retry 5 --retry-delay 5 --retry-all-errors -o "$zip.part" "$chr_url"
	mv "$zip.part" "$zip"
fi
echo "${chr_sha256}  ${zip}" | sha256sum -c -
unzip -o -q "$zip" -d "$work"
# A throwaway overlay: the downloaded image is never modified.
qemu-img create -q -f qcow2 -F raw -b "$work/chr-${chr_version}.img" "$work/chr.qcow2"

# ---- lab network: tap with Packeteer and the lab speakers on the host ----
log "tap ${tap}: 192.0.2.0/24"
sudo ip link del "$tap" 2>/dev/null || true
sudo ip tuntap add dev "$tap" mode tap user "$(id -un)"
# 192.0.2.10 first, so it is the primary address and Packeteer's source.
sudo ip addr add 192.0.2.10/24 dev "$tap"
for a in 192.0.2.1 192.0.2.2 192.0.2.20 192.0.2.30; do
	sudo ip addr add "$a/32" dev "$tap"
done
sudo ip link set "$tap" up

# ---- boot CHR ----
accel=${CHR_ACCEL:-}
if [ -z "$accel" ]; then
	if [ -r /dev/kvm ] && [ -w /dev/kvm ]; then accel=kvm; else accel=tcg; fi
fi
log "booting CHR ${chr_version} (accel ${accel})"
# ether1: user-mode network, management only (REST on a host loopback port).
# ether2: the lab tap.
qemu-system-x86_64 -accel "$accel" -m 256 -smp 1 \
	-drive "file=$work/chr.qcow2,if=virtio,format=qcow2" \
	-netdev "user,id=mgmt,hostfwd=tcp:127.0.0.1:${rest_port}-:80" \
	-device virtio-net-pci,netdev=mgmt \
	-netdev "tap,id=lab,ifname=${tap},script=no,downscript=no" \
	-device virtio-net-pci,netdev=lab \
	-serial "file:$work/serial.log" -monitor none -display none \
	-daemonize -pidfile "$work/qemu.pid"

up=0
for _ in $(seq 1 150); do
	if rest '/system/resource' -o "$work/resource.json" 2>/dev/null && jq -e '.version' "$work/resource.json" >/dev/null 2>&1; then
		up=1
		break
	fi
	sleep 2
done
[ "$up" = 1 ] || fail "CHR REST API did not come up"
jq -c '{version, "board-name", uptime}' "$work/resource.json"
jq -e --arg v "$chr_version" '.version | startswith($v)' "$work/resource.json" >/dev/null || fail "unexpected RouterOS version"
# No license key is ever applied: the run must be on the free level.
rest '/system/license' | tee "$work/license.json"
echo
jq -e '.level == "free"' "$work/license.json" >/dev/null || fail "CHR is not on the free license level"

# ---- configure the edge from lab/chr/edge.rsc ----
log "applying lab/chr/edge.rsc"
rest '/execute' -X POST -d "$(jq -Rs '{script: ., "as-string": true}' lab/chr/edge.rsc)" | tee "$work/apply.json"
echo
jq -e '.ret == ""' "$work/apply.json" >/dev/null || fail "edge.rsc did not apply cleanly"

# Graceful restart must not be configured anywhere on the router.
if rest '/routing/bgp/connection' | jq -e 'any(.[]; (.["graceful-restart"] // "no") != "no")' >/dev/null; then
	fail "graceful restart is enabled on a CHR connection"
fi

# ---- lab speakers ----
log "starting lab speakers"
go build -o "$work/chrpeer" ./lab/chrpeer
peer() {
	local name=$1
	shift
	"$work/chrpeer" -peer 192.0.2.254 -peer-asn 64512 -routes "$work/$name.routes" "$@" >"$work/peer-$name.log" 2>&1 &
	peer_pids+=($!)
}
peer transit-a -asn 64496 -router-id 192.0.2.1 -local 192.0.2.1 -announce "$prefix"
peer transit-b -asn 64497 -router-id 192.0.2.2 -local 192.0.2.2 -announce "$prefix"
peer collector -asn 64498 -router-id 192.0.2.20 -local 192.0.2.20
peer untagged -asn 64512 -router-id 192.0.2.30 -local 192.0.2.30 -announce "$unlearned"

session_up() {
	rest '/routing/bgp/session' 2>/dev/null | jq -e --arg a "$1" 'any(.[]; ."remote.address" == $a and .established == "true")' >/dev/null
}

wait_for() {
	local what=$1 tries=$2
	shift 2
	local i
	for i in $(seq 1 "$tries"); do
		if "$@"; then
			return 0
		fi
		sleep 1
	done
	fail "timed out: $what"
}

for a in 192.0.2.1 192.0.2.2 192.0.2.20 192.0.2.30; do
	wait_for "CHR session to $a" 60 session_up "$a"
done

routes() {
	rest '/routing/route' -o "$work/routes.json" 2>/dev/null && jq -e 'type == "array"' "$work/routes.json" >/dev/null 2>&1
}

# The untagged iBGP route reaches the CHR and is filtered by packeteer-in.
untagged_filtered() {
	routes && jq -e --arg p "$unlearned" 'any(.[]; ."dst-address" == $p and .filtered == "true" and (.gateway == "192.0.2.30")) and
		(all(.[]; ."dst-address" != $p or .filtered == "true"))' "$work/routes.json" >/dev/null
}
wait_for "untagged route filtered by packeteer-in" 30 untagged_filtered
log "untagged iBGP route ${unlearned} rejected by packeteer-in"

collector_has_native() {
	grep -q "^${prefix} " "$work/collector.routes" 2>/dev/null && ! grep -q "$community" "$work/collector.routes"
}
wait_for "collector learns ${prefix} from the CHR" 30 collector_has_native

# ---- Packeteer ----
cp lab/probes/prefer-b.yaml "$work/probes/state.yaml"
flip() {
	cp "lab/probes/$1.yaml" "$work/probes/.next"
	mv "$work/probes/.next" "$work/probes/state.yaml"
}

if [ -n "${PACKETEER_BIN:-}" ]; then
	sed "s#/etc/packeteer/probes/#$work/probes/#" lab/chr/packeteer.yaml >"$work/packeteer.yaml"
else
	cp lab/chr/packeteer.yaml "$work/packeteer.yaml"
	image=${PACKETEER_IMAGE:-}
	if [ -z "$image" ]; then
		image=packeteer:chr
		log "building ${image}"
		docker build -q -t "$image" --build-arg VERSION=chr .
	fi
fi

pk_start() {
	if [ -n "${PACKETEER_BIN:-}" ]; then
		"$PACKETEER_BIN" -config "$work/packeteer.yaml" >>"$work/packeteer.log" 2>&1 &
		pk_pid=$!
	else
		docker rm -f "$pk_name" >/dev/null 2>&1 || true
		docker run -d --name "$pk_name" --network host --cap-add NET_RAW --cap-add NET_ADMIN \
			-e PACKETEER_LOG_LEVEL=debug -e PACKETEER_ROUTER_READ_USER -e PACKETEER_ROUTER_READ_PASSWORD \
			-e PACKETEER_HTTP_USER -e PACKETEER_HTTP_PASSWORD \
			-v "$work/packeteer.yaml:/etc/packeteer/config.yaml:ro" \
			-v "$work/probes:/etc/packeteer/probes:ro" "$image" >/dev/null
	fi
}

pk_signal() {
	if [ -n "${PACKETEER_BIN:-}" ]; then
		kill -"$1" "$pk_pid"
	else
		docker kill -s "$1" "$pk_name" >/dev/null
	fi
}

# pk_wait waits for Packeteer to exit and sets pk_rc to its exit code.
pk_rc=
pk_wait() {
	if [ -n "${PACKETEER_BIN:-}" ]; then
		pk_rc=0
		wait "$pk_pid" || pk_rc=$?
	else
		pk_rc=$(docker wait "$pk_name")
	fi
}

# Every CHR read also checks the invariants that hold for the whole run:
# no Packeteer route for a prefix outside the learned RIB, and no Packeteer
# route (or community) exported to an eBGP speaker.
invariants() {
	if jq -e --arg p "$unlearned" --arg c "$community" 'any(.[]; ."dst-address" == $p and ((."bgp.communities" // "") | contains($c)))' "$work/routes.json" >/dev/null; then
		fail "CHR received ${unlearned} from Packeteer, a prefix not in the learned RIB"
	fi
	if grep -q "$community" "$work/collector.routes" "$work/transit-a.routes" "$work/transit-b.routes"; then
		fail "Packeteer community exported to an eBGP peer"
	fi
}

# route_state prints present, absent, or bad (a Packeteer route that is
# not exactly what RouterOS should hold) for the last routes read.
route_state() {
	jq -r --arg p "$prefix" --arg c "$community" '
		[.[] | select(."dst-address" == $p and ((."bgp.communities" // "") | contains($c)))] as $r |
		if ($r | length) == 0 then "absent"
		elif ($r | length) == 1 and ($r[0] |
			.gateway == "192.0.2.2" and .active == "true" and (.filtered // "false") != "true" and
			."bgp.local-pref" == "250" and
			((."bgp.communities" | split(",")) as $cs | ($cs | index($c)) != null and ($cs | index("no-export")) != null) and
			(."belongs-to" | contains("192.0.2.10")))
		then "present" else "bad" end' "$work/routes.json"
}

route_is() {
	local s
	routes || return 1
	invariants
	s=$(route_state)
	if [ "$s" = bad ]; then
		fail "CHR holds a Packeteer route with the wrong attributes"
	fi
	[ "$s" = "$1" ]
}

log "starting Packeteer (inject, transit-b faster)"
pk_start
wait_for "CHR accepts Packeteer's route" 90 route_is present
rest '/routing/route' | jq -c --arg p "$prefix" '.[] | select(."dst-address" == $p) | {gateway, active, "belongs-to", "bgp.local-pref", "bgp.communities", distance}'
log "RouterOS accepted ${prefix} via 192.0.2.2 with ${community} + no-export, local-pref 250, active"

collector_lost_prefix() {
	routes && invariants && ! grep -q "^${prefix} " "$work/collector.routes"
}
# The router's best path now carries the Packeteer community, so ebgp-out
# (and NO_EXPORT) keeps it from every eBGP peer: the collector's copy is
# withdrawn, never replaced by Packeteer's route.
wait_for "collector no longer receives ${prefix}" 30 collector_lost_prefix
log "Packeteer route not exported to the eBGP collector"

# The session runs on the router's 9s hold time, and Packeteer never offers
# graceful restart (RouterOS itself offers "gr"; it takes both sides).
rest '/routing/bgp/session' -o "$work/sessions.json"
jq -c '.[] | select(."remote.address" == "192.0.2.10") | {"hold-time", "remote.capabilities", "local.capabilities"}' "$work/sessions.json"
jq -e '[.[] | select(."remote.address" == "192.0.2.10" and .established == "true")] | length == 1 and
	(.[0]."hold-time" == "9s") and ((.[0]."remote.capabilities" // "") | split(",") | index("gr") == null)' "$work/sessions.json" >/dev/null ||
	fail "Packeteer session: want hold time 9s and no graceful-restart capability from Packeteer"

stays() {
	local i
	for i in $(seq 1 "$1"); do
		route_is present || fail "route did not stay present ($2) at second $i"
		sleep 1
	done
}
stays 10 "native path hidden by the router; no flap"

log "flip-back: transit-a faster again"
flip prefer-a
wait_for "route withdrawn on flip-back" 30 route_is absent
wait_for "collector gets the native path back" 30 collector_has_native

log "restoring the improvement"
flip prefer-b
wait_for "route back after the flip-back cooldown" 60 route_is present

log "SIGTERM: WithdrawAll before exit"
pk_signal TERM
wait_for "route withdrawn after SIGTERM" 30 route_is absent
pk_wait
[ "$pk_rc" = 0 ] || fail "Packeteer exit code $pk_rc after SIGTERM"
pk_logs | grep -q "withdrew all.*prefixes=1" || fail "no WithdrawAll of the injected route in the log"

hold=$(rest '/routing/bgp/connection' | jq -r '.[] | select(.name == "packeteer") | ."hold-time"')
[ "$hold" = 9s ] || fail "packeteer connection hold-time is '$hold', want 9s"

pk_session_down() {
	! session_up 192.0.2.10
}

# crash_drop SIGNAL: the route must stay while the session is up and be
# gone within the 9s hold timer (plus polling slack) after the signal.
crash_drop() {
	local sig=$1 start deadline s
	wait_for "route present before ${sig}" 60 route_is present
	start=$(date +%s)
	pk_signal "$sig"
	deadline=$((start + 9 + 8))
	while [ "$(date +%s)" -le "$deadline" ]; do
		routes || { sleep 1; continue; }
		invariants
		s=$(route_state)
		[ "$s" = bad ] && fail "bad Packeteer route after ${sig}"
		if [ "$s" = absent ]; then
			pk_session_down || fail "route dropped while the Packeteer session is still established (${sig})"
			log "route gone $(($(date +%s) - start))s after ${sig} (hold 9s)"
			return 0
		fi
		sleep 1
	done
	fail "route still present past the 9s hold timer after ${sig}"
}

log "frozen controller (SIGSTOP): no keepalives, hold timer expires"
pk_start
crash_drop STOP
pk_signal KILL
pk_wait

log "SIGKILL: no WithdrawAll, session loss drops the route"
pk_start
crash_drop KILL
pk_wait
[ "$pk_rc" = 137 ] || fail "expected SIGKILL exit 137, got $pk_rc"

wait_for "collector gets the native path back after the crash" 30 collector_has_native
routes && invariants

# ---- read-only router check (#637) ----
log "read-only router check: routeros, observe, read-group user"
reader_pw=$(openssl rand -hex 16) # generated per run, never a literal
chr_script() {
	rest '/execute' -X POST -d "$(jq -n --arg s "$1" '{script: $s, "as-string": true}')" >/dev/null
}
chr_script "/user add name=pk-reader group=read password=\"${reader_pw}\""
rest '/user' | jq -e 'any(.[]; .name == "pk-reader" and .group == "read")' >/dev/null || fail "read-group user not created"
export PACKETEER_ROUTER_READ_USER=pk-reader PACKETEER_ROUTER_READ_PASSWORD="$reader_pw"
# Running the preflight checks needs a login on Packeteer's API.
http_pw=$(openssl rand -hex 16)
export PACKETEER_HTTP_USER=lab PACKETEER_HTTP_PASSWORD="$http_pw"
{
	sed 's/^mode: inject$/mode: observe/' "$work/packeteer.yaml"
	printf 'preflight:\n  router_check:\n    type: routeros\n    config:\n'
	printf '      url: http://127.0.0.1:%s\n      username_env: PACKETEER_ROUTER_READ_USER\n      password_env: PACKETEER_ROUTER_READ_PASSWORD\n' "$rest_port"
} >"$work/router-check.yaml"
mv "$work/router-check.yaml" "$work/packeteer.yaml"
grep -q '^mode: observe$' "$work/packeteer.yaml" || fail "router check config is not observe"

router_export() {
	rest '/execute' -X POST -d '{"script": "/export", "as-string": true}' | jq -r '.ret' | grep -v '^#'
}

# check_filter NAME STATUS PATTERN... runs the preflight checks and expects
# import_filter to have STATUS with every PATTERN in its detail and fix.
check_filter() {
	local name=$1 status=$2 want
	shift 2
	router_export >"$work/export-$name-before.txt"
	curl -fsS -m 30 -u "lab:$http_pw" -X POST "http://${pk_http}/api/preflight/run" >"$work/report-$name.json"
	curl -fsS -m 10 -u "lab:$http_pw" "http://${pk_http}/api/preflight" >"$work/latest-$name.json"
	router_export >"$work/export-$name-after.txt"
	jq '.results[] | select(.id == "import_filter")' "$work/report-$name.json" | tee "$work/filter-$name.json"
	jq -e --arg s "$status" '.status == $s' "$work/filter-$name.json" >/dev/null || fail "$name: import_filter is not $status"
	for want in "$@"; do
		jq -r '.detail + "\n" + (.fix // "")' "$work/filter-$name.json" | grep -qF -- "$want" || fail "$name: import_filter lacks: $want"
	done
	diff "$work/export-$name-before.txt" "$work/export-$name-after.txt" || fail "$name: the router config changed during the read"
	[ -s "$work/export-$name-after.txt" ] || fail "$name: empty /export"
}

pk_start
api_up() { curl -fsS -m 2 -u "lab:$http_pw" "http://${pk_http}/healthz" >/dev/null 2>&1; }
wait_for "Packeteer API (router check)" 60 api_up

check_filter good pass 'Read from the router (routeros, read-only commands)' \
	'Import from Packeteer 192.0.2.10 (connection packeteer): chain packeteer-in accepts only routes with 64512:666.' \
	'Export to eBGP connection collector: chain ebgp-out rejects 64512:666 at rule 1, before any accept.'

log "the collector's output chain without the reject"
chr_script '/routing filter rule add chain=ebgp-open rule="accept"'
chr_script '/routing bgp connection set [find where name=collector] output.filter-chain=ebgp-open'
rest '/routing/bgp/connection' | jq -e 'any(.[]; .name == "collector" and ."output.filter-chain" == "ebgp-open")' >/dev/null ||
	fail "collector output chain not changed"
check_filter broken fail 'Export to eBGP connection collector: chain ebgp-open accepts at rule 1 before 64512:666 is rejected.' \
	'/routing filter rule add chain=ebgp-open place-before=0 rule="if (bgp-communities includes 64512:666) { reject }"'
jq -e '.confirmable != true' "$work/filter-broken.json" >/dev/null || fail "a failing router check is confirmable"

pk_signal TERM
pk_wait
pk_logs >"$work/packeteer-router-check.log"
grep -qF 'announce=disabled' "$work/packeteer-router-check.log" || fail "router check run was not observe"
if grep -lF -e "$reader_pw" -e pk-reader "$work"/report-*.json "$work"/latest-*.json "$work/packeteer-router-check.log"; then
	fail "the router login is in the output above"
fi
log "router check: pass with evidence, fail with the fix, router config unchanged"
log "e2e-chr ok"
