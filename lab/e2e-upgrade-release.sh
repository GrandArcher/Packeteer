#!/bin/bash
# Upgrade between real releases (#644). Runs the last published release image
# (pinned by digest) with sqlite history, a second user, a pin, a pause and an
# acknowledged alert, stops it, starts the image built from this tree on the
# same packeteer-data volume, and checks what the 1.2 to 1.3 upgrade notes
# promise. Then it does the documented downgrade on that volume: it starts the
# release image again (no config key is newer than the release, so none is
# removed). Complements
# lab/e2e-upgrade.sh, which upgrades a build of this tree against a fake
# release server.
#
# Documentation prefixes and the private ASN 64512 only. Observe mode: the
# FRR edge must receive no route from Packeteer at any sample.
#
#   IMAGE       the image built from this tree (default: built here as
#               packeteer:upgrade-pr)
#   PREV_IMAGE  the previous release, which must be pinned by digest
#
# To move to the next release, set PREV_IMAGE to its digest:
#   docker buildx imagetools inspect ghcr.io/grandarcher/packeteer:<version>
set -euo pipefail

root=$(cd "$(dirname "$0")/.." && pwd)
cd "$root"

prev_version=1.6.0
prev_image="${PREV_IMAGE:-ghcr.io/grandarcher/packeteer@sha256:324c39af4efc17c0e755e2348664fc502ac083ba8cc02518a11baf2c5d13ffaf}"
case "$prev_image" in
*@sha256:????????????????????????????????????????????????????????????????) ;;
*)
	echo "e2e-upgrade-release: PREV_IMAGE must be pinned by digest (name@sha256:...), got $prev_image" >&2
	exit 1
	;;
esac
new_image="${IMAGE:-packeteer:upgrade-pr}"
new_version=pr-build

compose=(docker compose -f lab/docker-compose-upgrade-release.yml)
work=$(mktemp -d)
chmod 755 "$work"
cp lab/packeteer-upgrade-release.yaml "$work/config.yaml"
chmod 644 "$work/config.yaml"
export PK_CONFIG="$work/config.yaml" PK_IMAGE="$new_image"

base=http://192.0.2.10:8080/api
admin=(-u admin:lab-only-upgrade-admin)
viewer=(-u noc-viewer:lab-only-upgrade-viewer)
prefix=198.51.100.0/24

fail() {
	echo "e2e-upgrade-release: FAIL: $*" >&2
	dump
	exit 1
}

dump() {
	"${compose[@]}" exec -T edge vtysh -c 'show bgp summary' >&2 || true
	"${compose[@]}" logs --no-color packeteer >&2 || true
}

trap 'rc=$?; "${compose[@]}" down -v --remove-orphans >/dev/null 2>&1 || true; rm -rf "$work"; exit "$rc"' EXIT

if ! docker image inspect "$new_image" >/dev/null 2>&1; then
	echo "building $new_image from this tree"
	docker build --build-arg VERSION="$new_version" -t "$new_image" .
fi
echo "pulling the previous release by digest: $prev_image"
docker pull "$prev_image" >/dev/null

api() { curl -sS "${admin[@]}" "$base/$1" 2>/dev/null || true; }
api_up() { curl -sf -o /dev/null "${admin[@]}" "$base/optimization"; }
# call METHOD PATH BODY: prints the body and, on the last line, the status.
# A 409 is the short window before the saved steering state is restored.
call() {
	local out i
	for i in 1 2 3 4 5 6 7 8 9 10; do
		out=$(curl -sS -X "$1" "${admin[@]}" -H 'Content-Type: application/json' -d "$3" -w '\n%{http_code}' "$base/$2")
		[ "$(tail -n1 <<<"$out")" = 409 ] || break
		sleep 2
	done
	printf '%s\n' "$out"
}
vty() { "${compose[@]}" exec -T edge vtysh -c "$1" 2>/dev/null || true; }

# received: how many routes the edge got from Packeteer, before policy.
received() {
	local s r
	s=$(vty 'show bgp ipv4 unicast summary json' | jq -r '(.ipv4Unicast.peers // .peers)["192.0.2.10"].pfxRcd // empty' 2>/dev/null || true)
	r=$(vty 'show bgp ipv4 unicast neighbors 192.0.2.10 received-routes json' | jq -r '(.receivedRoutes // {}) | length' 2>/dev/null || true)
	echo "${s:-?}/${r:-?}"
}
quiet() {
	local n
	n=$(received)
	[ "$n" = "0/0" ] || fail "the edge received routes from Packeteer (pfxRcd/received-routes $n)"
}
session_up() { [[ "$(vty 'show bgp neighbors 192.0.2.10')" == *"BGP state = Established"* ]]; }

wait_for() { # wait_for SECONDS WHAT CMD...
	local end=$((SECONDS + $1)) what=$2
	shift 2
	while [ "$SECONDS" -lt "$end" ]; do
		if "$@" 2>/dev/null; then return 0; fi
		sleep 2
	done
	fail "timed out waiting for: $what"
}

learned() {
	api "troubleshoot/lookingglass?prefix=$prefix" | jq -e --arg p "$prefix" '.exact.prefix == $p' >/dev/null
}
down_event() {
	api 'events?limit=1000' | jq -e '[.events[] | select(.kind == "provider.down" and .fields.provider == "transit-b")] | length > 0' >/dev/null
}

cid() { "${compose[@]}" ps -a -q packeteer; }

# start IMAGE VERSION: recreate the Packeteer container on the shared volume.
start() {
	PK_IMAGE=$1 "${compose[@]}" up -d --force-recreate --no-deps packeteer >/dev/null
	wait_for 120 "the ops API of $1" api_up
	local v
	v=$(curl -sS "${admin[@]}" "$base/optimization" | jq -r .version)
	[[ "$v" == *"$2"* ]] || fail "running version is $v, want $2"
	wait_for 120 "the iBGP session" session_up
}

# stop: SIGTERM, exit code 0.
stop() {
	local id
	id=$(cid)
	docker stop -t 20 "$id" >/dev/null
	[ "$(docker inspect -f '{{.State.ExitCode}}' "$id")" = 0 ] || fail "the container did not exit 0 on SIGTERM"
	"${compose[@]}" rm -f packeteer >/dev/null
}

# check_cfg IMAGE FILE: the image's -check on a config file, with no data
# volume, so it cannot touch the shared one.
check_cfg() {
	docker run --rm -v "$2:/etc/packeteer/config.yaml:ro" -v "$root/lab/probes:/etc/packeteer/probes:ro" \
		"$1" -check >"$work/check.out" 2>&1
}

echo "== -check on the config with the release image and the build"
check_cfg "$prev_image" "$work/config.yaml" || { cat "$work/check.out" >&2; fail "-check refused the lab config on the release image"; }
check_cfg "$new_image" "$work/config.yaml" || { cat "$work/check.out" >&2; fail "-check refused the lab config on the build"; }

echo "== the release image ($prev_version): write state"
"${compose[@]}" up -d edge >/dev/null
start "$prev_image" "$prev_version"
wait_for 60 "$prefix in the learned view" learned
wait_for 90 "the provider.down alert for transit-b" down_event
quiet

resp=$(call POST users '{"name":"noc-viewer","role":"viewer","password":"lab-only-upgrade-viewer"}')
[ "$(tail -n1 <<<"$resp")" = 201 ] || fail "create user: $resp"
resp=$(call POST pins "{\"prefix\":\"$prefix\",\"provider\":\"transit-a\",\"max_loss_pct\":5,\"duration\":\"24h\",\"reason\":\"upgrade lab\"}")
case "$(tail -n1 <<<"$resp")" in 200 | 201) ;; *) fail "pin: $resp" ;; esac
pin_id=$(sed '$d' <<<"$resp" | jq -r .id)
[ -n "$pin_id" ] && [ "$pin_id" != null ] || fail "pin has no id: $resp"
resp=$(call POST optimization/pause '{"reason":"upgrade lab pause"}')
case "$(tail -n1 <<<"$resp")" in 200 | 201) ;; *) fail "pause: $resp" ;; esac
key=$(api 'events?limit=1000' | jq -r '[.events[] | select(.kind == "provider.down" and .fields.provider == "transit-b")][0].dedup_key')
[ -n "$key" ] && [ "$key" != null ] || fail "no dedup_key on the provider.down event"
resp=$(call POST alerts/ack "{\"key\":\"$key\",\"note\":\"upgrade lab\"}")
[ "$(tail -n1 <<<"$resp")" = 200 ] || fail "ack: $resp"

# The events written before the upgrade, by time, to prove the history is kept.
api 'events?limit=1000' | jq -c '[.events[] | select(.kind == "provider.down" and .fields.provider == "transit-b") | .time]' >"$work/times.json"
api 'events?limit=1000' | jq -c '[.events[] | select(.kind == "controller.started")] | length' >"$work/started.txt"

# state_is_kept WHO: the pin, the pause, the acknowledgement, the users, the
# history, the mode, and an empty edge, on whatever image is running.
state_is_kept() {
	local who=$1 out
	out=$(api pins)
	jq -e --arg id "$pin_id" --arg p "$prefix" '.mode == "observe" and ([.pins[] | select(.id == $id and .prefix == $p and .provider == "transit-a")] | length == 1)' <<<"$out" >/dev/null ||
		fail "$who: the pin is not restored: $out"
	out=$(api optimization)
	jq -e '.mode == "observe" and .paused == true and .reason == "upgrade lab pause" and .by == "admin"' <<<"$out" >/dev/null ||
		fail "$who: the pause is not restored: $out"
	out=$(api 'events?limit=1000')
	jq -e --arg k "$key" '[.events[] | select(.dedup_key == $k and .ack.by == "admin" and .ack.note == "upgrade lab")] | length > 0' <<<"$out" >/dev/null ||
		fail "$who: the acknowledgement is not restored: $out"
	jq -e --argjson t "$(cat "$work/times.json")" '[.events[] | select(.kind == "provider.down" and .fields.provider == "transit-b") | .time] as $now | all($t[]; . as $x | $now | index($x) != null)' <<<"$out" >/dev/null ||
		fail "$who: events written before the upgrade are gone: $out"
	jq -e '[.events[] | select(.kind == "steering.lost")] | length == 0' <<<"$out" >/dev/null ||
		fail "$who: steering.lost fired, so saved state was not fully restored: $out"
	out=$(api users)
	jq -e '[.users[].name] | index("admin") != null and index("noc-viewer") != null' <<<"$out" >/dev/null ||
		fail "$who: users are not kept: $out"
	[ "$(curl -sS -o /dev/null -w '%{http_code}' "${viewer[@]}" "$base/me")" = 200 ] ||
		fail "$who: the viewer cannot sign in with the password set before the upgrade"
	out=$(api audit)
	jq -e '[.records[] | select(.action == "POST /api/pins" and .result == "ok" and .actor == "admin")] | length > 0' <<<"$out" >/dev/null ||
		fail "$who: the audit log lost the pin change: $out"
	# The RIB is rebuilt from the session after every restart, so the route
	# arrives some seconds after the session is Established.
	wait_for 60 "$who: $prefix in the learned view" learned
	quiet
}
state_is_kept "release $prev_version"

echo "== upgrade: stop the release, start the build on the same volume"
stop
start "$new_image" "$new_version"
state_is_kept "build"
n=$(api 'events?limit=1000' | jq '[.events[] | select(.kind == "controller.started")] | length')
[ "$n" -gt "$(cat "$work/started.txt")" ] || fail "no new controller.started event after the upgrade (before $(cat "$work/started.txt"), now $n)"
echo "e2e-upgrade-release: upgrade kept pin, pause, ack, users, history; mode observe; nothing announced"

echo "== downgrade: start the release image on the same volume"
# No config key is newer than the release (v1.6.0 accepts everything the build
# does), so the downgrade removes nothing. When the build adds a key, write it
# into a copy of the config here, check that the release refuses it, and start
# the release with the original config, as the README upgrade notes say.
stop
start "$prev_image" "$prev_version"
state_is_kept "release $prev_version after the downgrade"

echo "== SIGTERM"
stop
echo "e2e-upgrade-release: ok"
