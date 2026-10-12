#!/usr/bin/env bash
# Upgrade e2e (#196): the Settings page's version check, one-click upgrade,
# and rollback against a lab release server (lab/fakerelease), with the real
# controller. Observe mode only; nothing here announces. The BGP side (the
# edge sees a clean withdraw, and the route returns only after a re-learn)
# is proven against a simulated edge by TestDaemonUpgradeWithdrawsRelearnsAndRollsBack.
#
#   MODE=bin    run a binary built from this tree (default)
#   MODE=docker run $IMAGE (default packeteer:ci) with a mounted config
#
# Checks: the page shows the running version; a bad signature and a bad
# checksum abort with no change; an unconfirmed upgrade is refused; the
# confirmed upgrade switches versions inside the same process (same PID, or
# the same container, not restarted) and leaves the config file untouched;
# rollback returns to the first version; SIGTERM still exits 0.
set -euo pipefail
cd "$(dirname "$0")/.."

mode="${MODE:-bin}"
image="${IMAGE:-packeteer:ci}"
work="$(mktemp -d)"
port=18191
rport=18190
pport=18192
base="http://127.0.0.1:$port"
auth=(-u lab:lab-only)
pids=()
cleanup() {
  for p in "${pids[@]:-}"; do [ -n "$p" ] && kill "$p" 2>/dev/null || true; done
  if [ "$mode" = docker ]; then
    docker logs pkup >&2 2>/dev/null || true
    docker rm -f pkup >/dev/null 2>&1 || true
    docker volume rm -f pkupgrade >/dev/null 2>&1 || true
  fi
  rm -rf "$work"
}
trap cleanup EXIT
fail() { echo "e2e-upgrade: FAIL: $*" >&2; exit 1; }

go build -o "$work/fakerelease" ./lab/fakerelease
go build -o "$work/uiproxy" ./lab/uiproxy
export CGO_ENABLED=0
go build -ldflags "-s -w -X main.version=9.9.9" -o "$work/packeteer-new" ./cmd/controller
mkdir -p "$work/bin" "$work/upgrade"
go build -ldflags "-s -w -X main.version=1.0.0" -o "$work/bin/packeteer" ./cmd/controller

"$work/fakerelease" -listen "127.0.0.1:$rport" -binary "$work/packeteer-new" -version 9.9.9 \
  -pubkey-file "$work/pub" >"$work/fakerelease.log" 2>&1 &
pids+=($!)
for _ in $(seq 1 50); do [ -s "$work/pub" ] && break; sleep 0.1; done
[ -s "$work/pub" ] || fail "fakerelease did not start"

if [ "$mode" = docker ]; then updir=""; else updir="  dir: $work/upgrade"; fi
cat >"$work/config.yaml" <<YAML
mode: observe
asn: 64512
router_id: 192.0.2.10
http:
  listen: "127.0.0.1:$port"
providers:
  - name: lab-a
    source_ip: 127.0.0.1
    next_hop: 192.0.2.1
probe: {interval: 30s, timeout: 200ms, packets: 1}
sources:
  - type: static
    config:
      targets: [{prefix: 198.51.100.0/24}]
upgrade:
  enabled: true
  public_key: $(cat "$work/pub")
  repo: example/packeteer
  api_url: http://127.0.0.1:$rport
$updir
YAML
cfg_sum="$(sha256sum "$work/config.yaml" | cut -d' ' -f1)"

if [ "$mode" = docker ]; then
  docker volume create pkupgrade >/dev/null
  docker run -d --name pkup --network host --cap-add NET_RAW --cap-add NET_ADMIN \
    -e PACKETEER_HTTP_USER=lab -e PACKETEER_HTTP_PASSWORD=lab-only \
    -v "$work/config.yaml:/etc/packeteer/config.yaml" -v pkupgrade:/var/lib/packeteer "$image" >/dev/null
else
  PACKETEER_HTTP_USER=lab PACKETEER_HTTP_PASSWORD=lab-only \
    "$work/bin/packeteer" -config "$work/config.yaml" >"$work/pk.log" 2>&1 &
  pk=$!
  pids+=($pk)
fi

ver() { curl -fsS "${auth[@]}" "$base/healthz" 2>/dev/null | jq -r .version; }
wait_ver() { # wait_ver VERSION
  for _ in $(seq 1 90); do
    [ "$(ver || true)" = "$1" ] && return 0
    sleep 1
  done
  fail "version never became $1 (now: $(ver || echo none))"
}
post() { # post PATH BODY -> sets code, body
  local out
  out="$(curl -sS "${auth[@]}" -o "$work/body" -w '%{http_code}' -H 'Content-Type: application/json' -d "$2" "$base$1")"
  code="$out"
  body="$(cat "$work/body")"
}
exe() { # the running executable of the controller process
  if [ "$mode" = docker ]; then docker exec pkup readlink /proc/1/exe; else readlink "/proc/$pk/exe"; fi
}
staged_exists() {
  if [ "$mode" = docker ]; then docker exec pkup test -e /var/lib/packeteer/upgrade/versions/9.9.9/packeteer
  else test -e "$work/upgrade/versions/9.9.9/packeteer"; fi
}
started_at() { if [ "$mode" = docker ]; then docker inspect -f '{{.State.StartedAt}} {{.RestartCount}}' pkup; else echo "$pk"; fi; }

for _ in $(seq 1 60); do ver >/dev/null 2>&1 && break; sleep 1; done
v0="$(ver)" || fail "controller did not start"
[ -n "$v0" ] || fail "no version"
echo "e2e-upgrade: running $v0 ($mode)"
[ "$v0" != 9.9.9 ] || fail "starting version must differ from the release"
s0="$(started_at)"

"$work/uiproxy" -listen "127.0.0.1:$pport" -upstream "$base" -user lab -password lab-only >"$work/proxy.log" 2>&1 &
pids+=($!)
for _ in $(seq 1 30); do curl -fsS "http://127.0.0.1:$pport/healthz" >/dev/null 2>&1 && break; sleep 0.2; done
bash lab/ui-smoke.sh "http://127.0.0.1:$pport/settings.html" 'Version and upgrade' "Running $v0" \
  'Check for updates' 'mode-observe' 'It announces nothing.' --absent 'mode-inject'

# Check lists the release and changes nothing.
post /api/upgrade/check '{}'
[ "$code" = 200 ] || fail "check: $code $body"
echo "$body" | jq -e '.available == true and .latest.tag == "v9.9.9" and .latest.installable == true' >/dev/null || fail "check body: $body"
[ "$(ver)" = "$v0" ] || fail "a check changed the version"

# No confirmation, bad signature, bad checksum: nothing changes.
post /api/upgrade/apply '{"tag":"v9.9.9"}'
[ "$code" = 400 ] || fail "unconfirmed upgrade: $code $body"
for bad in sig sum; do
  curl -fsS -X POST "http://127.0.0.1:$rport/_corrupt?mode=$bad" >/dev/null
  post /api/upgrade/apply '{"tag":"v9.9.9","confirm":true}'
  [ "$code" = 422 ] || fail "bad $bad: $code $body"
  echo "e2e-upgrade: bad $bad refused: $(echo "$body" | jq -r .error)"
  [ "$(ver)" = "$v0" ] || fail "bad $bad changed the version"
  ! staged_exists || fail "bad $bad left a staged binary"
done
curl -fsS -X POST "http://127.0.0.1:$rport/_corrupt?mode=none" >/dev/null

# Upgrade. The same process (or container) now runs the new version.
post /api/upgrade/apply '{"tag":"v9.9.9","confirm":true}'
[ "$code" = 202 ] || fail "upgrade: $code $body"
wait_ver 9.9.9
exe | grep -q 'versions/9.9.9/packeteer' || fail "not running the staged binary: $(exe)"
[ "$(started_at)" = "$s0" ] || fail "the process or container was restarted: $(started_at) vs $s0"
[ "$(sha256sum "$work/config.yaml" | cut -d' ' -f1)" = "$cfg_sum" ] || fail "config file changed"
echo "e2e-upgrade: upgraded to 9.9.9, same process"
bash lab/ui-smoke.sh "http://127.0.0.1:$pport/settings.html" 'Running 9.9.9' 'Roll back to ' 'mode-observe'

# Rollback returns to the first version with the config intact.
post /api/upgrade/rollback '{"confirm":true}'
[ "$code" = 202 ] || fail "rollback: $code $body"
wait_ver "$v0"
exe | grep -q 'versions/9.9.9' && fail "still running the staged binary after rollback"
[ "$(started_at)" = "$s0" ] || fail "rollback restarted the process or container"
[ "$(sha256sum "$work/config.yaml" | cut -d' ' -f1)" = "$cfg_sum" ] || fail "config file changed by rollback"
echo "e2e-upgrade: rolled back to $v0"

# A clean stop still exits 0.
if [ "$mode" = docker ]; then
  docker stop -t 15 pkup >/dev/null
  [ "$(docker inspect -f '{{.State.ExitCode}}' pkup)" = 0 ] || fail "container exit code"
else
  kill -TERM "$pk"
  wait "$pk" || fail "controller exit code $?"
  pids=("${pids[@]/$pk}")
fi
echo "e2e-upgrade: ok"
