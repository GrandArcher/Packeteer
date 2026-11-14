#!/bin/bash
# The one-command demo (#586; scripts/demo.sh) on its own: the FRR edge, two
# simulated transits, and Packeteer in observe with sign-in on.
#
#  1. scripts/demo.sh brings the lab up and prints the dashboard URL and a
#     generated admin password.
#  2. The edge's iBGP session to Packeteer comes up.
#  3. /api/prefixes learns 198.51.100.0/24 from transit-a, /api/improvements
#     recommends transit-b, and /api/overview says mode observe.
#  4. The edge has no route from Packeteer: nothing from neighbor
#     192.0.2.10 and no Packeteer community on the prefix.
#  5. Without credentials the API is refused; the dashboard is on loopback.
#  6. scripts/demo.sh stop removes every container.
set -euo pipefail

root=$(cd "$(dirname "$0")/.." && pwd)
cd "$root"
compose=(docker compose -f lab/docker-compose-demo.yml)
base=http://127.0.0.1:18080
prefix=198.51.100.0/24

trap 'rc=$?; if [ "$rc" -ne 0 ]; then echo "---- lab logs ----"; "${compose[@]}" logs --no-color || true; docker exec pkd-edge vtysh -c "show bgp summary" -c "show bgp ipv4 unicast" || true; fi; ./scripts/demo.sh stop >/dev/null 2>&1 || true; exit "$rc"' EXIT

# The demo prints the generated password; keep it out of the CI log.
unset PACKETEER_DEMO_PASSWORD
out=$(./scripts/demo.sh)
grep -qF "dashboard: $base/" <<<"$out"
password=$(sed -n 's/^  password:  //p' <<<"$out")
if [ "${#password}" -lt 12 ]; then
	echo "demo.sh did not print a generated password" >&2
	exit 1
fi

# api <path>: an authenticated GET; the password never reaches a command line.
api() {
	printf 'user = "admin:%s"\n' "$password" | curl -fsS -K - "$base$1"
}

retry() {
	local n=$1 i
	shift
	for i in $(seq 1 "$n"); do
		if "$@" >/dev/null 2>&1; then
			return 0
		fi
		sleep 2
	done
	"$@"
}

established() {
	local out
	out=$(docker exec pkd-edge vtysh -c 'show bgp neighbors 192.0.2.10') && grep -q 'BGP state = Established' <<<"$out"
}
echo "waiting for the iBGP session"
retry 60 established

learned() {
	api "/api/prefixes?limit=500" | jq -e --arg p "$prefix" \
		'[.prefixes[] | select(.prefix == $p and .in_rib == true and .rib_provider == "transit-a" and .recommended == "transit-b")] | length == 1'
}
echo "waiting for the learned prefix"
retry 60 learned

recommended() {
	api /api/improvements | jq -e --arg p "$prefix" '[.improvements[] | select(.prefix == $p and .provider == "transit-b")] | length == 1'
}
retry 30 recommended
api /api/overview | jq -e '.mode == "observe"' >/dev/null

# Observe announces nothing: the edge has no route from Packeteer. The
# output is captured first so a failed vtysh fails the script instead of
# passing the absence check.
routes=$(docker exec pkd-edge vtysh -c 'show bgp ipv4 unicast neighbors 192.0.2.10 routes')
if grep -qF "$prefix" <<<"$routes"; then
	echo "the edge holds a route from Packeteer in observe" >&2
	exit 1
fi
path=$(docker exec pkd-edge vtysh -c "show bgp ipv4 unicast $prefix")
if grep -qF 64512:666 <<<"$path"; then
	echo "the prefix carries the Packeteer community in observe" >&2
	exit 1
fi
grep -qF '192.0.2.21 from 192.0.2.21' <<<"$path"

# The dashboard is published on loopback only.
[ "$(docker port pkd-packeteer 8080/tcp | head -n1)" = "127.0.0.1:18080" ]

code=$(curl -sS -o /dev/null -w '%{http_code}' "$base/api/prefixes")
if [ "$code" != 401 ]; then
	echo "unauthenticated /api/prefixes returned $code, want 401" >&2
	exit 1
fi

./scripts/demo.sh stop
if [ -n "$(docker ps -aq --filter name=pkd-)" ]; then
	echo "demo containers remain after stop" >&2
	exit 1
fi
echo "demo ok"
