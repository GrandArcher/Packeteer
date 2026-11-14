#!/bin/bash
# One-command demo lab (#586): Packeteer in observe, an FRR edge, and two
# simulated transits on a Docker bridge. Documentation addresses only.
#
#   ./scripts/demo.sh        build, start, and print the dashboard URL and sign-in
#   ./scripts/demo.sh stop   tear the lab down
#
# PACKETEER_DEMO_PASSWORD picks the admin password (12 to 256 characters);
# without it one is generated for this run and printed once.
#
# Before it builds anything, "up" checks the host and stops with a one-line
# fix when Docker is not Docker Engine on Linux, when 127.0.0.1:18080 is
# taken, or when another Docker network already uses 192.0.2.0/24.
set -euo pipefail

root=$(cd "$(dirname "$0")/.." && pwd)
compose=(docker compose -f "$root/lab/docker-compose-demo.yml")
url=http://127.0.0.1:18080/

case "${1:-up}" in
stop)
	"${compose[@]}" down -v --remove-orphans
	exit 0
	;;
up) ;;
*)
	echo "usage: scripts/demo.sh [up|stop]" >&2
	exit 2
	;;
esac

fail() {
	echo "demo.sh: $1" >&2
	exit 1
}

preflight() {
	[ "$(uname -s)" = Linux ] || fail "Linux is required; the lab needs Docker Engine on Linux. Fix: run it on a Linux host."
	command -v docker >/dev/null 2>&1 || fail "docker is not installed. Fix: install Docker Engine, https://docs.docker.com/engine/install/"
	docker info >/dev/null 2>&1 || fail "cannot talk to the Docker daemon. Fix: start Docker and add your user to the docker group, or use sudo."
	case "$(docker info --format '{{.OperatingSystem}}' 2>/dev/null)" in
	*"Docker Desktop"*) fail "this is Docker Desktop, not Docker Engine on Linux. Fix: run it on a Linux host with Docker Engine." ;;
	esac
	docker compose version >/dev/null 2>&1 || fail "the Docker Compose plugin is missing. Fix: install docker-compose-plugin, so that 'docker compose version' works."
	# A lab that is already up is a no-op for compose; do not call it a clash.
	if [ -n "$(docker ps -q --filter name='^pkd-packeteer$')" ]; then
		return 0
	fi
	if (exec 3<>/dev/tcp/127.0.0.1/18080) 2>/dev/null; then
		fail "127.0.0.1:18080 is already in use. Fix: stop what listens there (ss -ltnp 'sport = :18080'), then rerun."
	fi
	local ids net
	ids=$(docker network ls -q)
	if [ -n "$ids" ]; then
		# shellcheck disable=SC2086
		net=$(docker network inspect --format '{{.Name}} {{range .IPAM.Config}}{{.Subnet}} {{end}}' $ids | awk '/(^| )192\.0\.2\.0\/24( |$)/ {print $1; exit}')
		# The demo's own network survives `docker stop` or a reboot; `up` reuses it.
		if [ -n "$net" ] && [ "$net" != packeteer-demo_lab ]; then
			fail "the Docker network $net already uses 192.0.2.0/24. Fix: stop the lab that owns it (the walkthrough: docker compose -f lab/docker-compose-walkthrough.yml down -v), or docker network rm $net."
		fi
	fi
}

preflight

generated=no
if [ -z "${PACKETEER_DEMO_PASSWORD:-}" ]; then
	PACKETEER_DEMO_PASSWORD=$(head -c 18 /dev/urandom | od -An -tx1 | tr -d ' \n')
	generated=yes
fi
if [ "${#PACKETEER_DEMO_PASSWORD}" -lt 12 ] || [ "${#PACKETEER_DEMO_PASSWORD}" -gt 256 ]; then
	echo "PACKETEER_DEMO_PASSWORD must be 12 to 256 characters" >&2
	exit 2
fi
export PACKETEER_DEMO_PASSWORD

"${compose[@]}" up -d --build

# /healthz is public; sign-in is not needed to know the dashboard is up.
for _ in $(seq 1 60); do
	if curl -fsS -o /dev/null "${url}healthz" 2>/dev/null; then
		break
	fi
	sleep 1
done
if ! curl -fsS -o /dev/null "${url}healthz"; then
	echo "the dashboard did not come up; see: docker compose -f lab/docker-compose-demo.yml logs" >&2
	exit 1
fi

echo
echo "Packeteer demo is up (mode: observe; nothing is announced)."
echo "  dashboard: $url"
echo "  user:      admin"
if [ "$generated" = yes ]; then
	echo "  password:  $PACKETEER_DEMO_PASSWORD"
else
	echo "  password:  the value of PACKETEER_DEMO_PASSWORD"
fi
echo "The iBGP session takes about 30 seconds; then Overview shows 198.51.100.0/24"
echo "on transit-a with transit-b recommended."
echo "Stop and remove the lab: ./scripts/demo.sh stop"
