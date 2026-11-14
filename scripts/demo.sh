#!/bin/bash
# One-command demo lab (#586): Packeteer in observe, an FRR edge, and two
# simulated transits on a Docker bridge. Documentation addresses only.
#
#   ./scripts/demo.sh        build, start, and print the dashboard URL and sign-in
#   ./scripts/demo.sh stop   tear the lab down
#
# PACKETEER_DEMO_PASSWORD picks the admin password (12 to 256 characters);
# without it one is generated for this run and printed once.
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
