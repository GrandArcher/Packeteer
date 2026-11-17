#!/bin/bash
# One-command demo lab (#586): Packeteer in observe, an FRR edge, and two
# simulated transits on a Docker bridge. Documentation addresses only.
#
#   ./scripts/demo.sh        build, start, and print the dashboard URL and sign-in
#   ./scripts/demo.sh stop   tear the lab down
#   ./scripts/demo.sh --report  run the whole demo, remove the lab, and print
#                            an address-free pass/fail block for a field report
#
# PACKETEER_DEMO_PASSWORD picks the admin password (12 to 256 characters);
# without it one is generated for this run and printed once.
#
# Before it builds anything, "up" checks the host and stops with a one-line
# fix when the shell is a native Windows one, Docker is missing, down, or in
# Windows containers mode, the Compose plugin is missing, 127.0.0.1:18080 is
# taken, or another Docker network already uses 192.0.2.0/24. Docker Desktop
# (macOS, or Windows through WSL2) is allowed with a one-line note; CI runs
# only Docker Engine on Linux. See docs/demo.md#platforms.
set -euo pipefail

root=$(cd "$(dirname "$0")/.." && pwd)
compose=(docker compose -f "$root/lab/docker-compose-demo.yml")
url=http://127.0.0.1:18080/

mode=${1:-up}
case "$mode" in
stop)
	"${compose[@]}" down -v --remove-orphans
	exit 0
	;;
up | --report) ;;
*)
	echo "usage: scripts/demo.sh [up|stop|--report]" >&2
	exit 2
	;;
esac

fail() {
	echo "demo.sh: $1" >&2
	exit 1
}

# Each pf_ check exits through fail; --report runs them one by one.
pf_shell() {
	case "$(uname -s)" in
	Linux | Darwin) ;;
	MINGW* | MSYS* | CYGWIN*) fail "this is a native Windows shell. Fix: run it from a WSL2 terminal with Docker Desktop's WSL integration, see docs/demo.md#platforms." ;;
	*) fail "$(uname -s) is not supported. Fix: run it on Linux with Docker Engine, or on macOS or Windows (WSL2) with Docker Desktop, see docs/demo.md#platforms." ;;
	esac
}

pf_docker() {
	command -v docker >/dev/null 2>&1 || fail "docker is not installed. Fix: install Docker Engine (Linux), https://docs.docker.com/engine/install/, or Docker Desktop (macOS, Windows)."
}

pf_daemon() {
	docker info >/dev/null 2>&1 || fail "cannot talk to the Docker daemon. Fix: start Docker (Docker Desktop, or the engine and your user in the docker group, or sudo)."
}

pf_linux_containers() {
	[ "$(docker info --format '{{.OSType}}' 2>/dev/null)" = linux ] || fail "Docker is not running Linux containers. Fix: switch Docker Desktop to Linux containers."
}

pf_compose() {
	docker compose version >/dev/null 2>&1 || fail "the Docker Compose plugin is missing. Fix: install docker-compose-plugin (Docker Desktop includes it), so that 'docker compose version' works."
}

is_desktop() {
	[ "$(uname -s)" = Darwin ] && return 0
	case "$(docker info --format '{{.OperatingSystem}}' 2>/dev/null)" in
	*"Docker Desktop"*) return 0 ;;
	esac
	return 1
}

# A lab that is already up is a no-op for compose; do not call it a clash.
lab_running() {
	[ -n "$(docker ps -q --filter name='^pkd-packeteer$')" ]
}

# --report only: a lab that is already up would be reused, then removed.
pf_no_lab() {
	lab_running && fail "the demo lab is already up. Fix: ./scripts/demo.sh stop, then rerun."
	return 0
}

pf_port() {
	lab_running && return 0
	if (exec 3<>/dev/tcp/127.0.0.1/18080) 2>/dev/null; then
		fail "127.0.0.1:18080 is already in use. Fix: stop what listens there (ss -ltnp 'sport = :18080', or lsof -iTCP:18080 -sTCP:LISTEN on macOS), then rerun."
	fi
}

pf_network() {
	lab_running && return 0
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

preflight() {
	pf_shell
	pf_docker
	pf_daemon
	pf_linux_containers
	pf_compose
	if is_desktop; then
		echo "demo.sh: note: Docker Desktop and Docker on macOS are not run in CI and are not verified; if the demo fails, see docs/demo.md#platforms." >&2
	fi
	pf_port
	pf_network
}

generated=no
password_setup() {
	if [ -z "${PACKETEER_DEMO_PASSWORD:-}" ]; then
		PACKETEER_DEMO_PASSWORD=$(head -c 18 /dev/urandom | od -An -tx1 | tr -d ' \n')
		generated=yes
	fi
	if [ "${#PACKETEER_DEMO_PASSWORD}" -lt 12 ] || [ "${#PACKETEER_DEMO_PASSWORD}" -gt 256 ]; then
		echo "PACKETEER_DEMO_PASSWORD must be 12 to 256 characters" >&2
		exit 2
	fi
	export PACKETEER_DEMO_PASSWORD
}

# wait_for <tries> <command...>: poll every 2 seconds.
wait_for() {
	local n=$1 i
	shift
	for i in $(seq 1 "$n"); do
		if "$@" >/dev/null 2>&1; then
			return 0
		fi
		sleep 2
	done
	return 1
}

# /healthz is public; sign-in is not needed to know the dashboard is up.
healthy() {
	curl -fsS -o /dev/null "${url}healthz"
}

started=no

# --report: run the whole demo, then print one block to paste into a field
# report. The block names each check as pass or FAIL and carries no address,
# prefix, AS number, host name, or credential: the checks use fixed labels, and
# the few values read from the host go through scrub.
scrub() {
	printf '%s' "$1" | tr -cd 'A-Za-z0-9 ._()+-' | sed -E 's/([0-9]+\.[0-9]+\.[0-9]+)\.[0-9.]+/\1/g' | cut -c1-80
}

os_label() {
	case "$(uname -s)" in
	Darwin) echo "macOS $(sw_vers -productVersion 2>/dev/null) $(uname -m)" ;;
	Linux)
		local name
		name=$(. /etc/os-release 2>/dev/null && echo "${PRETTY_NAME:-}")
		if grep -qi microsoft /proc/version 2>/dev/null; then
			name="${name:-Linux} under WSL"
		fi
		echo "${name:-Linux} $(uname -m)"
		;;
	*) uname -s ;;
	esac
}

api_has() {
	local out
	out=$(printf 'user = "admin:%s"\n' "$PACKETEER_DEMO_PASSWORD" | curl -fsS -K - "${url%/}$1") || return 1
	shift
	local want
	for want in "$@"; do
		grep -qF -- "$want" <<<"$out" || return 1
	done
}

w_up() { "${compose[@]}" up -d --build >&2; }
w_signin() { api_has /api/overview '"mode":"observe"'; }
w_unauth() { [ "$(curl -sS -o /dev/null -w '%{http_code}' "${url}api/prefixes")" = 401 ]; }
w_loopback() { [ "$(docker port pkd-packeteer 8080/tcp | head -n1)" = "127.0.0.1:18080" ]; }
w_ibgp() {
	local out
	out=$(docker exec pkd-edge vtysh -c 'show bgp neighbors 192.0.2.10') && grep -q 'BGP state = Established' <<<"$out"
}
w_prefix() {
	api_has "/api/prefixes?limit=500" '"prefix":"198.51.100.0/24"' '"in_rib":true' '"rib_provider":"transit-a"' '"recommended":"transit-b"'
}
w_improvement() { api_has /api/improvements '"provider":"transit-b"'; }
# The output is captured first so a failed vtysh fails the check instead of
# passing the absence test.
w_noroute() {
	local routes path
	routes=$(docker exec pkd-edge vtysh -c 'show bgp ipv4 unicast neighbors 192.0.2.10 routes') || return 1
	path=$(docker exec pkd-edge vtysh -c 'show bgp ipv4 unicast 198.51.100.0/24') || return 1
	! grep -qF 198.51.100.0/24 <<<"$routes" && ! grep -qF 64512:666 <<<"$path" && grep -qF '192.0.2.21 from 192.0.2.21' <<<"$path"
}
w_stop() {
	"${compose[@]}" down -v --remove-orphans >&2 && [ -z "$(docker ps -aq --filter name=pkd-)" ]
}

report() {
	local body="" total=0 bad=0 skip=no
	echo "demo.sh: --report runs the whole demo, then removes the lab; it takes a few minutes." >&2
	password_setup
	trap '[ "$started" = yes ] && "${compose[@]}" down -v --remove-orphans >/dev/null 2>&1' EXIT

	# check <label> <command...>: pass, FAIL, or "not run" after a blocking failure.
	check() {
		local label=$1 status=pass
		shift
		if [ "$skip" = yes ]; then
			status="not run"
		elif ! ("$@") >&2; then
			status=FAIL
		fi
		total=$((total + 1))
		[ "$status" = pass ] || bad=$((bad + 1))
		body+=$(printf '  [%s] %s' "$status" "$label")$'\n'
		[ "$status" != FAIL ]
	}

	body+=$'Preflight:\n'
	check "the shell is not a native Windows one" pf_shell || skip=yes
	check "Docker is installed" pf_docker || skip=yes
	check "the Docker daemon answers" pf_daemon || skip=yes
	check "Docker runs Linux containers" pf_linux_containers || skip=yes
	check "the Docker Compose plugin is present" pf_compose || skip=yes
	local pre=$bad
	check "no demo lab is already running" pf_no_lab || true
	check "the dashboard port is free" pf_port || true
	check "the lab bridge is free" pf_network || true
	[ "$bad" -eq "$pre" ] || skip=yes

	local desktop=unknown engine=unknown platform=unknown compose_v=unknown
	if docker info >/dev/null 2>&1; then
		if is_desktop; then desktop=yes; else desktop=no; fi
		platform=$(scrub "$(docker version --format '{{.Server.Platform.Name}}' 2>/dev/null)")
		engine=$(scrub "$(docker version --format '{{.Server.Version}}' 2>/dev/null)")
		compose_v=$(scrub "$(docker compose version --short 2>/dev/null)")
	fi

	body+=$'Walkthrough:\n'
	if [ "$skip" = no ]; then
		started=yes
	fi
	check "the lab builds and starts" w_up || skip=yes
	check "the dashboard answers" wait_for 30 healthy || skip=yes
	check "sign-in works and the mode is observe" w_signin || true
	check "the API refuses a request without credentials" w_unauth || true
	check "the dashboard is published on loopback only" w_loopback || true
	check "the edge's iBGP session to Packeteer comes up" wait_for 60 w_ibgp || skip=yes
	check "the learned prefix is in the RIB on the first transit and the second is recommended" wait_for 60 w_prefix || true
	check "an improvement recommends the second transit" wait_for 30 w_improvement || true
	check "the edge holds no route from Packeteer and the prefix has no Packeteer community" w_noroute || true
	if [ "$started" = yes ]; then
		skip=no
	fi
	check "stop removes every container" w_stop || true
	started=no

	echo "Packeteer demo report (scripts/demo.sh --report)"
	echo "OS: $(scrub "$(os_label)")"
	echo "Docker: $platform"
	echo "Docker engine: $engine"
	echo "Docker Compose: $compose_v"
	echo "Docker Desktop: $desktop"
	printf '%s' "$body"
	if [ "$bad" -eq 0 ]; then
		echo "Result: passed ($total of $total checks)"
		return 0
	fi
	echo "Result: FAILED ($bad of $total checks not passed)"
	return 1
}

if [ "$mode" = --report ]; then
	report
	exit $?
fi

preflight
password_setup

"${compose[@]}" up -d --build

if ! wait_for 30 healthy; then
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
