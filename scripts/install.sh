#!/bin/sh
# Install Packeteer in observe mode with one command (#221), then print where
# to sign in. Needs Linux, Docker, and curl. Nothing here turns inject on:
# the config is the shipped observe example, and the setup wizard in the web
# UI takes it from there.
#
#   sh install.sh                      # into ./packeteer, image from main
#   PACKETEER_VERSION=0.8.0 sh install.sh   # a release (config from its tag)
#
# PACKETEER_DIR       where config.yaml and plugins/ live (default ./packeteer)
# PACKETEER_VERSION   an image tag; "edge" (default) is the build from main
# PACKETEER_ADMIN_PASSWORD  the first admin's password (default: generated)
# PACKETEER_RAW_BASE  where config.example.yaml is downloaded from
set -eu

dir=${PACKETEER_DIR:-packeteer}
version=${PACKETEER_VERSION:-edge}
image=${PACKETEER_IMAGE:-ghcr.io/grandarcher/packeteer:$version}
if [ "$version" = edge ]; then
	ref=main
else
	ref=v$version
fi
raw=${PACKETEER_RAW_BASE:-https://raw.githubusercontent.com/GrandArcher/Packeteer/$ref}
url=http://127.0.0.1:8080

die() {
	echo "install: $*" >&2
	exit 1
}

[ "$(uname -s)" = Linux ] || die "Linux is required: Packeteer needs host networking, which Docker Desktop does not give you."
command -v docker >/dev/null 2>&1 || die "Docker is required. Install Docker Engine first: https://docs.docker.com/engine/install/"
command -v curl >/dev/null 2>&1 || die "curl is required."
docker info >/dev/null 2>&1 || die "cannot talk to the Docker daemon. Is it running, and may you use it (docker group or sudo)?"
if [ -n "$(docker ps -a --filter name='^packeteer$' --format '{{.Names}}')" ]; then
	die "a container named packeteer exists. Stop and remove it first (docker stop -t 30 packeteer && docker rm packeteer), or keep it and skip this script."
fi

mkdir -p "$dir/plugins"
dir=$(cd "$dir" && pwd)
kept=0
if [ -e "$dir/config.yaml" ]; then
	kept=1
	echo "install: keeping the existing $dir/config.yaml"
else
	curl -fsSLo "$dir/config.yaml" "$raw/config.example.yaml" || die "cannot download $raw/config.example.yaml"
fi

echo "install: checking the config"
docker run --rm -v "$dir/config.yaml:/etc/packeteer/config.yaml:ro" "$image" -check || die "the config did not pass -check; Packeteer was not started."

# The config is mounted writable so the setup wizard can save it.
set -- docker run -d --name packeteer --network host \
	--cap-add NET_RAW --cap-add NET_ADMIN --restart unless-stopped \
	-v "$dir/config.yaml:/etc/packeteer/config.yaml" \
	-v "$dir/plugins:/etc/packeteer/plugins:ro" \
	-v packeteer-data:/var/lib/packeteer
if [ -n "${PACKETEER_ADMIN_PASSWORD:-}" ]; then
	set -- "$@" -e PACKETEER_ADMIN_PASSWORD
fi
"$@" "$image" >/dev/null || die "docker run failed."

echo "install: waiting for Packeteer"
i=0
until curl -fsS "$url/healthz" >/dev/null 2>&1; do
	i=$((i + 1))
	[ "$i" -le 60 ] || die "Packeteer did not answer on $url. See: docker logs packeteer"
	sleep 1
done

echo
if [ "$kept" = 1 ]; then
	echo "Packeteer is running with your existing config. Check its mode: it announces routes only when it says mode: inject."
else
	echo "Packeteer is running in observe mode. It announces nothing."
fi
echo "Open:     $url/settings.html#wizard"
if [ -n "${PACKETEER_ADMIN_PASSWORD:-}" ]; then
	echo "Sign in:  admin, with the password you set in PACKETEER_ADMIN_PASSWORD."
else
	echo "Sign in:  admin, with the generated password below (you choose a new one at first sign-in)."
	docker logs packeteer 2>&1 | grep 'generated admin password' || true
fi
echo "Next:     the wizard asks for your AS number, router, and providers; the preflight checks"
echo "          there decide when injection can be turned on. Stop with: docker stop -t 30 packeteer"
if [ -n "${DISPLAY:-}${WAYLAND_DISPLAY:-}" ] && command -v xdg-open >/dev/null 2>&1; then
	xdg-open "$url/settings.html#wizard" >/dev/null 2>&1 || true
fi
