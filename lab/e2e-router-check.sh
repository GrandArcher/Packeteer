#!/bin/bash
# Read-only router check lab (#626). Lab only: documentation addresses and
# ASNs, the image CI just built, simulated FRR and BIRD routers. For FRR 10.2,
# BIRD 2, and BIRD 3 it proves:
#   1. With the router config `-snippet` prints and an eBGP session that uses
#      its export filter, import_filter passes with the evidence read from
#      the router.
#   2. With an eBGP session whose export policy lacks the reject,
#      import_filter fails with the fix for that session.
#   3. The router's running config is the same before and after, and the
#      socket and config paths appear in no API answer and no log line.
#
#   bash lab/e2e-router-check.sh packeteer:ci
set -euo pipefail

image=${1:?usage: e2e-router-check.sh IMAGE}
root=$(cd "$(dirname "$0")/.." && pwd)
cd "$root"
work=$(mktemp -d)
base=http://127.0.0.1:8080
pw=$(openssl rand -hex 16) # generated per run, never a literal
# The paths the reader gets from the environment. They must never show up.
sock_dir=/run/pk-router-secret

cleanup() {
	rc=$?
	if [ "$rc" -ne 0 ]; then
		for c in packeteer pk-rc-frr-good pk-rc-frr-broken pk-rc-bird; do
			echo "== logs $c" >&2
			docker logs "$c" >&2 2>&1 || true
		done
	fi
	docker rm -f packeteer pk-rc-frr-good pk-rc-frr-broken pk-rc-bird >/dev/null 2>&1 || true
	docker volume rm pk-rc-frr-good pk-rc-frr-broken pk-rc-bird >/dev/null 2>&1 || true
	# FRR chowns the files it mounted, so the runner user cannot always delete them.
	rm -rf "$work" 2>/dev/null || sudo rm -rf "$work"
	exit "$rc"
}
trap cleanup EXIT

cat >"$work/base.yaml" <<'YAML'
mode: observe
asn: 64512
router_id: 192.0.2.10
packeteer_community: "64512:666"
providers:
  - {name: lab-a, source_ip: 127.0.0.1, next_hop: 192.0.2.1}
bgp:
  neighbors:
    - address: 192.0.2.254
YAML
snippet() { docker run --rm -v "$work/base.yaml:/etc/packeteer/config.yaml:ro" "$image" -snippet "$1"; }
snippet frr >"$work/frr-snippet.txt"
snippet bird >"$work/bird-snippet.txt"

# check NAME TYPE STATUS PATTERN... starts the stock image with the router
# check of TYPE, runs the preflight checks, and expects import_filter to have
# STATUS with every PATTERN in its detail and fix.
check() {
	local name=$1 type=$2 status=$3
	shift 3
	{
		cat "$work/base.yaml"
		printf 'preflight:\n  router_check:\n    type: %s\n    config:\n' "$type"
		if [ "$type" = frr ]; then
			printf '      socket_env: PACKETEER_FRR_SOCKET\n'
		else
			printf '      socket_env: PACKETEER_BIRD_SOCKET\n      config_env: PACKETEER_BIRD_CONFIG\n'
		fi
	} >"$work/pk-$name.yaml"
	docker run -d --name packeteer --network host --cap-add NET_RAW --cap-add NET_ADMIN \
		-e PACKETEER_HTTP_USER=lab -e "PACKETEER_HTTP_PASSWORD=$pw" "${router_args[@]}" \
		-v "$work/pk-$name.yaml:/etc/packeteer/config.yaml:ro" "$image" >/dev/null
	for _ in $(seq 1 30); do
		curl -fsS -u "lab:$pw" "$base/healthz" >/dev/null 2>&1 && break
		sleep 1
	done
	curl -fsS -u "lab:$pw" -X POST "$base/api/preflight/run" >"$work/report-$name.json"
	curl -fsS -u "lab:$pw" "$base/api/preflight" >"$work/latest-$name.json"
	jq '.results[] | select(.id == "import_filter")' "$work/report-$name.json" | tee "$work/filter-$name.json"
	jq -e --arg s "$status" '.status == $s' "$work/filter-$name.json" >/dev/null ||
		{ echo "$name: import_filter is not $status" >&2; exit 1; }
	for want in "$@"; do
		jq -r '.detail + "\n" + (.fix // "")' "$work/filter-$name.json" | grep -qF -- "$want" ||
			{ echo "$name: import_filter lacks: $want" >&2; exit 1; }
	done
	docker stop -t 15 packeteer >/dev/null
	docker logs packeteer >"$work/packeteer-$name.log" 2>&1
	docker rm packeteer >/dev/null
	grep -qF 'announce=disabled' "$work/packeteer-$name.log"
	if grep -lF -e "$sock_dir" -e /etc/router "$work/report-$name.json" "$work/latest-$name.json" "$work/packeteer-$name.log"; then
		echo "$name: a router path is in the output above" >&2
		exit 1
	fi
}

echo "== FRR"
frr_conf() { # NAME OUT_MAP EXTRA
	mkdir -p "$work/$1"
	cp lab/interop/frr/daemons lab/interop/frr/vtysh.conf "$work/$1/"
	{
		printf 'frr version 10.2\nfrr defaults traditional\nhostname edge\nlog stdout informational\n!\n'
		cat "$work/frr-snippet.txt"
		printf 'router bgp 64512\n neighbor 192.0.2.20 remote-as 64511\n address-family ipv4 unicast\n  neighbor 192.0.2.20 route-map %s out\n exit-address-family\n!\n%s' "$2" "$3"
	} >"$work/$1/frr.conf"
	chmod -R a+rX "$work/$1"
	docker run -d --name "pk-rc-$1" --privileged \
		-e "FRR_EXPECT=neighbor 192.0.2.10 route-map packeteer-in in;neighbor 192.0.2.20 route-map $2 out" \
		-v "$work/$1:/etc/frr" -v "pk-rc-$1:/var/run/frr" -v "$root/lab/frr-start.sh:/lab/frr-start.sh:ro" \
		--entrypoint /bin/sh quay.io/frrouting/frr:10.2.4 /lab/frr-start.sh >/dev/null
	for _ in $(seq 1 90); do
		docker exec "pk-rc-$1" vtysh -c 'show running-config' >"$work/$1-before.txt" 2>/dev/null &&
			grep -qF "neighbor 192.0.2.20 route-map $2 out" "$work/$1-before.txt" && return 0
		sleep 1
	done
	echo "FRR $1 did not load its config" >&2
	exit 1
}
# Good: the snippet's ebgp-out (deny the community first) on the eBGP session.
frr_conf frr-good ebgp-out $'route-map ebgp-out permit 100\n!\n'
# Broken: the eBGP session's route-map permits without the deny.
frr_conf frr-broken ebgp-open $'route-map ebgp-open permit 100\n!\n'

router_args=(-v "pk-rc-frr-good:$sock_dir" -e "PACKETEER_FRR_SOCKET=$sock_dir/bgpd.vty")
check frr-good frr pass 'Read from the router (frr, read-only commands)' \
	'Import from Packeteer 192.0.2.10 (ipv4 unicast): route-map packeteer-in permits only routes with 64512:666' \
	'Export to eBGP neighbor 192.0.2.20 (ipv4 unicast): route-map ebgp-out denies 64512:666 at entry 10'
router_args=(-v "pk-rc-frr-broken:$sock_dir" -e "PACKETEER_FRR_SOCKET=$sock_dir/bgpd.vty")
check frr-broken frr fail 'route-map ebgp-open entry 100 permits before 64512:666 is denied' \
	'Add a deny entry to route-map ebgp-open with a sequence number below 100 and match community packeteer'
jq -e '.confirmable != true' "$work/filter-frr-broken.json" >/dev/null

for c in frr-good frr-broken; do
	docker exec "pk-rc-$c" vtysh -c 'show running-config' >"$work/$c-after.txt"
	diff "$work/$c-before.txt" "$work/$c-after.txt" || { echo "FRR $c running config changed" >&2; exit 1; }
done
docker rm -f pk-rc-frr-good pk-rc-frr-broken >/dev/null

echo "== BIRD"
for bird in bird2 bird3; do
	docker build -q -t "pk-rc-$bird" --build-arg "BIRD=$bird" lab/interop/bird >/dev/null
	for kind in good broken; do
		out=ebgp_out
		extra=''
		if [ "$kind" = broken ]; then
			out=ebgp_open
			extra=$'filter ebgp_open {\n\taccept;\n}\n'
		fi
		{
			printf 'router id 192.0.2.254;\nprotocol device {}\n'
			cat "$work/bird-snippet.txt"
			printf '\n%s\nprotocol bgp transit {\n\tlocal 192.0.2.254 as 64512;\n\tneighbor 192.0.2.20 as 64511;\n\tipv4 {\n\t\timport all;\n\t\texport filter %s;\n\t};\n}\n' "$extra" "$out"
		} >"$work/bird-$kind.conf"
		chmod a+r "$work/bird-$kind.conf"
		docker run --rm -v "$work/bird-$kind.conf:/etc/bird/rc.conf:ro" --entrypoint bird "pk-rc-$bird" -p -c /etc/bird/rc.conf
		docker volume rm pk-rc-bird >/dev/null 2>&1 || true
		docker run -d --name pk-rc-bird -e BIRD_CONF=rc.conf -v "$work/bird-$kind.conf:/etc/bird/rc.conf:ro" \
			-v "pk-rc-bird:/run/bird" "pk-rc-$bird" >/dev/null
		for _ in $(seq 1 30); do
			docker exec pk-rc-bird birdc -s /run/bird/bird.ctl show protocols >"$work/bird-protocols.txt" 2>/dev/null &&
				grep -q '^transit ' "$work/bird-protocols.txt" && break
			sleep 1
		done
		docker exec pk-rc-bird birdc -s /run/bird/bird.ctl show status | grep -v 'server time' >"$work/bird-before.txt"
		router_args=(-v "pk-rc-bird:$sock_dir" -e "PACKETEER_BIRD_SOCKET=$sock_dir/bird.ctl"
			-v "$work/bird-$kind.conf:/etc/router/bird.conf:ro" -e PACKETEER_BIRD_CONFIG=/etc/router/bird.conf)
		if [ "$kind" = good ]; then
			check "$bird-good" bird pass 'Read from the router (bird, read-only commands)' \
				'Import from Packeteer (protocol packeteer, ipv4): filter packeteer_in accepts only routes with 64512:666' \
				'Export to eBGP protocol transit (ipv4): filter ebgp_out rejects 64512:666 at statement 1'
		else
			check "$bird-broken" bird fail 'filter ebgp_open accepts at statement 1 before 64512:666 is rejected' \
				'Make the first statement of filter ebgp_open: if (64512, 666) ~ bgp_community then reject;'
		fi
		docker exec pk-rc-bird birdc -s /run/bird/bird.ctl show status | grep -v 'server time' >"$work/bird-after.txt"
		diff "$work/bird-before.txt" "$work/bird-after.txt" || { echo "$bird $kind: BIRD was reconfigured" >&2; exit 1; }
		docker rm -f pk-rc-bird >/dev/null
	done
done
echo "router check lab: ok"
