#!/bin/bash
# First-run GUI lab (#587). Lab only: documentation prefixes and ASNs, the image
# CI just built, simulated FRR. A stock image on the unchanged
# config.example.yaml is taken to a working observe setup by clicking through
# the dashboard (lab/e2e-gui/firstrun.mjs, headless Chrome), inside 15 minutes:
#
#   1. sign in with the generated password, choose a new one
#   2. the setup wizard: ASN, router, edge, providers, probe target, history
#   3. copy the router config the Settings page writes for FRR; the script
#      pastes it into the lab edge
#   4. restart the container (providers apply on restart), sign in again
#   5. the Overview checklist says setup is not complete; Settings > Host
#      policy routing shows the plan, applies it after a confirm, and verifies
#   6. the Overview checklist says "Setup complete, still observe"
#
# It fails when the walk takes 15 minutes or more, when a step needs the YAML
# editor, when the config file differs from what the wizard saved, when inject
# is on, when the session is not Established or no prefix is learned, when a
# provider's probes do not leave through its next hop, or when the edge
# receives a route from Packeteer.
#
#   bash lab/e2e-firstrun.sh packeteer:ci
#
# FIRSTRUN_OUT names a directory for the router config, the saved hash, and
# failure screenshots (default: a temporary directory).
set -euo pipefail

image=${1:?usage: e2e-firstrun.sh IMAGE}
root=$(cd "$(dirname "$0")/.." && pwd)
cd "$root"
export PACKETEER_IMAGE=$image
compose=(docker compose -f lab/docker-compose-firstrun.yml)
budget=900
work=$(mktemp -d)
out=${FIRSTRUN_OUT:-$work/out}
mkdir -p "$out"
base=http://127.0.0.1:18587
user=admin
pk=pkfr-packeteer
newpw=$(openssl rand -hex 16) # generated per run, never a literal

cleanup() {
	rc=$?
	if [ "$rc" -ne 0 ]; then
		echo "---- packeteer log ----" >&2
		docker logs "$pk" 2>&1 | tail -n 80 >&2 || true
		echo "---- edge ----" >&2
		docker exec pkfr-edge vtysh -c 'show bgp summary' >&2 || true
		docker exec pkfr-edge vtysh -c 'show running-config' >&2 || true
		docker exec pkfr-netns ip rule show >&2 || true
	fi
	docker rm -f "$pk" >/dev/null 2>&1 || true
	"${compose[@]}" down -v --remove-orphans >/dev/null 2>&1 || true
	docker volume rm pkfr-data >/dev/null 2>&1 || true
	# FRR chowns the files it mounted, so the runner user cannot always delete them.
	if [ -z "${FIRSTRUN_OUT:-}" ]; then rm -rf "$work" 2>/dev/null || sudo rm -rf "$work"; else rm -rf "$work/pk" 2>/dev/null || sudo rm -rf "$work/pk"; fi
	exit "$rc"
}
trap cleanup EXIT

api() { curl -fsS -u "$user:$newpw" "$@"; }
vty() { docker exec pkfr-edge vtysh "$@"; }
fail() { echo "FAIL: $*" >&2; exit 1; }

echo "== lab: edge, two transits, and the network namespace"
"${compose[@]}" up -d
for t in a b; do
	for _ in $(seq 1 90); do
		docker exec "pkfr-transit-$t" vtysh -c 'show running-config' 2>/dev/null | grep -q 'network 198.51.100.0/24' && break
		sleep 1
	done
	# The pinned host the wizard is given, answered by each transit.
	docker exec "pkfr-transit-$t" ip addr add 198.51.100.1/32 dev lo
done
for n in 21 22; do
	for _ in $(seq 1 90); do
		vty -c "show bgp neighbors 192.0.2.$n" 2>/dev/null | grep -q 'BGP state = Established' && break
		sleep 1
	done
	vty -c "show bgp neighbors 192.0.2.$n" | grep -q 'BGP state = Established' || fail "the edge has no session to 192.0.2.$n"
done
# The probe sources are addresses of the host Packeteer runs on. The lab has
# no way out, so a probe that does not leave through a provider has no route.
docker exec pkfr-netns ip addr add 192.0.2.11/24 dev eth0
docker exec pkfr-netns ip addr add 192.0.2.12/24 dev eth0
docker exec pkfr-netns ip route del default

echo "== 1. stock image, unchanged example config"
mkdir -p "$work/pk"
cp config.example.yaml "$work/pk/config.yaml"
chmod 0666 "$work/pk/config.yaml"
start=$(date +%s)
docker run -d --name "$pk" --network container:pkfr-netns --cap-add NET_RAW --cap-add NET_ADMIN \
	-e PACKETEER_HTTP_LISTEN=0.0.0.0:8080 \
	-v "$work/pk/config.yaml:/etc/packeteer/config.yaml" -v pkfr-data:/var/lib/packeteer "$image" >/dev/null
for _ in $(seq 1 60); do curl -fsS "$base/healthz" >/dev/null 2>&1 && break; sleep 1; done
curl -fsS "$base/healthz" >/dev/null || fail "Packeteer did not answer on $base"
pwfile=/var/lib/packeteer/first-run-admin-password
for _ in $(seq 1 30); do docker exec "$pk" test -s "$pwfile" && break; sleep 1; done
firstpw=$(docker exec "$pk" sed -n 's/^password: //p' "$pwfile")
test -n "$firstpw" || fail "no generated admin password"
cmp -s "$work/pk/config.yaml" config.example.yaml || fail "the config differs from the example before the walk"
sum_example=$(sha256sum "$work/pk/config.yaml" | cut -d' ' -f1)

echo "== 2. browser: first sign-in, password change, wizard, router config, save"
export PK_URL=$base PK_USER=$user PK_FIRST_PASSWORD=$firstpw PK_NEW_PASSWORD=$newpw PK_OUT=$out
npm ci --prefix lab/e2e-gui --ignore-scripts --no-audit --no-fund >/dev/null
node lab/e2e-gui/firstrun.mjs setup
saved=$(jq -r .sha256 "$out/saved.json")
sum_saved=$(sha256sum "$work/pk/config.yaml" | cut -d' ' -f1)
test "$sum_saved" != "$sum_example" || fail "the wizard did not change the config file"
test "$sum_saved" = "$saved" || fail "the file on disk is not what the wizard saved"
grep -q '^mode: observe' "$work/pk/config.yaml" || fail "the saved config is not observe"
if grep -Eq '^[[:space:]]*(mode:[[:space:]]*inject|announcer:)' "$work/pk/config.yaml"; then fail "the saved config turns inject on"; fi
grep -qF 'type: sqlite' "$work/pk/config.yaml" || fail "the saved config has no sqlite history"
grep -qF '/var/lib/packeteer/packeteer.db' "$work/pk/config.yaml" || fail "history is not under /var/lib/packeteer"

echo "== 3. the router config from the page goes into the edge"
args=()
while IFS= read -r line; do
	line=${line#"${line%%[![:space:]]*}"}
	case $line in '' | '!'*) continue ;; esac
	args+=(-c "$line")
done <"$out/router-frr.txt"
conf=$(vty -c 'configure terminal' "${args[@]}" -c end 2>&1) || { echo "$conf" >&2; fail "the edge refused the router config"; }
if grep -q '^%' <<<"$conf"; then echo "$conf" >&2; fail "the edge reported an error on the router config"; fi
run=$(vty -c 'show running-config')
for want in 'neighbor 192.0.2.10 remote-as 64512' 'neighbor 192.0.2.10 route-map packeteer-in in' 'neighbor 192.0.2.10 graceful-restart-disable' 'route-map ebgp-out deny 10'; do
	grep -qF -- "$want" <<<"$run" || fail "the edge lacks: $want"
done

echo "== 4. restart: the providers apply on restart"
docker restart -t 30 "$pk" >/dev/null
for _ in $(seq 1 60); do api "$base/api/me" >/dev/null 2>&1 && break; sleep 1; done
api "$base/api/me" | jq -e --arg u "$user" '.user == $u' >/dev/null || fail "cannot sign in with the new password after the restart"

echo "== 5. browser: checklist incomplete, host policy routing, setup complete"
left=$((budget - ($(date +%s) - start)))
test "$left" -gt 0 || fail "the walk is already past $budget s"
PK_COMPLETE_MS=$((left * 1000)) node lab/e2e-gui/firstrun.mjs finish
elapsed=$(($(date +%s) - start))
echo "walk time: ${elapsed}s (limit ${budget}s)"
test "$elapsed" -lt "$budget" || fail "the walk took ${elapsed}s, limit ${budget}s"

echo "== 6. what the walk must have produced"
test "$(sha256sum "$work/pk/config.yaml" | cut -d' ' -f1)" = "$saved" || fail "the config file changed after the wizard saved it"
api "$base/api/overview" >"$work/overview.json"
jq -e '.mode == "observe" and .setup_complete == true' "$work/overview.json" >/dev/null || { cat "$work/overview.json" >&2; fail "the Overview is not set up and observe"; }
jq -e '.bgp.peers == 1 and .bgp.established == 1 and .bgp.learned >= 1' "$work/overview.json" >/dev/null || { cat "$work/overview.json" >&2; fail "the session is not Established with a learned prefix"; }
api "$base/api/prefixes?limit=500" | jq -e '[.prefixes[] | select(.prefix == "198.51.100.0/24" and .in_rib == true)] | length == 1' >/dev/null || fail "198.51.100.0/24 is not in the learned RIB"
vty -c 'show bgp neighbors 192.0.2.10' | grep -q 'BGP state = Established' || fail "the edge does not see the session as Established"
for p in "192.0.2.11 192.0.2.21" "192.0.2.12 192.0.2.22"; do
	set -- $p
	docker exec pkfr-netns ip route get 203.0.113.254 from "$1" | grep -qF "via $2" || fail "probes from $1 do not leave through $2"
done
docker exec pkfr-netns ip rule show | grep -c 'lookup 100[12]' | grep -qx 2 || fail "expected the two Packeteer rules"
api "$base/api/preflight" | jq -e '.report.results[] | select(.id == "probe_egress") | .status == "pass"' >/dev/null || fail "preflight probe_egress is not passing"
if docker logs "$pk" 2>&1 | grep -q 'mode=inject'; then fail "Packeteer logged mode=inject"; fi
docker logs "$pk" 2>&1 | grep -q 'announce=disabled' || fail "Packeteer does not say announce=disabled"
# Nothing came back from Packeteer: no route carries its community, and the
# edge received no prefix over the session.
if [ -n "$(vty -c 'show bgp ipv4 unicast community 64512:666 json' | jq -r '.routes // {} | keys[]')" ]; then fail "a route with the Packeteer community is on the edge"; fi
vty -c 'show bgp ipv4 unicast summary json' | jq -e '(.ipv4Unicast.peers // .peers)["192.0.2.10"].pfxRcd == 0' >/dev/null || fail "the edge received a prefix from Packeteer"
echo "first-run lab: ok (${elapsed}s)"
