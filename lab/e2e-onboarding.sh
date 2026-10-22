#!/bin/bash
# Onboarding lab (#221). Lab only: documentation prefixes and ASNs, the image
# CI just built, simulated FRR and BIRD. It proves, in order:
#   1. scripts/install.sh brings the stock image up in observe mode.
#   2. On that fresh install every preflight check that cannot pass yet is
#      blocking and carries its fix text, and the guided inject step is
#      refused until the checks pass.
#   3. The FRR and BIRD router config that `-snippet` prints for the interop
#      lab's Packeteer config is accepted by real FRR and BIRD daemons.
#   4. `-pbr linux -apply` shows a diff, changes nothing without -yes, applies
#      the rules in a scratch network, makes the kernel route each provider's
#      source through its next hop, and removes them when a provider goes.
#
#   bash lab/e2e-onboarding.sh packeteer:ci
set -euo pipefail

image=${1:?usage: e2e-onboarding.sh IMAGE}
root=$(cd "$(dirname "$0")/.." && pwd)
cd "$root"
work=$(mktemp -d)
base=http://127.0.0.1:8080
pw=$(openssl rand -hex 16) # generated per run, never a literal

cleanup() {
	rc=$?
	if [ "$rc" -ne 0 ]; then
		docker logs packeteer >&2 2>&1 || true
		docker logs pk-snip-frr >&2 2>&1 || true
	fi
	docker rm -f packeteer pk-snip-frr pk-snip-bird pk-pbr >/dev/null 2>&1 || true
	docker volume rm packeteer-data >/dev/null 2>&1 || true
	docker network rm pk-pbr-net >/dev/null 2>&1 || true
	# FRR chowns the files it mounted, so the runner user cannot always delete them.
	rm -rf "$work" 2>/dev/null || sudo rm -rf "$work"
	exit "$rc"
}
trap cleanup EXIT

code() { curl -s -o /dev/null -w '%{http_code}' "$@"; }
api() { curl -fsS -u "admin:$pw" "$@"; }

echo "== 1. one command"
PACKETEER_DIR="$work/pk" PACKETEER_IMAGE="$image" PACKETEER_RAW_BASE="file://$root" PACKETEER_ADMIN_PASSWORD="$pw" \
	sh scripts/install.sh | tee "$work/install.txt"
grep -qF 'observe mode. It announces nothing.' "$work/install.txt"
grep -qF "$base/settings.html#wizard" "$work/install.txt"
test "$(docker inspect -f '{{.State.Running}}' packeteer)" = true
grep -q '^mode: observe' "$work/pk/config.yaml"
api "$base/api/overview" | jq -e '.mode == "observe"'
docker logs packeteer 2>&1 | grep -qF 'announce=disabled'

echo "== 2. the checks block, with their fixes"
api "$base/api/preflight" | jq -e '.available == true and (.report == null)'
api -X POST "$base/api/preflight/run" >"$work/report.json"
jq -e '.ready == false' "$work/report.json"
for id in bgp_session import_filter probe_egress timers withdrawal; do
	jq -e --arg id "$id" '.results[] | select(.id == $id) | (.status != "pass") and (.fix | length > 0) and (.detail | length > 0)' "$work/report.json" >/dev/null ||
		{ echo "check $id does not block with a fix" >&2; cat "$work/report.json" >&2; exit 1; }
done
jq -e '.results[] | select(.id == "bgp_session") | .status == "fail" and (.fix | test("bgp.neighbors"))' "$work/report.json"
jq -e '.results[] | select(.id == "import_filter") | .status == "unverified" and .confirmable == true and (.fix | test("rejects everything else"))' "$work/report.json"
jq -e '.results[] | select(.id == "timers") | .status == "fail" and (.fix | test("Bring the BGP session up"))' "$work/report.json"
jq -e '.results[] | select(.id == "withdrawal") | .status == "fail"' "$work/report.json"
api "$base/metrics" | grep -qF 'packeteer_preflight_check{check="bgp_session",status="fail"} 1'
api "$base/metrics" | grep -qF 'packeteer_preflight_ready 0'
# The wizard refuses to turn injection on, and says which check holds it back.
jq -n --rawfile y "$work/pk/config.yaml" '{current: $y, allowlist: ["198.51.100.0/24"]}' >"$work/inject.json"
test "$(code -u "admin:$pw" -H 'Content-Type: application/json' -d @"$work/inject.json" "$base/api/config/inject")" = 412
curl -s -u "admin:$pw" -H 'Content-Type: application/json' -d @"$work/inject.json" "$base/api/config/inject" |
	jq -e '.code == "preflight_required" and (.preflight.ready == false)'
docker exec packeteer test -e /var/lib/packeteer/first-run-setup-pending

echo "== 3. FRR and BIRD accept the router config"
snippet() { docker run --rm -v "$root/lab/interop/packeteer.yaml:/etc/packeteer/config.yaml:ro" "$image" -snippet "$1"; }
for v in frr bird junos iosxr arista mikrotik; do
	snippet "$v" >"$work/$v.txt"
	grep -q '64512:666\|64512, 666' "$work/$v.txt"
	grep -q '192.0.2.10' "$work/$v.txt"
done

mkdir -p "$work/frr"
cp lab/interop/frr/daemons lab/interop/frr/vtysh.conf "$work/frr/"
{
	printf 'frr version 10.2\nfrr defaults traditional\nhostname edge\nlog stdout informational\n!\n'
	cat "$work/frr.txt"
} >"$work/frr/frr.conf"
chmod -R a+rX "$work/frr"
docker run -d --name pk-snip-frr --privileged \
	-e 'FRR_EXPECT=route-map packeteer-in permit 10;neighbor 192.0.2.10 route-map packeteer-in in;neighbor 192.0.2.10 graceful-restart-disable;neighbor 192.0.2.10 timers 10 30' \
	-v "$work/frr:/etc/frr" -v "$root/lab/frr-start.sh:/lab/frr-start.sh:ro" \
	--entrypoint /bin/sh quay.io/frrouting/frr:10.2.4 /lab/frr-start.sh >/dev/null
for _ in $(seq 1 90); do
	docker exec pk-snip-frr vtysh -c 'show running-config' >"$work/frr-running.txt" 2>/dev/null &&
		grep -qF 'neighbor 192.0.2.10 timers 10 30' "$work/frr-running.txt" && break
	sleep 1
done
for want in 'bgp community-list standard packeteer seq 5 permit 64512:666' 'route-map packeteer-in deny 100' 'route-map ebgp-out deny 10' \
	' match community packeteer' 'neighbor 192.0.2.10 remote-as 64512' 'neighbor 192.0.2.10 route-map packeteer-in in'; do
	grep -qF -- "$want" "$work/frr-running.txt" || { echo "FRR running-config lacks: $want" >&2; cat "$work/frr-running.txt" >&2; exit 1; }
done
rm_out=$(docker exec pk-snip-frr vtysh -c 'show route-map packeteer-in')
grep -qF 'community packeteer' <<<"$rm_out" || { echo "FRR route-map packeteer-in lacks the community match" >&2; echo "$rm_out" >&2; exit 1; }
docker rm -f pk-snip-frr >/dev/null

for bird in bird2 bird3; do
	docker build -q -t "pk-snip-$bird" --build-arg "BIRD=$bird" lab/interop/bird >/dev/null
	{
		printf 'router id 192.0.2.254;\nprotocol device {}\nprotocol direct {\n\tipv4;\n}\n'
		cat "$work/bird.txt"
	} >"$work/bird.conf"
	chmod a+r "$work/bird.conf"
	# Parse and load: -p checks the syntax, then the daemon runs it.
	docker run --rm -v "$work/bird.conf:/etc/bird/snippet.conf:ro" --entrypoint bird "pk-snip-$bird" -p -c /etc/bird/snippet.conf
	docker run -d --name pk-snip-bird -e BIRD_CONF=snippet.conf -v "$work/bird.conf:/etc/bird/snippet.conf:ro" "pk-snip-$bird" >/dev/null
	for _ in $(seq 1 30); do
		docker exec pk-snip-bird birdc -s /run/bird/bird.ctl show protocols >"$work/bird-protocols.txt" 2>/dev/null && break
		sleep 1
	done
	grep -q '^packeteer ' "$work/bird-protocols.txt" || { echo "$bird: protocol packeteer not loaded" >&2; cat "$work/bird-protocols.txt" >&2; docker logs pk-snip-bird >&2; exit 1; }
	syms=$(docker exec pk-snip-bird birdc -s /run/bird/bird.ctl show symbols)
	grep -qE 'packeteer_in[[:space:]]+filter' <<<"$syms" || { echo "$bird: filter packeteer_in not loaded" >&2; echo "$syms" >&2; exit 1; }
	docker rm -f pk-snip-bird >/dev/null
done

echo "== 4. policy routing: diff, apply, verify, clean up"
docker network create --subnet 192.0.2.0/24 pk-pbr-net >/dev/null
cat >"$work/pbr.yaml" <<'YAML'
mode: observe
asn: 64512
router_id: 192.0.2.10
providers:
  - {name: transit-a, source_ip: 192.0.2.11, next_hop: 192.0.2.3}
  - {name: transit-b, source_ip: 192.0.2.12, next_hop: 192.0.2.4}
YAML
docker run -d --name pk-pbr --network pk-pbr-net --ip 192.0.2.10 --cap-add NET_ADMIN \
	-v "$work/pbr.yaml:/etc/packeteer/config.yaml:ro" --entrypoint sleep "$image" 600 >/dev/null
docker exec pk-pbr ip addr add 192.0.2.11/24 dev eth0
docker exec pk-pbr ip addr add 192.0.2.12/24 dev eth0
pk() { docker exec pk-pbr /usr/local/bin/packeteer "$@"; }
pk -pbr linux -apply | tee "$work/pbr-diff.txt"
grep -qF '+ ip rule add from 192.0.2.11 lookup 1001 priority 2001' "$work/pbr-diff.txt"
grep -qF 'Nothing was changed. Add -yes' "$work/pbr-diff.txt"
test -z "$(docker exec pk-pbr ip rule show | grep 2001: || true)"
pk -pbr linux -apply -yes | tee "$work/pbr-apply.txt"
grep -qF 'Applied 4 changes.' "$work/pbr-apply.txt"
grep -qF 'leave through its next hop' "$work/pbr-apply.txt"
docker exec pk-pbr ip route get 203.0.113.254 from 192.0.2.11 | grep 'via 192.0.2.3' >/dev/null
docker exec pk-pbr ip route get 203.0.113.254 from 192.0.2.12 | grep 'via 192.0.2.4' >/dev/null
pk -pbr linux -apply | grep -F 'already has the policy routing' >/dev/null
# A provider leaves the config: its rule and route go, the other stays. The
# file is rewritten in place, since the container's mount follows the inode.
grep -v transit-b "$work/pbr.yaml" >"$work/pbr-one.yaml"
cat "$work/pbr-one.yaml" >"$work/pbr.yaml"
pk -pbr linux -apply -yes | tee "$work/pbr-clean.txt"
grep -qF -- '- ip rule del from 192.0.2.12 lookup 1002 priority 2002' "$work/pbr-clean.txt"
test -z "$(docker exec pk-pbr ip rule show | grep 2002: || true)"
docker exec pk-pbr ip rule show | grep 2001: >/dev/null
echo "onboarding lab: ok"
