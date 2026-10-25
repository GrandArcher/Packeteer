#!/bin/bash
# Reordering lab (#224): two provider paths to a TWAMP-Light reflector
# Packeteer controls (lab/docker-compose-reorder.yml). transit-b is a 2-way
# ECMP bundle; this script puts a netem qdisc on its second member that
# sends every fifth packet ahead of the one before it (delay 30ms, reorder
# gap 5), so a train on that member reads an RFC 4737 reordered ratio of
# about 20% with extent 1, while the clean member and transit-a read 0.
# Every train keeps one 5-tuple; the flows rotate the source port, so some
# land on each member and the worst flow finds the bad one. The ICMP
# responder is labelled an estimate. Removing the qdisc brings transit-b
# back to 0, the Providers page shows the column, and SIGTERM stops
# cleanly. Observe mode, nothing announced, documentation prefixes only.
set -euo pipefail

root=$(cd "$(dirname "$0")/.." && pwd)
cd "$root"
compose=(docker compose -f lab/docker-compose-reorder.yml)
base=http://127.0.0.1:18084

trap 'rc=$?; if [ "$rc" -ne 0 ]; then echo "---- lab logs ----"; "${compose[@]}" logs --no-color || true; "${compose[@]}" ps || true; fi; "${compose[@]}" down -v --remove-orphans || true; exit "$rc"' EXIT

echo "building lab"
"${compose[@]}" build
"${compose[@]}" up -d

api() { curl -fsS "$base$1" 2>/dev/null || true; }
fail() {
	echo "$1" >&2
	api /api/reorder >&2 || true
	"${compose[@]}" exec -T transit-b tc -s qdisc show >&2 || true
	exit 1
}

# member_dev prints transit-b's interface toward the reflector's second link.
member_dev() {
	"${compose[@]}" exec -T transit-b sh -c 'ip -o -4 addr show | awk "\$4 ~ /^198\\.51\\.100\\.129\\// {print \$2}"'
}

for _ in $(seq 1 60); do
	if [ -n "$(member_dev)" ] && curl -fsS "$base/healthz" >/dev/null 2>&1; then break; fi
	sleep 1
done
dev=$(member_dev)
[ -n "$dev" ] || fail "transit-b has no interface on 198.51.100.128/26"
echo "netem reorder on transit-b member $dev"
"${compose[@]}" exec -T transit-b tc qdisc add dev "$dev" root netem delay 30ms reorder 100% gap 5
"${compose[@]}" exec -T transit-b tc qdisc show dev "$dev" | grep -q netem || fail "netem qdisc not installed"

# wait_reorder <jq filter>: wait until /api/reorder matches it.
wait_reorder() {
	local i
	for i in $(seq 1 90); do
		if api /api/reorder | jq -e "$1" >/dev/null 2>&1; then
			return 0
		fi
		sleep 2
	done
	fail "/api/reorder never matched: $1"
}

echo "waiting for a measurement of every provider and responder"
wait_reorder '.configured and ([.reorder[] | select(.ok)] | length) == 4'
json=$(api /api/reorder)
echo "$json" | jq -c '.reorder[] | {provider, responder, type, estimate, worst, worst_flow, flows: [.flows[] | .ratio_pct]}'

twamp_a() { echo "$json" | jq -e '[.reorder[] | select(.provider == "transit-a" and .type == "twamp")][0] | '"$1" >/dev/null; }
twamp_b() { echo "$json" | jq -e '[.reorder[] | select(.provider == "transit-b" and .type == "twamp")][0] | '"$1" >/dev/null; }

echo "clean path: transit-a reads about 0 on every flow"
twamp_a '.ok and .estimate == false and .port == 862 and (.flows | length) == 12' || fail "transit-a twamp row is wrong"
twamp_a '[.flows[] | .ratio_pct] | max < 3' || fail "transit-a reordered ratio is not about 0"
twamp_a '[.flows[] | .received] | min >= 18' || fail "transit-a lost packets on the clean path"

echo "bad member: transit-b's worst flow reads the configured rate (every fifth packet, about 20%)"
twamp_b '.ok and .worst.ratio_pct >= 12 and .worst.ratio_pct <= 30' || fail "transit-b worst flow is not near 20%"
twamp_b '.worst.extent >= 1 and .worst.n_reordering >= 1 and .worst.reordered >= 2' || fail "transit-b extent or n-reordering missing"
echo "clean member: per-flow rotation also lands on it and reads about 0"
twamp_b '[.flows[] | .ratio_pct] | min < 3' || fail "no transit-b flow saw the clean member"
twamp_b '[.flows[] | select(.ratio_pct >= 12)] | length >= 1' || fail "no transit-b flow saw the reordering member"
twamp_b '[.flows[] | .received] | min >= 18' || fail "transit-b lost packets"

echo "ICMP responders are estimates"
echo "$json" | jq -e '[.reorder[] | select(.type == "icmp")] | length == 2 and all(.estimate and .ok and (.flows | length) == 1)' >/dev/null || fail "icmp estimate rows are wrong"

echo "providers carry the controlled reading, decisions carry it per candidate, metrics export it per flow"
prov=$(api /api/providers)
echo "$prov" | jq -e '[.providers[] | select(.name == "transit-b")][0].reorder | .estimate == false and .ratio_pct >= 12 and .responder == "203.0.113.9"' >/dev/null || fail "transit-b headline reading is wrong: $prov"
echo "$prov" | jq -e '[.providers[] | select(.name == "transit-a")][0].reorder | .estimate == false and .ratio_pct < 3' >/dev/null || fail "transit-a headline reading is wrong: $prov"
dec=$(api /api/decisions)
echo "$dec" | jq -e '[.decisions[] | select(.prefix == "203.0.113.0/24")][0].candidates | map(select(.provider == "transit-b"))[0].reorder_pct >= 12' >/dev/null || fail "decision candidate lacks reorder_pct: $dec"
metrics=$(api /metrics)
echo "$metrics" | grep -q '^packeteer_reorder_ratio{provider="transit-b",responder="203.0.113.9",type="twamp",estimate="false",flow="1"} ' || fail "no reorder ratio metric"
echo "$metrics" | grep -q '^packeteer_reorder_success{provider="transit-a",responder="203.0.113.9",type="icmp",estimate="true"} 1' || fail "no estimate success metric"
echo "$metrics" | grep -q '^packeteer_reorder_extent{provider="transit-b"' || fail "no reorder extent metric"

echo "UI: the Providers page shows the Reordering column and the estimate badge"
bash lab/ui-smoke.sh "$base/providers.html" 'Reordering' 'class="reorder"' 'It announces nothing.' --absent 'Cannot reach'

echo "removing the qdisc brings transit-b back to about 0"
"${compose[@]}" exec -T transit-b tc qdisc del dev "$dev" root
wait_reorder '[.reorder[] | select(.provider == "transit-b" and .type == "twamp")][0] | .ok and .worst.ratio_pct < 3'

echo "SIGTERM stops cleanly"
"${compose[@]}" stop -t 15 packeteer
code=$(docker inspect -f '{{.State.ExitCode}}' "$("${compose[@]}" ps -aq packeteer)")
[ "$code" = "0" ] || fail "packeteer exit code $code"
"${compose[@]}" logs --no-color packeteer | grep -q "shutting down" || fail "no clean shutdown log"
echo "reorder lab OK"
