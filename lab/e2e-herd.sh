#!/bin/bash
# Herd phase 1 (#260) against three simulated members: member-a, member-b,
# and member-c, each a Packeteer instance in observe mode behind one FRR
# edge. The edge learns 192.0.2.128/26 (path "64501 64510") from an upstream
# router that also answers the members' real ICMP probes at 192.0.2.130.
# Documentation addresses and documentation or private ASNs only; keys are
# generated for this run. No seed is configured and nothing talks to a real
# herd.
#
# member-a and member-b share at origin-ASN level and list what they share.
# member-c excludes 192.0.2.0/24, so it records and serves nothing, but
# pulls from both.
# Checked in order:
#  1. each member pulls both peers (no failures, records pulled), and
#     nothing is announced by anyone (the edge has no route from a member);
#  2. per-vantage view: a sees itself and b (not c), c sees a and b, each as
#     its own vantage with its own country, never merged; a view that
#     names no origin_asn or prefix gets 400;
#  3. no prefix and no provider name appears in a preview, which is built
#     by the same code that answers a pull, and member-c previews nothing;
#  4. the served-response audit logs the pulls: unfiltered pages on the
#     listing members a and b, origin_asn queries on the query-only c;
#  5. isolation: with member-b paused (a peer that never answers), a and c
#     keep probing and finish rounds, and report b as failing;
#  6. a member with herd on exits on SIGTERM.
set -euo pipefail
export LC_ALL=C

root=$(cd "$(dirname "$0")/.." && pwd)
cd "$root"
compose=(docker compose -f lab/docker-compose-herd.yml)

lab_dir=$(mktemp -d)
keys_bin=$(mktemp)
trap 'rc=$?; if [ "$rc" -ne 0 ]; then echo "---- lab logs ----"; "${compose[@]}" logs --no-color || true; "${compose[@]}" ps || true; fi; "${compose[@]}" unpause member-b >/dev/null 2>&1 || true; "${compose[@]}" down -v --remove-orphans || true; rm -f "$keys_bin"; rm -rf "$lab_dir"; exit "$rc"' EXIT

echo "building herd keys"
go build -o "$keys_bin" ./lab/mkherdkeys
mkdir -p "$lab_dir/keys"
declare -A pub
while read -r name key; do pub[$name]=$key; done < <("$keys_bin" "$lab_dir/keys" a b c)
chmod 755 "$lab_dir" "$lab_dir/keys"
export PACKETEER_LAB_DIR="$lab_dir"

declare -A ip=([a]=192.0.2.10 [b]=192.0.2.11 [c]=192.0.2.12)
declare -A country=([a]=US [b]=DE [c]=JP)

# render id: write the member's config. Pull every 30s so the lab is quick.
render() {
	local id=$1 other peers="" exclude="" discovery="listing"
	for other in a b c; do
		[ "$other" = "$id" ] && continue
		peers+="    - url: https://${ip[$other]}:9444
      key: ${pub[$other]}
"
	done
	if [ "$id" = c ]; then
		exclude="    exclude: {prefixes: [192.0.2.0/24]}
"
		discovery="query_only"
	fi
	cat >"$lab_dir/$id.yaml" <<YAML
# Lab only (#260). Observe mode: nothing is announced.
mode: observe
asn: 64512
router_id: ${ip[$id]}
providers:
  - name: lab-upstream-secret
    source_ip: ${ip[$id]}
    next_hop: 192.0.2.21
probe:
  interval: 2s
  timeout: 500ms
  packets: 4
bgp:
  neighbors:
    - address: 192.0.2.254
      description: edge
storage:
  type: sqlite
sources:
  - type: static
    config:
      targets:
        - prefix: 192.0.2.128/26
          host: 192.0.2.130
probers:
  - type: icmp
herd:
  enabled: true
  share:
    classes: [measurements]
    discovery: ${discovery}
${exclude}  vantage: {country: ${country[$id]}}
  listen: 0.0.0.0:9444
  key_file: /etc/packeteer/herd/$id.key
  limits: {pull_interval: 30s}
  peers:
${peers}
YAML
}
for id in a b c; do render "$id"; done

echo "building lab"
"${compose[@]}" build
"${compose[@]}" up -d

api() {
	"${compose[@]}" exec -T "member-$1" wget -qO- "http://127.0.0.1:8080$2" 2>/dev/null || true
}

dump() {
	local m
	for m in a b c; do
		api "$m" /api/herd >&2
		echo >&2
	done
	"${compose[@]}" exec -T edge vtysh -c 'show bgp summary' -c 'show bgp ipv4 unicast' >&2 || true
	"${compose[@]}" logs --no-color member-a member-b member-c >&2 || true
}

# need_api member path jq-filter why [tries]: wait until the filter holds.
need_api() {
	local i tries=${5:-90}
	for i in $(seq 1 "$tries"); do
		if api "$1" "$2" | jq -e "$3" >/dev/null 2>&1; then
			return 0
		fi
		sleep 1
	done
	echo "FAIL: $4 (member-$1 $2 does not satisfy: $3)" >&2
	api "$1" "$2" >&2
	dump
	exit 1
}

# need_status member path code why: the ops API answers with this HTTP
# status. api() cannot check an error: busybox wget prints no body for one.
# With -S it prints the status line to stderr.
need_status() {
	local out
	out=$("${compose[@]}" exec -T "member-$1" wget -S -O /dev/null "http://127.0.0.1:8080$2" 2>&1 || true)
	if ! printf '%s\n' "$out" | grep -Eq "HTTP/1\.[01] $3 "; then
		echo "FAIL: $4 (member-$1 $2 did not answer $3)" >&2
		printf '%s\n' "$out" >&2
		dump
		exit 1
	fi
}

need_log() {
	local svc=$1 pattern=$2 why=$3 i
	for i in $(seq 1 30); do
		if "${compose[@]}" logs --no-color "$svc" 2>/dev/null | grep -Eq "$pattern"; then
			return 0
		fi
		sleep 1
	done
	echo "FAIL: $why (no $svc log matching: $pattern)" >&2
	dump
	exit 1
}

echo "1. every member pulls both peers; nobody announces"
for m in a b c; do
	need_api "$m" /api/herd '.enabled and .granularity == "origin_asn" and (.peers | length) == 2 and all(.peers[]; .failures == 0 and .last_ok != null)' "member-$m does not see its peers" 150
done
need_api a /api/herd '[.peers[] | select(.records_pulled > 0)] | length == 1' "member-a pulled records from b only (c serves none)"
need_api c /api/herd '[.peers[] | select(.records_pulled > 0)] | length == 2' "member-c pulled records from both a and b"
routes=$("${compose[@]}" exec -T edge vtysh -c 'show bgp ipv4 unicast json' 2>/dev/null || true)
for m in 192.0.2.10 192.0.2.11 192.0.2.12; do
	if printf '%s\n' "$routes" | jq -e --arg m "$m" '[.routes[]?[]? | select(.peerId == $m)] | length > 0' >/dev/null 2>&1; then
		echo "FAIL: the edge holds a route from member $m; herd members announce nothing" >&2
		dump
		exit 1
	fi
done

echo "2. per-vantage view: one vantage per member and country, never merged"
need_api a '/api/herd/vantages?origin_asn=64510' '(.vantages | length) == 2 and ([.vantages[].country] | sort) == ["DE","US"] and ([.vantages[] | select(.local)] | length) == 1 and all(.vantages[]; .provider_asn == 64501 and .method == "icmp")' "member-a should see itself and b, not c"
need_api c '/api/herd/vantages?origin_asn=64510' '(.vantages | length) == 2 and ([.vantages[].country] | sort) == ["DE","US"] and ([.vantages[] | select(.local)] | length) == 0' "member-c should see a and b and have no vantage of its own (it excludes the prefix)"
need_api b '/api/herd/vantages?origin_asn=64510' '(.vantages | length) == 2 and ([.vantages[].country] | sort) == ["DE","US"]' "member-b should see itself and a"
need_status a '/api/herd/vantages' 400 "a view without origin_asn or prefix is refused"

echo "3. nothing on the never-shared list reaches a response, and preview equals a pull"
for m in a b; do
	prev=$(api "$m" '/api/herd/preview?origin_asn=64510&nonce=lab')
	if [ -z "$prev" ] || ! printf '%s' "$prev" | jq -e '(.records | length) > 0 and .granularity == "origin_asn" and (.signature | length) > 0' >/dev/null; then
		echo "FAIL: member-$m preview has no signed origin-level records: $prev" >&2
		dump
		exit 1
	fi
	for leak in 192.0.2.128 192.0.2.130 lab-upstream-secret '"prefix"' as_path; do
		if printf '%s' "$prev" | grep -q "$leak"; then
			echo "FAIL: member-$m preview contains $leak" >&2
			printf '%s\n' "$prev" >&2
			exit 1
		fi
	done
done
prevc=$(api c '/api/herd/preview?origin_asn=64510')
printf '%s' "$prevc" | jq -e '(.records | length) == 0' >/dev/null || { echo "FAIL: member-c serves records for an excluded prefix: $prevc" >&2; dump; exit 1; }

echo "4. the served-response audit records the pulls"
need_log member-a 'action=herd\.serve target=.*nonce=' "member-a logged no served pull"
need_log member-b 'action=herd\.serve target=.*nonce=' "member-b logged no served pull"
need_log member-c 'action=herd\.serve target=.*origin_asn=64510' "member-c logged no served origin_asn query"

echo "5. a peer that never answers does not stop probing or the other members"
"${compose[@]}" pause member-b
need_api a /api/herd '[.peers[] | select(.failures > 0 and .last_error != "")] | length == 1' "member-a does not report the paused peer as failing" 120
need_api c /api/herd '[.peers[] | select(.failures > 0)] | length == 1' "member-c does not report the paused peer as failing" 120
stamp() { api "$1" /api/probes | jq -r '[.. | .time? // empty] | max // empty' 2>/dev/null || true; }
before=$(stamp a)
sleep 8
after=$(stamp a)
if [ -z "$after" ] || [ "$after" = "$before" ]; then
	echo "FAIL: member-a probe results did not advance while a peer was paused ($before -> $after)" >&2
	dump
	exit 1
fi
api a /readyz | jq -e '.ready == true' >/dev/null || { echo "FAIL: member-a is not ready with a paused peer" >&2; dump; exit 1; }
"${compose[@]}" unpause member-b

echo "6. SIGTERM: a member with herd on exits"
"${compose[@]}" kill -s SIGTERM member-a
for i in $(seq 1 20); do
	if [ "$("${compose[@]}" ps -q --status running member-a | wc -l)" -eq 0 ]; then
		break
	fi
	sleep 1
done
if [ "$("${compose[@]}" ps -q --status running member-a | wc -l)" -ne 0 ]; then
	echo "FAIL: member-a did not exit on SIGTERM" >&2
	dump
	exit 1
fi
echo "herd lab: ok"
