#!/bin/bash
# Herd phase 1 (#260) with its hub and dashboard (#261, #296) proved in the
# lab (#659) against three simulated members: member-a, member-b, and
# member-c, each a Packeteer instance in observe mode in its own AS (64496,
# 64497, 64498) behind its own FRR edge. Each edge learns 192.0.2.128/26
# (path "64501 64510") and 192.0.2.192/27 (path "64501 64511") from one
# upstream, which answers the members' ICMP probes at 192.0.2.130; the dark
# host 192.0.2.200 answers none, so every member sees loss toward AS64511.
# Documentation addresses and ASNs only; keys and certificates are
# generated for this run.
#
# The members configure no static peer. Each publishes a signed entry made
# by "packeteer herd entry"; "packeteer herd hub-check" checks the entries
# and writes the list, as a hub repository's CI would; and the local hub
# (lab/herdhub, not a public repository) serves that list over https with
# a tampered and an expired entry added. Members find each other only from
# that list.
#
# member-a and member-b share at origin-ASN level and list what they share.
# member-c excludes 192.0.2.128/26 and answers queries only, so it serves
# only its AS64511 records.
# Checked in order:
#  0. hub-check accepts the three entries and refuses the tampered and the
#     expired one;
#  1. every member fetched the list from the hub, refused the tampered and
#     expired entries, and took the other two members as hub peers;
#  2. each member pulls both peers (no failures, records pulled), nothing
#     is announced (no edge receives a route from its member), and no
#     member has an improvement;
#  3. per-vantage view: a sees itself and b for AS64510 (not c, which
#     excludes it) and all three for AS64511, each as its own vantage with
#     its own country, never merged; a view that names no origin_asn or
#     prefix gets 400;
#  4. the world view: /api/herd/events and the rendered /herd.html on
#     member-a show AS64511 seen with loss by the three members;
#  5. no prefix and no provider name appears in a preview, which is built
#     by the same code that answers a pull, and member-c previews nothing
#     for AS64510;
#  6. the served-response audit logs the pulls: unfiltered pages on the
#     listing members a and b, origin_asn queries on the query-only c;
#  7. isolation: with member-b paused (a peer that never answers), a and c
#     keep probing and finish rounds, and report b as failing;
#  8. a member with herd on exits on SIGTERM.
# That herd data never reaches Decide, a scorer, or an announcer is the
# import rule in internal/herd/boundary_test.go; this lab shows the effect.
set -euo pipefail
export LC_ALL=C

root=$(cd "$(dirname "$0")/.." && pwd)
cd "$root"
compose=(docker compose -f lab/docker-compose-herd.yml)
image=packeteer:e2e

lab_dir=$(mktemp -d)
keys_bin=$(mktemp)
certs_bin=$(mktemp)
trap 'rc=$?; if [ "$rc" -ne 0 ]; then echo "---- lab logs ----"; "${compose[@]}" logs --no-color || true; "${compose[@]}" ps || true; fi; "${compose[@]}" unpause member-b >/dev/null 2>&1 || true; "${compose[@]}" down -v --remove-orphans || true; rm -f "$keys_bin" "$certs_bin"; rm -rf "$lab_dir"; exit "$rc"' EXIT

fail() {
	echo "FAIL: $*" >&2
	exit 1
}

echo "building herd keys, the hub, and the lab certificate"
go build -o "$keys_bin" ./lab/mkherdkeys
go build -o "$certs_bin" ./lab/mkcerts
mkdir -p "$lab_dir/keys" "$lab_dir/certs" "$lab_dir/hub" "$lab_dir/repo/entries" "$lab_dir/bad"
CGO_ENABLED=0 GOOS=linux GOARCH="$(go env GOARCH)" go build -o "$lab_dir/hub/herdhub" ./lab/herdhub
"$certs_bin" "$lab_dir/certs" herd-hub
# d is never started: its key signs the expired entry.
"$keys_bin" "$lab_dir/keys" a b c d >/dev/null
# The containers read these as other users; the keys protect nothing.
chmod 755 "$lab_dir" "$lab_dir/keys" "$lab_dir/certs" "$lab_dir/hub" "$lab_dir/hub/herdhub"
export PACKETEER_LAB_DIR="$lab_dir"

declare -A ip=([a]=192.0.2.10 [b]=192.0.2.11 [c]=192.0.2.12 [d]=192.0.2.13)
declare -A asn=([a]=64496 [b]=64497 [c]=64498 [d]=64499)
declare -A edge=([a]=192.0.2.254 [b]=192.0.2.253 [c]=192.0.2.252 [d]=192.0.2.251)
declare -A country=([a]=US [b]=DE [c]=JP [d]=FR)

# render id: write the member's config. Pull every 30s so the lab is quick.
render() {
	local id=$1 exclude="" discovery="listing"
	if [ "$id" = c ]; then
		exclude="    exclude: {prefixes: [192.0.2.128/26]}
"
		discovery="query_only"
	fi
	cat >"$lab_dir/$id.yaml" <<YAML
# Lab only (#260, #659). Observe mode: nothing is announced.
mode: observe
asn: ${asn[$id]}
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
    - address: ${edge[$id]}
      description: edge
http:
  listen: 0.0.0.0:8080
storage:
  type: sqlite
auth:
  enabled: false
sources:
  - type: static
    config:
      targets:
        - prefix: 192.0.2.128/26
          host: 192.0.2.130
        - prefix: 192.0.2.192/27
          host: 192.0.2.200
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
  hub: {url: "https://herd-hub:8443/herd.json"}
YAML
}
for id in a b c d; do render "$id"; done

echo "building lab"
"${compose[@]}" build

# pk_herd id args...: run "packeteer herd" from the lab image with the
# member's config and key, on no network.
pk_herd() {
	local id=$1
	shift
	docker run --rm --network none -e PACKETEER_CONFIG=/etc/packeteer/config.yaml \
		-v "$lab_dir/$id.yaml:/etc/packeteer/config.yaml:ro" -v "$lab_dir/keys:/etc/packeteer/herd:ro" \
		"$image" herd "$@"
}
# hub_check dir args...: the hub repository's check, from the lab image.
hub_check() {
	local dir=$1
	shift
	docker run --rm --network none -v "$dir:/hub" "$image" herd hub-check "$@"
}

echo "0. members publish signed entries; hub-check builds the list and refuses bad entries"
pk_herd d entry -url "https://${ip[d]}:9444" -valid 1s >"$lab_dir/bad/${asn[d]}.json"
for id in a b c; do
	pk_herd "$id" entry -url "https://${ip[$id]}:9444" >"$lab_dir/repo/entries/${asn[$id]}.json"
done
# A hub that rewrites b's endpoint without b's key: the signature no longer matches.
jq '.nodes[0].url = "https://192.0.2.14:9444"' "$lab_dir/repo/entries/${asn[b]}.json" >"$lab_dir/bad/${asn[b]}.json"
out=$(hub_check "$lab_dir/repo" -list /hub/herd.json /hub/entries 2>&1) || fail "hub-check refused the members' entries: $out"
[ "$out" = "3 entries ok, 0 pruned" ] || fail "hub-check: $out"
jq -e '.schema == "packeteer-herd-hub/1" and ([.entries[].asn] == [64496, 64497, 64498])' "$lab_dir/repo/herd.json" >/dev/null ||
	fail "hub-check list: $(cat "$lab_dir/repo/herd.json")"
sleep 2
if out=$(hub_check "$lab_dir/bad" /hub 2>&1); then
	fail "hub-check accepted a tampered or expired entry: $out"
fi
printf '%s\n' "$out" | grep -q "^${asn[b]}.json: entry asn ${asn[b]}: signature does not verify$" || fail "hub-check did not refuse the tampered entry: $out"
printf '%s\n' "$out" | grep -q "^${asn[d]}.json: entry asn ${asn[d]}: expired at " || fail "hub-check did not refuse the expired entry: $out"
# The hub is not trusted: it serves the bad entries too, and every node must refuse them.
jq --slurpfile t "$lab_dir/bad/${asn[b]}.json" --slurpfile x "$lab_dir/bad/${asn[d]}.json" '.entries += $t + $x' \
	"$lab_dir/repo/herd.json" >"$lab_dir/hub/herd.json"
chmod 644 "$lab_dir/hub/herd.json"

"${compose[@]}" up -d herd-hub
hub_get() {
	curl -fsS --cacert "$lab_dir/certs/ca.crt" --resolve herd-hub:8443:192.0.2.20 https://herd-hub:8443/herd.json 2>/dev/null || true
}
for i in $(seq 1 30); do
	hub_get | jq -e '(.entries | length) == 5' >/dev/null 2>&1 && break
	[ "$i" -eq 30 ] && fail "the hub does not serve the list over https"
	sleep 1
done
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
	for m in a b c; do
		"${compose[@]}" exec -T "edge-$m" vtysh -c 'show bgp summary' -c 'show bgp ipv4 unicast' >&2 || true
	done
	"${compose[@]}" logs --no-color herd-hub member-a member-b member-c >&2 || true
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

# peers_of member: set urls (JSON strings) and asns to the other two members'.
peers_of() {
	local o
	urls=() asns=()
	for o in a b c; do
		if [ "$o" != "$1" ]; then
			urls+=("\"https://${ip[$o]}:9444\"")
			asns+=("${asn[$o]}")
		fi
	done
}

echo "1. every member takes its peers from the hub list and refuses the bad entries"
for m in a b c; do
	need_api "$m" /api/herd '.hub.source == "hub" and .hub.listed == 3 and .hub.rejected == 2 and .hub.peers == 2 and .hub.last_error == null' "member-$m did not load the hub list" 120
	peers_of "$m"
	need_api "$m" /api/herd "(.peers | length) == 2 and all(.peers[]; .source == \"hub\") and ([.peers[].url] | sort) == [${urls[0]},${urls[1]}]" "member-$m should have exactly the other two members as hub peers"
	need_log herd-hub "GET /herd.json from ${ip[$m]}:" "member-$m did not fetch the list from the local hub"
done

echo "2. every member pulls both peers; nobody announces"
for m in a b c; do
	need_api "$m" /api/herd '.enabled and .granularity == "origin_asn" and (.peers | length) == 2 and all(.peers[]; .failures == 0 and .last_ok != null)' "member-$m does not see its peers" 150
	need_api "$m" /api/herd '[.peers[] | select(.records_pulled > 0)] | length == 2' "member-$m should pull records from both peers"
	peers_of "$m"
	need_api "$m" /api/herd "([.peers[].asn] | sort) == [${asns[0]},${asns[1]}]" "member-$m peers must report the ASN of their entries"
done
for m in a b c; do
	got=$("${compose[@]}" exec -T "edge-$m" vtysh -c "show bgp ipv4 unicast neighbors ${ip[$m]} received-routes json" 2>/dev/null | jq -r '(.receivedRoutes // {}) | length' 2>/dev/null || true)
	[ "$got" = 0 ] || { echo "FAIL: edge-$m received routes from member-$m ($got); herd members announce nothing" >&2; dump; exit 1; }
	api "$m" /api/improvements | jq -e '(.improvements | length) == 0' >/dev/null || { echo "FAIL: member-$m has an improvement" >&2; dump; exit 1; }
done

echo "3. per-vantage view: one vantage per member and country, never merged"
need_api a '/api/herd/vantages?origin_asn=64510' '(.vantages | length) == 2 and ([.vantages[].country] | sort) == ["DE","US"] and ([.vantages[] | select(.local)] | length) == 1 and all(.vantages[]; .provider_asn == 64501 and .method == "icmp")' "member-a should see itself and b, not c"
need_api c '/api/herd/vantages?origin_asn=64510' '(.vantages | length) == 2 and ([.vantages[].country] | sort) == ["DE","US"] and ([.vantages[] | select(.local)] | length) == 0' "member-c should see a and b and have no vantage of its own (it excludes the prefix)"
need_api b '/api/herd/vantages?origin_asn=64510' '(.vantages | length) == 2 and ([.vantages[].country] | sort) == ["DE","US"]' "member-b should see itself and a"
need_api a '/api/herd/vantages?origin_asn=64511' '(.vantages | length) == 3 and ([.vantages[].country] | sort) == ["DE","JP","US"] and ([.vantages[].asn] | sort) == [64496,64497,64498]' "member-a should see all three members for AS64511"
need_status a '/api/herd/vantages' 400 "a view without origin_asn or prefix is refused"

echo "4. the world view on member-a shows the three members"
need_api a /api/herd/overview '(.members | length) == 3 and ([.members[].asn] | sort) == [64496,64497,64498] and ([.members[] | select(.local | not) | .source] | unique) == ["hub"] and ([.countries[]] | sort) == ["DE","JP","US"]' "member-a overview should list the three members"
need_api a /api/herd/events '[.events[] | select(.kind == "origin_asn" and .value == "64511" and .reporting == 3 and .degraded == 3 and ([.vantages[].country] | sort) == ["DE","JP","US"])] | length == 1' "member-a world view should show AS64511 with loss from all three members"
bash lab/ui-smoke.sh "http://${ip[a]}:8080/herd.html" \
	'World view' '3 of 3 members see loss (pooled by origin AS)' \
	'this node (AS64496), US, via AS64501, icmp' ', DE, via AS64501, icmp' ', JP, via AS64501, icmp' \
	'>AS64497<' '>AS64498<' '>hub<' \
	--absent 'No target shows loss' || { dump; exit 1; }

echo "5. nothing on the never-shared list reaches a response, and preview equals a pull"
for m in a b; do
	prev=$(api "$m" '/api/herd/preview?origin_asn=64510&nonce=lab')
	if [ -z "$prev" ] || ! printf '%s' "$prev" | jq -e '(.records | length) > 0 and .granularity == "origin_asn" and (.signature | length) > 0' >/dev/null; then
		echo "FAIL: member-$m preview has no signed origin-level records: $prev" >&2
		dump
		exit 1
	fi
	for leak in 192.0.2.128 192.0.2.130 192.0.2.192 192.0.2.200 lab-upstream-secret '"prefix"' as_path; do
		if printf '%s' "$prev" | grep -q "$leak"; then
			echo "FAIL: member-$m preview contains $leak" >&2
			printf '%s\n' "$prev" >&2
			exit 1
		fi
	done
done
prevc=$(api c '/api/herd/preview?origin_asn=64510')
printf '%s' "$prevc" | jq -e '(.records | length) == 0' >/dev/null || { echo "FAIL: member-c serves records for an excluded prefix: $prevc" >&2; dump; exit 1; }

echo "6. the served-response audit records the pulls"
need_log member-a 'action=herd\.serve target=.*nonce=' "member-a logged no served pull"
need_log member-b 'action=herd\.serve target=.*nonce=' "member-b logged no served pull"
need_log member-c 'action=herd\.serve target=.*origin_asn=64510' "member-c logged no served origin_asn query"

echo "7. a peer that never answers does not stop probing or the other members"
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

echo "8. SIGTERM: a member with herd on exits"
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
