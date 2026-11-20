#!/bin/bash
# Herd phase 1 (#260) with its hub (#261) and dashboard (#296), proved in
# the lab (#659), and herd phase 2 (#672): peer exchange, identities checked
# against an RPKI stand-in, probe hints, and the crowd threshold, and its
# local uses (#686): a block and a down-weight, the "my upstream or the
# destination" attribution, and the outage second opinion. Three
# simulated members, member-a, member-b, and member-c, each a Packeteer
# instance in observe mode in its own AS (64496, 64497, 64498) behind its own
# FRR edge. Each edge learns 192.0.2.128/26 (path "64501 64510"),
# 192.0.2.192/27 (path "64501 64511"), and 192.0.2.224/28 (path
# "64501 64509") from one upstream, which answers the members' ICMP probes
# at 192.0.2.130; the dark host 192.0.2.200 answers none, and nothing owns
# 192.0.2.224/28, so every member that probes them sees loss toward AS64511
# and AS64509.
# Documentation addresses and ASNs only; keys and certificates are
# generated for this run.
#
# The members configure no static peer. Each publishes a signed entry made
# by "packeteer herd entry"; "packeteer herd hub-check" checks the entries
# as a hub repository's CI would. The local hub (lab/herdhub, not a public
# repository) lists only the seed node (AS64499, run by lab/herdhub too)
# plus a tampered and an expired entry, so the members find each other only
# by peer exchange from the seed's peer list, which relays the three member
# entries and a tampered, an expired, and an oversized one. The hub also
# serves the RPKI stand-in: validated checklists that bind a's and b's keys
# to their ASNs and AS64498 to the seed's key, so member-c is unverified
# (shown, not counted) and so is the seed.
#
# member-a and member-b share at origin-ASN level and list what they share.
# member-c excludes 192.0.2.128/26, answers queries only, and shares at route
# level with a flow source fed by lab/sendflow toward 192.0.2.230, so
# 192.0.2.224/28 is a route only user traffic put on its probe list
# (crowd_k 1). member-b probes 192.0.2.224/28 as a static target; member-a
# does not, and starts probing it through its herd_hints source. member-a
# also runs an outage source, which opens an AS64501 incident once it probes
# the two dark routes, and then lists the /28 too. member-b blocks member-c by endpoint and down-weights
# member-a by ASN (its own view only).
# Checked in order:
#  0. hub-check accepts the four entries and refuses the tampered and the
#     expired one;
#  1. every member fetched the list and the checklists from the hub, took
#     the seed as its one hub peer, refused the two bad hub entries, found
#     the other two members by peer exchange, and refused the tampered,
#     expired, and oversized relayed entries;
#  2. each member pulls both other members (no failures, records pulled),
#     nothing is announced (no edge receives a route from its member), and
#     no member has an improvement;
#  3. identity: a and b are verified, c and the seed are not; the world
#     view on member-a counts a and b for AS64511 and lists c's row as not
#     counted;
#  4. per-vantage view: a sees itself and b for AS64510 (not c, which
#     excludes it) and all three for AS64511, each as its own vantage with
#     its own country, never merged; a view that names no origin_asn or
#     prefix gets 400;
#  5. the world view, mesh, map, monitors, and search on member-a list the
#     same three members, and the rendered /herd.html shows them;
#  6. hints: member-a, which has no static target in 192.0.2.224/28, probes
#     it because verified member-b sees loss there, and steers nothing (in
#     observe with one provider that holds anyway; that a hint never steers
#     without a local measurement is TestHintsNeverSteerWithoutALocalMeasurement);
#  7. crowd threshold: member-c measured its flow-only route but serves it
#     to nobody while no other verified member serves it, and still serves
#     its static route at route level;
#  8. no prefix and no provider name appears in an origin-level preview,
#     which is built by the same code that answers a pull, and member-c
#     previews nothing for AS64510;
#  9. the served-response audit logs the pulls: unfiltered pages on the
#     listing members a and b, origin_asn queries on the query-only c;
# 10. local view on member-b: c is neither pulled nor shown and a is shown
#     and not counted, while a still shows and counts both; b keeps
#     probing, stays ready, and announces nothing;
# 11. attribution: member-a sees AS64511 degraded through AS64501, and the
#     API and /herd.html show that the one other member that counts sees it
#     degraded through the same provider ASN, which cannot tell the provider
#     from the destination (every member has the one upstream); on member-b,
#     which down-weights a, no other member counts;
# 12. outage second opinion: member-a's AS64501 incident carries 1 of 1
#     verified members seeing AS64501 degraded, and a announces nothing;
# 13. isolation: with member-b paused (a peer that never answers), a and c
#     report b as failing, and a keeps probing and stays ready;
# 14. a member with herd on exits on SIGTERM.
# That herd data never reaches Decide, a scorer, or an announcer is the
# import rule in internal/herd/boundary_test.go and the hint test in
# internal/herd/hints_test.go; this lab shows the effect.
set -euo pipefail
export LC_ALL=C

root=$(cd "$(dirname "$0")/.." && pwd)
cd "$root"
compose=(docker compose -f lab/docker-compose-herd.yml)
image=packeteer:e2e

lab_dir=$(mktemp -d)
keys_bin=$(mktemp)
certs_bin=$(mktemp)
flow_bin=$(mktemp)
rates=$(mktemp)
flow_pid=""
trap 'rc=$?; if [ -n "$flow_pid" ]; then kill "$flow_pid" 2>/dev/null || true; fi; if [ "$rc" -ne 0 ]; then echo "---- lab logs ----"; "${compose[@]}" logs --no-color || true; "${compose[@]}" ps || true; fi; "${compose[@]}" unpause member-b >/dev/null 2>&1 || true; "${compose[@]}" down -v --remove-orphans || true; rm -f "$keys_bin" "$certs_bin" "$flow_bin" "$rates" "$rates.tmp"; rm -rf "$lab_dir"; exit "$rc"' EXIT

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

fail() {
	echo "FAIL: $*" >&2
	dump
	exit 1
}

echo "building herd keys, the hub, flow sender, and the lab certificate"
go build -o "$keys_bin" ./lab/mkherdkeys
go build -o "$certs_bin" ./lab/mkcerts
go build -o "$flow_bin" ./lab/sendflow
mkdir -p "$lab_dir/keys" "$lab_dir/certs" "$lab_dir/hub" "$lab_dir/repo/entries" "$lab_dir/bad" "$lab_dir/relay"
CGO_ENABLED=0 GOOS=linux GOARCH="$(go env GOARCH)" go build -o "$lab_dir/hub/herdhub" ./lab/herdhub
"$certs_bin" "$lab_dir/certs" herd-hub
# d is the seed node (run by lab/herdhub); e and f never run: e's key signs
# the expired entry, f's the oversized one.
"$keys_bin" "$lab_dir/keys" a b c d e f >/dev/null
# A rootless Docker reads these as another user; the keys protect nothing.
chmod 755 "$lab_dir" "$lab_dir/keys" "$lab_dir/certs" "$lab_dir/hub" "$lab_dir/hub/herdhub" "$lab_dir/relay"
export PACKETEER_LAB_DIR="$lab_dir"

declare -A ip=([a]=192.0.2.10 [b]=192.0.2.11 [c]=192.0.2.12 [d]=192.0.2.20 [e]=192.0.2.13 [f]=192.0.2.14)
declare -A asn=([a]=64496 [b]=64497 [c]=64498 [d]=64499 [e]=64502 [f]=64503)
# d, e, and f name no router: their configs only validate.
declare -A edge=([a]=192.0.2.254 [b]=192.0.2.253 [c]=192.0.2.252 [d]=192.0.2.251 [e]=192.0.2.251 [f]=192.0.2.251)
declare -A country=([a]=US [b]=DE [c]=JP [d]=FR [e]=GB [f]=NL)

# render id: write the member's config. Pull every 30s so the lab is quick.
render() {
	local id=$1 share="    discovery: listing
" targets="        - prefix: 192.0.2.128/26
          host: 192.0.2.130
        - prefix: 192.0.2.192/27
          host: 192.0.2.200
" extra="" view=""
	case "$id" in
	a)
		extra="  - type: herd_hints
    config: {min_vantages: 1, max_targets: 4}
  - type: outage
    config: {min_prefixes: 2, window: 1m, interval: 1s}
"
		;;
	c)
		share="    granularity: route
    sources: [static, flow]
    crowd_k: 1
    discovery: query_only
    exclude: {prefixes: [192.0.2.128/26]}
"
		extra="  - type: flow
    config:
      listen: 0.0.0.0:2055
      window: 30s
"
		;;
	*)
		targets+="        - prefix: 192.0.2.224/28
          host: 192.0.2.230
"
		;;
	esac
	if [ "$id" = b ]; then
		view="  block: {endpoints: [\"https://${ip[c]}:9444\"]}
  down_weight: {asns: [${asn[a]}]}
"
	fi
	cat >"$lab_dir/$id.yaml" <<YAML
# Lab only (#260, #659, #672, #686). Observe mode: nothing is announced.
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
${targets}${extra}probers:
  - type: icmp
herd:
  enabled: true
  share:
    classes: [measurements]
${share}  vantage: {country: ${country[$id]}}
  listen: 0.0.0.0:9444
  key_file: /etc/packeteer/herd/$id.key
  limits: {pull_interval: 30s}
  hub: {url: "https://herd-hub:8443/herd.json"}
  identity: {url: "https://herd-hub:8443/rsc.json"}
${view}
YAML
}
for id in a b c d e f; do render "$id"; done

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
# keyid id: the node key id, the SHA-256 of the raw public key, which a
# checklist digest names.
keyid() {
	jq -r '.nodes[0].key' "$lab_dir/repo/entries/${asn[$1]}.json" | sed 's/^ed25519://' | base64 -d | sha256sum | cut -d' ' -f1
}

echo "0. members publish signed entries; hub-check builds the list and refuses bad entries"
pk_herd e entry -url "https://${ip[e]}:9444" -valid 1s >"$lab_dir/bad/${asn[e]}.json"
for id in a b c d; do
	pk_herd "$id" entry -url "https://${ip[$id]}:9444" >"$lab_dir/repo/entries/${asn[$id]}.json"
done
# A hub or relayer that rewrites b's endpoint without b's key: the signature no longer matches.
jq '.nodes[0].url = "https://192.0.2.15:9444"' "$lab_dir/repo/entries/${asn[b]}.json" >"$lab_dir/bad/${asn[b]}.json"
out=$(hub_check "$lab_dir/repo" -list /hub/herd.json /hub/entries 2>&1) || fail "hub-check refused the entries: $out"
[ "$out" = "4 entries ok, 0 pruned" ] || fail "hub-check: $out"
jq -e '.schema == "packeteer-herd-hub/1" and ([.entries[].asn] == [64496, 64497, 64498, 64499])' "$lab_dir/repo/herd.json" >/dev/null ||
	fail "hub-check list: $(cat "$lab_dir/repo/herd.json")"
sleep 2
if out=$(hub_check "$lab_dir/bad" /hub 2>&1); then
	fail "hub-check accepted a tampered or expired entry: $out"
fi
printf '%s\n' "$out" | grep -q "^${asn[b]}.json: entry asn ${asn[b]}: signature does not verify$" || fail "hub-check did not refuse the tampered entry: $out"
printf '%s\n' "$out" | grep -q "^${asn[e]}.json: entry asn ${asn[e]}: expired at " || fail "hub-check did not refuse the expired entry: $out"
# The hub lists only the seed, and cannot alter an entry: it serves the bad
# entries too, and every node must refuse them.
jq --slurpfile t "$lab_dir/bad/${asn[b]}.json" --slurpfile x "$lab_dir/bad/${asn[e]}.json" \
	'.entries |= map(select(.asn == 64499)) | .entries += $t + $x' "$lab_dir/repo/herd.json" >"$lab_dir/hub/herd.json"
# The seed relays the members' entries as they signed them, and the bad ones.
for id in a b c; do
	cp "$lab_dir/repo/entries/${asn[$id]}.json" "$lab_dir/relay/"
done
cp "$lab_dir/bad/${asn[b]}.json" "$lab_dir/relay/tampered.json"
cp "$lab_dir/bad/${asn[e]}.json" "$lab_dir/relay/expired.json"
pk_herd f entry -url "https://${ip[f]}:9444" | jq --arg pad "$(head -c 20000 /dev/zero | tr '\0' x)" '. + {pad: $pad}' >"$lab_dir/relay/oversized.json"
# The RPKI stand-in: a and b are bound to their ASNs; AS64498 is bound to
# the seed's key, not c's, so c (and the seed, which nothing binds) is
# unverified.
not_after=$(date -u -d '+1 day' +%Y-%m-%dT%H:%M:%SZ)
jq -n --arg na "$not_after" --arg a "$(keyid a)" --arg b "$(keyid b)" --arg d "$(keyid d)" \
	'{schema: "packeteer-herd-rsc/1", generated_at: (now | todate), checklists: [
		{asns: [64496], digests: [$a], not_after: $na},
		{asns: [64497], digests: [$b], not_after: $na},
		{asns: [64498], digests: [$d], not_after: $na}]}' >"$lab_dir/hub/rsc.json"
chmod 644 "$lab_dir/hub/herd.json" "$lab_dir/hub/rsc.json" "$lab_dir/relay/"*.json

"${compose[@]}" up -d herd-hub
hub_get() {
	curl -fsS --cacert "$lab_dir/certs/ca.crt" --resolve herd-hub:8443:192.0.2.20 "https://herd-hub:8443$1" 2>/dev/null || true
}
for i in $(seq 1 30); do
	hub_get /herd.json | jq -e '(.entries | length) == 3' >/dev/null 2>&1 &&
		hub_get /rsc.json | jq -e '(.checklists | length) == 3' >/dev/null 2>&1 && break
	[ "$i" -eq 30 ] && fail "the hub does not serve the list and the checklists over https"
	sleep 1
done
"${compose[@]}" up -d

# member-c's flow source sees user traffic toward 192.0.2.230 only.
printf '%s\n' "192.0.2.230 udp 1" >"$rates.tmp"
mv "$rates.tmp" "$rates"
"$flow_bin" -to "${ip[c]}:2055" -rates "$rates" -every 500ms &
flow_pid=$!

# need_api member path jq-filter why [tries]: wait until the filter holds.
need_api() {
	local i tries=${5:-90}
	for i in $(seq 1 "$tries"); do
		if api "$1" "$2" | jq -e "$3" >/dev/null 2>&1; then
			return 0
		fi
		sleep 1
	done
	api "$1" "$2" >&2
	fail "$4 (member-$1 $2 does not satisfy: $3)"
}

# need_status member path code why: the ops API answers with this HTTP
# status. api() cannot check an error: busybox wget prints no body for one.
# With -S it prints the status line to stderr.
need_status() {
	local out
	out=$("${compose[@]}" exec -T "member-$1" wget -S -O /dev/null "http://127.0.0.1:8080$2" 2>&1 || true)
	if ! printf '%s\n' "$out" | grep -Eq "HTTP/1\.[01] $3 "; then
		printf '%s\n' "$out" >&2
		fail "$4 (member-$1 $2 did not answer $3)"
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
	fail "$why (no $svc log matching: $pattern)"
}

# peers_of member: set urls (JSON strings) and asns to the other members it
# pulls. member-b blocks member-c (#686).
peers_of() {
	local o
	urls=() asns=()
	for o in a b c; do
		if [ "$o" != "$1" ] && [ "$1$o" != bc ]; then
			urls+=("\"https://${ip[$o]}:9444\"")
			asns+=("${asn[$o]}")
		fi
	done
}

# no_steer member: the member's edge received no route and it holds no improvement.
no_steer() {
	local got
	got=$("${compose[@]}" exec -T "edge-$1" vtysh -c "show bgp ipv4 unicast neighbors ${ip[$1]} received-routes json" 2>/dev/null | jq -r '(.receivedRoutes // {}) | length' 2>/dev/null || true)
	[ "$got" = 0 ] || fail "edge-$1 received routes from member-$1 ($got) $2"
	api "$1" /api/improvements | jq -e '(.improvements | length) == 0' >/dev/null || fail "member-$1 has an improvement $2"
}

echo "1. every member takes the seed from the hub and finds the others by peer exchange"
for m in a b c; do
	need_api "$m" /api/herd '.hub.source == "hub" and .hub.listed == 1 and .hub.rejected == 2 and .hub.peers == 1 and .hub.last_error == null' "member-$m did not load the hub list" 120
	peers_of "$m"
	need_api "$m" /api/herd "(.peers | length) == $((${#urls[@]} + 1)) and ([.peers[] | select(.source == \"hub\") | .url] == [\"https://${ip[d]}:9444\"]) and ([.peers[] | select(.source == \"exchange\") | .url] | sort) == [$(IFS=,; echo "${urls[*]}")]" "member-$m should have the seed as its hub peer and the other members it does not block by peer exchange" 150
	need_api "$m" /api/herd '[.peers[] | select(.source == "hub")][0] | .relayed == 6 and .relay_refused == 3 and .exchange_error == null' "member-$m should read six relayed entries from the seed and refuse three"
	need_log herd-hub "GET /herd.json from ${ip[$m]}:" "member-$m did not fetch the list from the local hub"
	need_log herd-hub "GET /rsc.json from ${ip[$m]}:" "member-$m did not fetch the checklists from the local hub"
	need_log "member-$m" 'entry refused.*signature does not verify' "member-$m did not refuse the tampered relayed entry"
	need_log "member-$m" 'entry refused.*expired at' "member-$m did not refuse the expired relayed entry"
	need_log "member-$m" 'entry refused.*larger than 16384 bytes' "member-$m did not refuse the oversized relayed entry"
done

echo "2. every member pulls both other members; nobody announces"
for m in a b c; do
	peers_of "$m"
	need_api "$m" /api/herd ".enabled and (.peers | length) == $((${#urls[@]} + 1)) and all(.peers[]; .failures == 0 and .last_ok != null)" "member-$m does not see its peers" 150
	need_api "$m" /api/herd "[.peers[] | select(.source == \"exchange\" and .records_pulled > 0)] | length == ${#urls[@]}" "member-$m should pull records from the other members it does not block"
	need_api "$m" /api/herd "([.peers[] | select(.source == \"exchange\") | .asn] | sort) == [$(IFS=,; echo "${asns[*]}")] and ([.peers[] | select(.source == \"hub\") | .asn] == [${asn[d]}])" "member-$m peers must report the ASN of their entries"
done
for m in a b c; do
	no_steer "$m" "(herd members announce nothing)"
done

echo "3. identity: a and b are verified, c and the seed are shown and not counted"
need_api a /api/herd '.verified and .identity.bindings == 3 and .identity.last_error == null and ([.peers[] | select(.verified) | .asn] == [64497])' "member-a should be verified and see only b verified"
need_api b /api/herd '.verified and ([.peers[] | select(.verified) | .asn] == [64496])' "member-b should be verified and see only a verified"
need_api c /api/herd '(.verified | not) and ([.peers[] | select(.verified) | .asn] | sort) == [64496,64497]' "member-c is bound to no key of its own and must not be verified"
need_api a /api/herd/overview '(.members | length) == 4 and ([.members[] | select(.verified) | .asn] | sort) == [64496,64497] and ([.members[] | select(.identity == "unverified") | .asn] | sort) == [64498,64499]' "member-a overview should mark c and the seed unverified"
need_api a /api/herd/events '.basis == "rpki" and ([.events[] | select(.kind == "origin_asn" and .value == "64511" and .reporting == 2 and .degraded == 2 and ([.vantages[].country] | sort) == ["DE","US"] and all(.vantages[]; .counted))] | length == 1)' "member-a world view should count a and b for AS64511" 120
need_api a /api/herd/events '[.events[] | select(.kind == "prefix" and .value == "192.0.2.192/27" and .reporting == 0 and ([.vantages[] | select(.country == "JP" and .degraded and (.counted | not))] | length == 1))] | length == 1' "member-a world view should list c's row for its route and not count it"

echo "4. per-vantage view: one vantage per member and country, never merged"
need_api a '/api/herd/vantages?origin_asn=64510' '(.vantages | length) == 2 and ([.vantages[].country] | sort) == ["DE","US"] and ([.vantages[] | select(.local)] | length) == 1 and all(.vantages[]; .provider_asn == 64501 and .method == "icmp")' "member-a should see itself and b, not c"
need_api c '/api/herd/vantages?origin_asn=64510' '(.vantages | length) == 2 and ([.vantages[].country] | sort) == ["DE","US"] and ([.vantages[] | select(.local)] | length) == 0' "member-c should see a and b and have no vantage of its own (it excludes the prefix)"
need_api b '/api/herd/vantages?origin_asn=64510' '(.vantages | length) == 2 and ([.vantages[].country] | sort) == ["DE","US"]' "member-b should see itself and a"
need_api a '/api/herd/vantages?origin_asn=64511' '(.vantages | length) == 3 and ([.vantages[].country] | sort) == ["DE","JP","US"] and ([.vantages[].asn] | sort) == [64496,64497,64498]' "member-a should see all three members for AS64511"
need_status a '/api/herd/vantages' 400 "a view without origin_asn or prefix is refused"

echo "5. the dashboard views on member-a list the same three members"
need_api a /api/herd/overview '([.members[] | select(.local | not) | .source] | sort) == ["exchange","exchange","hub"] and ([.countries[]] | sort) == ["DE","JP","US"] and ([.members[] | select(.asn == 64499) | .records] == [0])' "member-a overview should list the seed and the two members found by exchange"
need_api a /api/herd/mesh '([.rows[].asn] | unique) == [64496,64497,64498]' "member-a mesh should list the three members"
# Attribution (#686): a sees AS64511 lose packets through AS64501, and so does
# b, the one other member that counts, through the same provider ASN. With
# no member through another provider ASN the provider and the destination
# look the same, so nothing clear is named.
need_api a /api/herd/events '[.events[] | select(.kind == "origin_asn" and .value == "64511") | .here] == [[{"provider_asn":64501,"points_at":"unknown","via_reporting":1,"via_degraded":1,"elsewhere_reporting":0,"elsewhere_degraded":0}]]' "member-a world view should compare its AS64511 loss through AS64501 with b's"
need_api a /api/herd/map '([.countries[] | select(.members > 0) | .country] | sort) == ["DE","JP","US"]' "member-a map should list the three members' countries"
need_api a '/api/herd/monitor?origin_asn=64511' '([.series[].asn] | unique) == [64496,64497,64498]' "member-a monitor for AS64511 should list the three members"
for asn_m in 64496 64497 64498; do
	need_api a "/api/herd/search?origin_asn=64511&member=$asn_m" '(.hits | length) > 0' "member-a search should find AS64511 records from AS$asn_m"
done
need_api a '/api/herd/search?origin_asn=64511&member=64499' '(.hits | length) == 0' "the seed shares no records"
bash lab/ui-smoke.sh "http://${ip[a]}:8080/herd.html" \
	'World view' '2 of 2 members see loss (pooled by origin AS)' 'Counts are RPKI-verified members' 'loss, not counted' \
	'this node (AS64496), US, via AS64501, icmp' ', DE, via AS64501, icmp' ', JP, via AS64501, icmp' \
	'>AS64497<' '>AS64498<' '>AS64499<' '>hub<' '>exchange<' '>RPKI<' '>unverified<' \
	'This node through AS64501: points at nothing clear (other members through AS64501: 1 of 1 see loss; through other providers: 0 of 0).' \
	--absent 'No target shows loss' || fail "member-a /herd.html does not show the world view"

echo "6. hints: member-a probes what verified b sees degraded, and steers nothing"
need_api a /api/herd '[.hints[] | select(.prefix == "192.0.2.224/28" and .vantages == 1)] | length == 1' "member-a should hold a hint for 192.0.2.224/28 from member-b" 150
need_api a /api/probes '[.probes[].prefix] | index("192.0.2.224/28") != null' "member-a should probe the hinted route, which no static target lists" 60
no_steer a "after a hint"

echo "7. crowd threshold: member-c holds back its flow-only route"
need_api c '/api/herd/vantages?prefix=192.0.2.224/28' '[.vantages[] | select(.local)] | length == 1' "member-c should have measured its flow route" 150
prev=$(api c '/api/herd/preview?prefix=192.0.2.224/28&nonce=lab')
printf '%s' "$prev" | jq -e '.granularity == "route" and (.records | length) == 0' >/dev/null || fail "member-c serves its flow-only route below crowd_k: $prev"
prev=$(api c '/api/herd/preview?prefix=192.0.2.192/27&nonce=lab')
printf '%s' "$prev" | jq -e '(.records | length) > 0 and all(.records[]; .prefix == "192.0.2.192/27")' >/dev/null || fail "member-c should serve its static route at route level: $prev"
need_api a '/api/herd/vantages?prefix=192.0.2.224/28' '(.vantages | length) == 0' "no member may hold member-c's flow-only route"

echo "8. nothing on the never-shared list reaches a response, and preview equals a pull"
for m in a b; do
	prev=$(api "$m" '/api/herd/preview?origin_asn=64510&nonce=lab')
	if [ -z "$prev" ] || ! printf '%s' "$prev" | jq -e '(.records | length) > 0 and .granularity == "origin_asn" and (.signature | length) > 0' >/dev/null; then
		fail "member-$m preview has no signed origin-level records: $prev"
	fi
	for leak in 192.0.2.128 192.0.2.130 192.0.2.192 192.0.2.200 lab-upstream-secret '"prefix"' as_path; do
		if printf '%s' "$prev" | grep -q "$leak"; then
			printf '%s\n' "$prev" >&2
			fail "member-$m preview contains $leak"
		fi
	done
done
prevc=$(api c '/api/herd/preview?origin_asn=64510')
printf '%s' "$prevc" | jq -e '(.records | length) == 0' >/dev/null || fail "member-c serves records for an excluded prefix: $prevc"

echo "9. the served-response audit records the pulls"
need_log member-a 'action=herd\.serve target=.*nonce=' "member-a logged no served pull"
need_log member-b 'action=herd\.serve target=.*nonce=' "member-b logged no served pull"
need_log member-c 'action=herd\.serve target=.*origin_asn=64510' "member-c logged no served origin_asn query"

stamp() { api "$1" /api/probes | jq -r '[.. | .time? // empty] | max // empty' 2>/dev/null || true; }

echo "10. local view: member-b blocks c and down-weights a; a's view is unchanged"
cid=$(keyid c)
need_api b /api/herd "([.blocked[] | {url, key_id, records_pulled}] == [{\"url\":\"https://${ip[c]}:9444\",\"key_id\":\"$cid\",\"records_pulled\":0}]) and ([.peers[] | select(.key_id == \"$cid\")] | length == 0) and ([.peers[] | select(.asn == 64496) | .down_weighted] == [true])" "member-b should list c as blocked, never pulled, and a as down-weighted"
need_api b '/api/herd/vantages?prefix=192.0.2.192/27' '(.vantages | length) == 0' "member-b must show none of the blocked member-c's rows"
need_api a '/api/herd/vantages?prefix=192.0.2.192/27' '(.vantages | length) == 1 and .vantages[0].asn == 64498' "member-a, which blocks nobody, should still show member-c's route"
need_api b /api/herd/overview '(any(.members[]; .asn == 64498) | not) and ([.members[] | select(.asn == 64496) | .down_weighted] == [true])' "member-b overview must not list c and must mark a down-weighted"
need_api b /api/herd/events '[.events[] | select(.kind == "origin_asn" and .value == "64511" and .reporting == 1 and .degraded == 1 and ([.vantages[] | select(.asn == 64496 and .down_weighted and (.counted | not))] | length == 1))] | length == 1' "member-b world view should list a's row for AS64511 and not count it"
need_api a /api/herd/events '[.events[] | select(.kind == "origin_asn" and .value == "64511" and .reporting == 2 and .degraded == 2)] | length == 1' "member-a world view must still count a and b: b's down-weight is b's view only"
before=$(stamp b)
sleep 8
after=$(stamp b)
if [ -z "$after" ] || [ "$after" = "$before" ]; then
	fail "member-b probe results did not advance with a block and a down-weight ($before -> $after)"
fi
api b /readyz | jq -e '.ready == true' >/dev/null || fail "member-b is not ready with a block and a down-weight"
no_steer b "with a block and a down-weight"

echo "11. attribution on member-b: with a down-weighted, no other member counts"
need_api b /api/herd/events '[.events[] | select(.kind == "origin_asn" and .value == "64511") | .here[] | select(.provider_asn == 64501 and .points_at == "unknown" and .via_reporting == 0)] | length == 1' "member-b attribution must not count the down-weighted member-a"

echo "12. outage second opinion: member-a's AS64501 incident is annotated, nothing steers"
need_api a '/api/events?limit=1000' '[.events[] | select(.kind == "outage.as" and .fields.asn == "64501" and (.message | startswith("AS 64501 degraded across ")) and .fields.herd_asn == "64501" and .fields.herd_reporting == "1" and .fields.herd_degraded == "1")] | length >= 1' "member-a outage incident for AS64501 should say 1 of 1 verified members sees AS64501 degraded" 150
no_steer a "after an annotated outage incident"

echo "13. a peer that never answers does not stop probing or the other members"
"${compose[@]}" pause member-b
need_api a /api/herd '[.peers[] | select(.failures > 0 and .last_error != "")] | length == 1' "member-a does not report the paused peer as failing" 120
need_api c /api/herd '[.peers[] | select(.failures > 0)] | length == 1' "member-c does not report the paused peer as failing" 120
before=$(stamp a)
sleep 8
after=$(stamp a)
if [ -z "$after" ] || [ "$after" = "$before" ]; then
	fail "member-a probe results did not advance while a peer was paused ($before -> $after)"
fi
api a /readyz | jq -e '.ready == true' >/dev/null || fail "member-a is not ready with a paused peer"
"${compose[@]}" unpause member-b

echo "14. SIGTERM: a member with herd on exits"
"${compose[@]}" kill -s SIGTERM member-a
for i in $(seq 1 20); do
	if [ "$("${compose[@]}" ps -q --status running member-a | wc -l)" -eq 0 ]; then
		break
	fi
	sleep 1
done
if [ "$("${compose[@]}" ps -q --status running member-a | wc -l)" -ne 0 ]; then
	fail "member-a did not exit on SIGTERM"
fi
echo "herd lab: ok"
