#!/bin/bash
# RIS and RouteViews origin agreement for RPKI-invalid only paths (#401),
# lab-proven (#671) against in-lab stand-ins only. Documentation prefixes
# and documentation/private ASNs only. lab/collectorstub is the RIS and
# RouteViews stand-in and the VRP document; the lab network is internal, so
# nothing can reach RIPE RIS, RouteViews, or any other live collector.
# Packeteer runs in observe mode.
#
# transit-a sends the edge three /25s that are longer than the lab ROAs'
# maxLength, so each is RPKI-invalid with nothing covering it:
#   198.51.100.0/25 from AS64500: both stand-ins list AS64500 (agreement);
#   203.0.113.0/25 from AS64501: RIS lists AS64501, RouteViews lists only
#     AS64511 (disagreement);
#   203.0.113.128/25 from AS64501: neither stand-in has it (empty answer).
# Checked:
#  - the network is internal, and every request the stand-ins got is a GET
#    for one of the three prefixes;
#  - each case carries the origin_agreement signal with the right points and
#    detail, and agreement alone does not class a case stale_roa;
#  - with both collectors stopped (down), every case has no agreement
#    (0 points) and the score of a case with no collector, and stays open;
#  - the edge receives no route from Packeteer at any sample, the mode stays
#    observe, and SIGTERM stops it cleanly.
set -euo pipefail

root=$(cd "$(dirname "$0")/.." && pwd)
cd "$root"
compose=(docker compose -f lab/docker-compose-origin-agreement.yml)

check_bin=$(mktemp)
LAB_DIR=$(mktemp -d)
export LAB_DIR
trap 'rc=$?; if [ "$rc" -ne 0 ]; then echo "---- lab logs ----"; "${compose[@]}" logs --no-color || true; "${compose[@]}" ps || true; fi; "${compose[@]}" down -v --remove-orphans || true; rm -rf "$check_bin" "$LAB_DIR"; exit "$rc"' EXIT

echo "building the path check and the collector stand-in"
go build -o "$check_bin" ./lab/checkpath
mkdir -p "$LAB_DIR/stub"
CGO_ENABLED=0 GOOS=linux GOARCH="$(go env GOARCH)" go build -o "$LAB_DIR/stub/collectorstub" ./lab/collectorstub
# The containers read these as other users.
chmod 755 "$LAB_DIR" "$LAB_DIR/stub" "$LAB_DIR/stub/collectorstub"

echo "building lab"
"${compose[@]}" build
"${compose[@]}" up -d

agree=198.51.100.0/25
disagree=203.0.113.0/25
empty=203.0.113.128/25
base=http://192.0.2.10:8080/api

# Lab-only basic auth (docker-compose-origin-agreement.yml).
auth=(-u lab:lab-only)
api() { curl -sS "${auth[@]}" "$base/$1" 2>/dev/null || true; }
api_up() { curl -sf -o /dev/null "${auth[@]}" "$base/rpki/only-invalid"; }
# state STUB: what the stand-in recorded.
state() { curl -sS "http://$1:8080/_lab/state" 2>/dev/null || true; }

vty() { "${compose[@]}" exec -T edge vtysh -c "$1" 2>/dev/null || true; }
edge_path() {
	vty "show bgp ipv4 unicast $1 json" | "$check_bin" -aspath "$2" -nexthop 192.0.2.21 -lacks 64512:
}
session_up() { [[ "$(vty 'show bgp neighbors 192.0.2.10')" == *"BGP state = Established"* ]]; }

received() {
	local s r
	s=$(vty 'show bgp ipv4 unicast summary json' | jq -r '(.ipv4Unicast.peers // .peers)["192.0.2.10"].pfxRcd // empty' 2>/dev/null || true)
	r=$(vty 'show bgp ipv4 unicast neighbors 192.0.2.10 received-routes json' | jq -r '(.receivedRoutes // {}) | length' 2>/dev/null || true)
	echo "${s:-?}/${r:-?}"
}
only_transit() {
	vty 'show bgp ipv4 unicast json' | jq -e '[.routes[][] | .peerId] | length > 0 and all(. == "192.0.2.21")' >/dev/null 2>&1
}

dump() {
	for r in edge transit-a; do
		echo "---- $r ----" >&2
		"${compose[@]}" exec -T "$r" vtysh -c 'show bgp summary' -c 'show bgp ipv4 unicast' >&2 || true
	done
	echo "---- only-invalid ----" >&2
	api rpki/only-invalid >&2
	for s in ris-stub routeviews-stub; do
		echo "---- $s state ----" >&2
		state "$s" >&2
	done
	"${compose[@]}" logs --no-color packeteer >&2 || true
}

# quiet: observe sends the edge nothing. Checked on every sample once the
# session is up.
quiet() {
	local n
	n=$(received)
	if [ "$n" != "0/0" ] || ! only_transit; then
		echo "the edge received routes from Packeteer (pfxRcd/received-routes $n)" >&2
		vty 'show bgp ipv4 unicast neighbors 192.0.2.10 received-routes' >&2
		dump
		exit 1
	fi
}

checked=0
wait_for() {
	local secs=$1 what=$2
	shift 2
	local end=$((SECONDS + secs))
	while [ "$SECONDS" -lt "$end" ]; do
		if [ "$checked" = 1 ]; then quiet; fi
		if "$@" 2>/dev/null; then
			return 0
		fi
		sleep 2
	done
	echo "timed out after ${secs}s waiting for: $what" >&2
	"$@" || true
	dump
	return 1
}

fail() {
	echo "$1" >&2
	dump
	exit 1
}

echo "the lab network has no route out"
net=$("${compose[@]}" ps -q packeteer | xargs docker inspect -f '{{range $k, $v := .NetworkSettings.Networks}}{{$k}} {{end}}')
[ "$(wc -w <<<"$net")" = 1 ] || fail "packeteer is on more than one network: $net"
[ "$(docker network inspect -f '{{.Internal}}' "${net// /}")" = true ] || fail "network $net is not internal"
for svc in packeteer ris-stub routeviews-stub vrp-stub edge transit-a; do
	[ "$("${compose[@]}" ps -q "$svc" | xargs docker inspect -f '{{len .NetworkSettings.Networks}}')" = 1 ] || fail "$svc is on more than one network"
done

echo "waiting for the edge paths, the Packeteer session, and the API"
wait_for 120 "edge path for $agree" edge_path "$agree" "64496 64500"
wait_for 60 "edge path for $disagree" edge_path "$disagree" "64496 64501"
wait_for 60 "edge path for $empty" edge_path "$empty" "64496 64501"
wait_for 120 "packeteer session" session_up
wait_for 60 "ops API" api_up
checked=1
quiet

learned() {
	api "troubleshoot/lookingglass?prefix=$1" | jq -e --arg p "$1" --argjson o "$2" \
		'.exact.prefix == $p and .exact.as_path[-1] == $o and .exact.provider == "transit-a"' >/dev/null
}
wait_for 60 "packeteer learned $agree" learned "$agree" 64500
wait_for 60 "packeteer learned $disagree" learned "$disagree" 64501
wait_for 60 "packeteer learned $empty" learned "$empty" 64501

# agreement PREFIX SCORE POINTS DETAIL: the open case for PREFIX has that
# score and an origin_agreement signal with exactly those points and detail.
agreement() {
	api rpki/only-invalid | jq -e --arg p "$1" --argjson score "$2" --argjson pts "$3" --arg d "$4" \
		'.cases | any(.prefix == $p and .score == $score and .class == "unclear" and
			(.signals | any(.name == "origin_agreement" and .points == $pts and .detail == $d)))' >/dev/null
}

# The first scan runs a minute after start and the next five minutes later;
# a scan that finds the RIB not ready yet skips.
echo "collectors up: agreement, disagreement, and an empty answer (up to three scans)"
agree_ok() { agreement "$agree" 3 2 "ris, routeviews see AS64500 as an origin"; }
disagree_ok() { agreement "$disagree" -1 -2 "not AS64501: routeviews sees AS64511"; }
empty_ok() { agreement "$empty" 1 0 "no collector reports an origin; no origin seen by ris, routeviews"; }
wait_for 700 "$agree agreed by both collectors" agree_ok
wait_for 60 "$disagree disagreed by routeviews" disagree_ok
wait_for 60 "$empty seen by neither collector" empty_ok

cases=$(api rpki/only-invalid | jq -c '[.cases[].prefix] | sort')
[ "$cases" = "[\"$agree\",\"$disagree\",\"$empty\"]" ] || fail "open cases are $cases, want the three /25s"
# ROA, route age, and provider signals stay as they were: agreement is
# added evidence, and it did not make a stale ROA of a case with no IRR or
# route age behind it.
api rpki/only-invalid | jq -e '.cases | all(.class != "stale_roa")' >/dev/null || fail "a case was classed stale_roa on collector agreement alone"
raised=$(api "events?limit=1000" | jq -c '[.events[] | select(.kind == "rpki.only_invalid")]')
jq -e --arg p "$agree" 'any(.fields.prefix == $p and (.fields.evidence | contains("origin_agreement +2: ris, routeviews see AS64500 as an origin")))' <<<"$raised" >/dev/null ||
	fail "no rpki.only_invalid event for $agree with the origin_agreement evidence: $raised"

echo "the stand-ins got only GET lookups for the three prefixes"
for s in ris-stub:ris routeviews-stub:routeviews; do
	host=${s%%:*} role=${s##*:}
	state "$host" | jq -e --arg role "$role" --arg a "$agree" --arg b "$disagree" --arg c "$empty" \
		'.role == $role and (.requests | length > 0) and
		(.requests | all(.method == "GET" and .path == ("/" + $role) and .status == 200 and (.prefix | IN($a, $b, $c)))) and
		([.requests[].prefix] | unique | length == 3)' >/dev/null || fail "unexpected requests at $host: $(state "$host")"
done

echo "collectors down: no agreement is invented"
"${compose[@]}" stop -t 5 ris-stub routeviews-stub
down_ok() {
	local d="no collector reports an origin; no answer from ris, routeviews"
	agreement "$agree" 1 0 "$d" && agreement "$disagree" 1 0 "$d" && agreement "$empty" 1 0 "$d"
}
wait_for 420 "every case without agreement while both collectors are down" down_ok
cases=$(api rpki/only-invalid | jq -c '[.cases[].prefix] | sort')
[ "$cases" = "[\"$agree\",\"$disagree\",\"$empty\"]" ] || fail "a down collector changed the open cases: $cases"
api rpki/only-invalid | jq -e '.cases | all(.class != "stale_roa")' >/dev/null || fail "a down collector produced a stale_roa case"

quiet
api overview | jq -e '.mode == "observe"' >/dev/null || fail "packeteer is not in observe mode"

echo "SIGTERM: packeteer stops cleanly"
"${compose[@]}" stop -t 20 packeteer
code=$(docker inspect -f '{{.State.ExitCode}}' "$("${compose[@]}" ps -aq packeteer)")
[ "$code" = 0 ] || fail "packeteer exited $code on SIGTERM"
only_transit || fail "the edge holds a route that did not come from transit-a"

echo "origin agreement lab passed"
