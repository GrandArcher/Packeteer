#!/bin/bash
# RPKI-invalid only paths (#401) against a real Routinator (#627).
# Documentation prefixes and documentation/private ASNs only. Routinator
# has no trust anchor and fetches nothing: it serves the lab ROAs from a
# local SLURM file (lab/only-invalid/roas.json) plus the exceptions file
# Packeteer writes. Packeteer runs in observe mode.
#
# transit-a sends the edge 198.51.100.0/24 from AS64500 (the ROA
# 198.51.100.0/22 maxLength 22 makes it invalid; nothing covers it) and
# 203.0.113.0/24 (valid) and 203.0.113.128/25 (invalid) from AS64501. The
# edge passes them to Packeteer. Checked:
#  - 198.51.100.0/24 raises rpki.only_invalid, classed stale_roa from the
#    IRR route object and the same-origin ROA, with the evidence; the
#    invalid 203.0.113.128/25, which the valid /24 covers, raises nothing;
#  - proposing writes nothing; after the admin approves, the SLURM file
#    holds exactly the proposed prefixAssertion, Routinator serves the
#    route as valid, the case clears with rpki.only_invalid_cleared, and
#    the audit log has the proposal, the approval, and the write;
#  - the edge receives no route from Packeteer at any sample, and SIGTERM
#    stops it cleanly.
set -euo pipefail

root=$(cd "$(dirname "$0")/.." && pwd)
cd "$root"
compose=(docker compose -f lab/docker-compose-only-invalid.yml)

check_bin=$(mktemp)
SLURM_DIR=$(mktemp -d)
export SLURM_DIR
# Routinator runs as an unprivileged user and only reads the directory.
chmod 755 "$SLURM_DIR"
trap 'rc=$?; if [ "$rc" -ne 0 ]; then echo "---- lab logs ----"; "${compose[@]}" logs --no-color || true; "${compose[@]}" ps || true; fi; "${compose[@]}" down -v --remove-orphans || true; rm -rf "$check_bin" "$SLURM_DIR"; exit "$rc"' EXIT

# Routinator refuses to start on a missing exceptions file, so it starts
# with an empty RFC 8416 document.
printf '%s\n' '{"slurmVersion":1,"validationOutputFilters":{"prefixFilters":[],"bgpsecFilters":[]},"locallyAddedAssertions":{"prefixAssertions":[],"bgpsecAssertions":[]}}' >"$SLURM_DIR/slurm.json"
chmod 644 "$SLURM_DIR/slurm.json"
empty_slurm=$(cat "$SLURM_DIR/slurm.json")

echo "building path check"
go build -o "$check_bin" ./lab/checkpath

echo "building lab"
"${compose[@]}" build
"${compose[@]}" up -d

stale=198.51.100.0/24
covered=203.0.113.128/25
base=http://192.0.2.10:8080/api
routinator=http://192.0.2.40:8323

# Lab-only basic auth (docker-compose-only-invalid.yml). It is the one
# account, so it may propose and approve.
auth=(-u lab:lab-only)
api() { curl -sS "${auth[@]}" "$base/$1" 2>/dev/null || true; }
api_up() { curl -sf -o /dev/null "${auth[@]}" "$base/rpki/only-invalid"; }
post() { curl -sS -w '\n%{http_code}' "${auth[@]}" -H 'Content-Type: application/json' -d "$2" "$base/$1"; }

vty() { "${compose[@]}" exec -T edge vtysh -c "$1" 2>/dev/null || true; }

# validity ASN PREFIX: Routinator's answer for the route.
validity() {
	curl -sS "$routinator/api/v1/validity/$1/$2" 2>/dev/null | jq -r '.validated_route.validity.state // empty' 2>/dev/null || true
}

# edge_path PREFIX ASPATH: the edge's best path, from transit-a.
edge_path() {
	vty "show bgp ipv4 unicast $1 json" | "$check_bin" -aspath "$2" -nexthop 192.0.2.21 -lacks 64512:
}

session_up() { [[ "$(vty 'show bgp neighbors 192.0.2.10')" == *"BGP state = Established"* ]]; }

# received: how many routes the edge got from Packeteer, before policy.
received() {
	local s r
	s=$(vty 'show bgp ipv4 unicast summary json' | jq -r '(.ipv4Unicast.peers // .peers)["192.0.2.10"].pfxRcd // empty' 2>/dev/null || true)
	r=$(vty 'show bgp ipv4 unicast neighbors 192.0.2.10 received-routes json' | jq -r '(.receivedRoutes // {}) | length' 2>/dev/null || true)
	echo "${s:-?}/${r:-?}"
}

dump() {
	for r in edge transit-a; do
		echo "---- $r ----" >&2
		"${compose[@]}" exec -T "$r" vtysh -c 'show bgp summary' -c 'show bgp ipv4 unicast' >&2 || true
	done
	echo "---- only-invalid ----" >&2
	api rpki/only-invalid >&2
	echo "---- slurm file ----" >&2
	cat "$SLURM_DIR/slurm.json" >&2 || true
	echo "---- routinator ----" >&2
	curl -sS "$routinator/json" >&2 || true
	"${compose[@]}" logs --no-color packeteer >&2 || true
}

# only_transit: every path in the edge's table came from transit-a.
only_transit() {
	vty 'show bgp ipv4 unicast json' | jq -e '[.routes[][] | .peerId] | length > 0 and all(. == "192.0.2.21")' >/dev/null 2>&1
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
# wait_for SECONDS WHAT CMD...
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

routinator_up() { [ "$(curl -sS "$routinator/json" 2>/dev/null | jq '.roas | length' 2>/dev/null || true)" = 2 ]; }
state_is() { [ "$(validity "$1" "$2")" = "$3" ]; }

echo "waiting for Routinator (local SLURM data only), the edge paths, and the Packeteer session"
wait_for 120 "routinator serving the two lab ROAs" routinator_up
state_is AS64500 "$stale" invalid || fail "routinator: $stale from AS64500 is not invalid"
state_is AS64501 203.0.113.0/24 valid || fail "routinator: 203.0.113.0/24 from AS64501 is not valid"
state_is AS64501 "$covered" invalid || fail "routinator: $covered from AS64501 is not invalid"
wait_for 120 "edge path for $stale" edge_path "$stale" "64496 64500"
wait_for 60 "edge path for $covered" edge_path "$covered" "64496 64501"
wait_for 60 "edge path for 203.0.113.0/24" edge_path 203.0.113.0/24 "64496 64501"
wait_for 120 "packeteer session" session_up
wait_for 60 "ops API" api_up
checked=1
quiet

# learned PREFIX ORIGIN: Packeteer's RIB view holds exactly that route.
learned() {
	api "troubleshoot/lookingglass?prefix=$1" | jq -e --arg p "$1" --argjson o "$2" \
		'.exact.prefix == $p and .exact.as_path[-1] == $o and .exact.provider == "transit-a"' >/dev/null
}
wait_for 60 "packeteer learned $stale" learned "$stale" 64500
wait_for 60 "packeteer learned $covered" learned "$covered" 64501

# The first scan runs a minute after start and the next five minutes
# later. The IRR file is read in the background on the first lookup, so
# the first scan may class the case unclear; the second has the route
# object. A scan that finds the RIB not ready yet skips, so three scans fit.
stale_case() {
	api "rpki/only-invalid?prefix=$stale" | jq -e --arg p "$stale" '.cases | length == 1 and
		(.[0] | .prefix == $p and .origin == 64500 and .class == "stale_roa" and .rpki_source == "routinator" and
		(.vrps | any(.prefix == "198.51.100.0/22" and .max_length == 22 and .asn == 64500)) and
		(.signals | any(.name == "irr_route" and .points == 2)) and
		(.signals | any(.name == "roa_same_origin" and .points == 1)) and
		(.paths | length == 1 and .[0].provider == "transit-a" and .[0].as_path == [64496, 64500]))' >/dev/null
}
echo "waiting for the $stale case (up to three scans)"
wait_for 700 "$stale classed stale_roa" stale_case

cases=$(api rpki/only-invalid | jq -c '[.cases[].prefix]')
[ "$cases" = "[\"$stale\"]" ] || fail "open cases are $cases, want only $stale ($covered is covered by a valid route)"

events() { api "events?limit=1000" | jq -c --arg k "$1" '[.events[] | select(.kind == $k)]'; }
raised=$(events rpki.only_invalid)
jq -e --arg p "$stale" 'any(.fields.prefix == $p and .fields.origin == "64500" and .fields.class == "stale_roa" and
	(.fields.evidence | contains("rpki_source=routinator") and contains("vrp 198.51.100.0/22-22 AS64500") and contains("irr_route +2")))' <<<"$raised" >/dev/null ||
	fail "no rpki.only_invalid event for $stale classed stale_roa with the evidence: $raised"
jq -e 'all(.fields.prefix | startswith("203.0.113.") | not)' <<<"$raised" >/dev/null ||
	fail "rpki.only_invalid raised for a prefix a valid route covers: $raised"

echo "propose: nothing is written"
resp=$(post rpki/only-invalid/propose "{\"prefix\":\"$stale\"}")
code=$(tail -n1 <<<"$resp")
prop=$(sed '$d' <<<"$resp")
[ "$code" = 200 ] || fail "propose answered $code: $prop"
jq -e --arg p "$stale" '.prefix == $p and .origin == 64500 and .kind == "prefix_assertion" and
	.state_before == "invalid" and .state_after == "valid" and .path == "/var/lib/packeteer/slurm/slurm.json" and
	([.entries.locallyAddedAssertions.prefixAssertions[] | {prefix, asn, maxPrefixLength}] == [{prefix: $p, asn: 64500, maxPrefixLength: 24}]) and
	.entries.validationOutputFilters.prefixFilters == []' <<<"$prop" >/dev/null || fail "unexpected proposal: $prop"
id=$(jq -r .id <<<"$prop")
digest=$(jq -r .digest <<<"$prop")
sleep 10
[ "$(cat "$SLURM_DIR/slurm.json")" = "$empty_slurm" ] || fail "proposing changed the SLURM file"
state_is AS64500 "$stale" invalid || fail "routinator turned $stale valid before the approval"
stale_case || fail "the case changed before the approval"

echo "approve: Packeteer writes the exception and Routinator serves it"
resp=$(post rpki/exceptions "{\"id\":\"$id\",\"digest\":\"$digest\"}")
code=$(tail -n1 <<<"$resp")
[ "$code" = 200 ] || fail "approve answered $code: $(sed '$d' <<<"$resp")"
jq -e --arg p "$stale" --arg id "$id" '[.locallyAddedAssertions.prefixAssertions[] | select(.prefix == $p)] |
	length == 1 and .[0].asn == 64500 and .[0].maxPrefixLength == 24 and (.[0].comment | startswith("packeteer audit=" + $id + " "))' \
	"$SLURM_DIR/slurm.json" >/dev/null || fail "the SLURM file does not hold the approved entry: $(cat "$SLURM_DIR/slurm.json")"
wait_for 60 "routinator serving $stale from AS64500 as valid" state_is AS64500 "$stale" valid
state_is AS64501 "$covered" invalid || fail "the exception changed $covered"

echo "the case clears on the next scan"
cleared() {
	api rpki/only-invalid | jq -e '.cases == []' >/dev/null &&
		events rpki.only_invalid_cleared | jq -e --arg p "$stale" 'any(.fields.prefix == $p and .fields.origin == "64500")' >/dev/null
}
wait_for 420 "$stale cleared" cleared
api rpki/only-invalid | jq -e --arg p "$stale" --arg id "$id" \
	'.slurm.exceptions | any(.prefix == $p and .asn == 64500 and .max_length == 24 and .audit_id == $id)' >/dev/null ||
	fail "the API does not list the written exception"

echo "audit log: proposal, approval, write"
audit=$(api "audit?limit=1000")
for action in rpki.slurm.propose rpki.slurm.approve rpki.slurm.write; do
	jq -e --arg a "$action" --arg p "$stale" 'any(.records[]; .action == $a and .result == "ok" and ((.target + " " + .detail) | contains($p)))' <<<"$audit" >/dev/null ||
		fail "the audit log has no $action record for $stale: $audit"
done
jq -e --arg id "$id" 'any(.records[]; .action == "rpki.slurm.propose" and .id == $id)' <<<"$audit" >/dev/null ||
	fail "the proposal id $id is not its audit record"

quiet
api overview | jq -e '.mode == "observe"' >/dev/null || fail "packeteer is not in observe mode"

echo "SIGTERM: packeteer stops cleanly"
"${compose[@]}" stop -t 20 packeteer
code=$(docker inspect -f '{{.State.ExitCode}}' "$("${compose[@]}" ps -aq packeteer)")
[ "$code" = 0 ] || fail "packeteer exited $code on SIGTERM"
only_transit || fail "the edge holds a route that did not come from transit-a"

echo "RPKI-invalid only path lab passed"
