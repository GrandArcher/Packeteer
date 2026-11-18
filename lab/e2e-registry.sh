#!/bin/bash
# Registry hygiene (#289) proved in the lab (#657) against in-lab registry
# stand-ins only. Documentation prefixes and documentation/private ASNs
# only. lab/registrystub is the IRR (whois), VRP JSON, PeeringDB, and RIPE
# REST stand-in; the lab network is internal, so nothing can reach RADB,
# ARIN, RIPE, PeeringDB, or any other public registry. Packeteer runs in
# observe mode.
#
# transit-a sends the edge 203.0.113.0/24 and 203.0.113.128/25 from AS64501.
# The stand-in registers only the /24 (and a 192.0.2.0/24 route object that
# nobody announces), has a ROA for the /24 with maxLength 24, lists one
# prefix in PeeringDB where two are announced, and lists a 1000 Mbps port
# where the config says 10000. Checked:
#  - the network is internal, and the stand-in is the only registry the
#    scan reads (every stand-in request is whois, PeeringDB, the VRP
#    document, or the RIPE REST API; none is a write before a push);
#  - the first scan reports exactly: a missing route object, a stale route
#    object (shown, not yet offered for delete), a ROA gap (maxLength), a
#    PeeringDB max-prefix drift, and a PeeringDB port-speed drift;
#  - a push with a digest other than the shown one is refused and changes
#    nothing; with the shown digest, the route object and the two PeeringDB
#    fields change on the stand-in, with the lab credentials from the
#    environment, and each push is in the audit log without a credential;
#  - a ROA finding and the not-yet-offered delete cannot be pushed;
#  - the edge receives no route from Packeteer, the mode stays observe, and
#    SIGTERM stops it cleanly.
set -euo pipefail

root=$(cd "$(dirname "$0")/.." && pwd)
cd "$root"
compose=(docker compose -f lab/docker-compose-registry.yml)

check_bin=$(mktemp)
LAB_DIR=$(mktemp -d)
export LAB_DIR
trap 'rc=$?; if [ "$rc" -ne 0 ]; then echo "---- lab logs ----"; "${compose[@]}" logs --no-color || true; "${compose[@]}" ps || true; fi; "${compose[@]}" down -v --remove-orphans || true; rm -rf "$check_bin" "$LAB_DIR"; exit "$rc"' EXIT

echo "building the path check, the registry stand-in, and the lab certificate"
go build -o "$check_bin" ./lab/checkpath
mkdir -p "$LAB_DIR/stub" "$LAB_DIR/certs"
CGO_ENABLED=0 GOOS=linux GOARCH="$(go env GOARCH)" go build -o "$LAB_DIR/stub/registrystub" ./lab/registrystub
certs_bin=$(mktemp)
go build -o "$certs_bin" ./lab/mkcerts
"$certs_bin" "$LAB_DIR/certs" registry-stub
rm -f "$certs_bin"
# The containers read these as other users; the keys protect nothing.
chmod 755 "$LAB_DIR" "$LAB_DIR/stub" "$LAB_DIR/certs" "$LAB_DIR/stub/registrystub"

echo "building lab"
"${compose[@]}" build
"${compose[@]}" up -d

base=http://192.0.2.10:8080/api
stub=http://192.0.2.40:8323/_lab/state
new_net=203.0.113.128/25
all_net=203.0.113.0/24

# Lab-only basic auth (docker-compose-registry.yml): the admin that may push.
auth=(-u lab:lab-only)
api() { curl -sS "${auth[@]}" "$base/$1" 2>/dev/null || true; }
api_up() { curl -sf -o /dev/null "${auth[@]}" "$base/registry"; }
post() { curl -sS -w '\n%{http_code}' "${auth[@]}" -H 'Content-Type: application/json' -d "$2" "$base/$1"; }
state() { curl -sS "$stub" 2>/dev/null || true; }

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
	echo "---- registry ----" >&2
	api registry >&2
	echo "---- stand-in state ----" >&2
	state >&2
	"${compose[@]}" logs --no-color packeteer registry-stub >&2 || true
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
for svc in packeteer registry-stub edge transit-a; do
	[ "$("${compose[@]}" ps -q "$svc" | xargs docker inspect -f '{{len .NetworkSettings.Networks}}')" = 1 ] || fail "$svc is on more than one network"
done

echo "waiting for the edge paths, the Packeteer session, and the stand-in"
wait_for 120 "edge path for $all_net" edge_path "$all_net" "64496 64501"
wait_for 60 "edge path for $new_net" edge_path "$new_net" "64496 64501"
wait_for 120 "packeteer session" session_up
wait_for 60 "ops API" api_up
wait_for 60 "registry stand-in" bash -c "curl -sf -o /dev/null $stub"
checked=1
quiet

learned() {
	api "troubleshoot/lookingglass?prefix=$1" | jq -e --arg p "$1" \
		'.exact.prefix == $p and .exact.as_path[-1] == 64501 and .exact.provider == "transit-a"' >/dev/null
}
wait_for 60 "packeteer learned $all_net" learned "$all_net"
wait_for 60 "packeteer learned $new_net" learned "$new_net"

# The first scan runs a minute after start.
scanned() { api registry | jq -e '.scanned != null and (.sections | length) > 0' >/dev/null; }
echo "waiting for the first scan"
wait_for 240 "the first registry scan" scanned
# The scan runs a minute after Packeteer starts and the next one an hour
# later. A slow runner can start it before the learned RIB is ready; the
# scan then skips the network, and a restart gives a new first scan.
for _ in 1 2; do
	api registry | jq -e '[.sections[] | select(.name == "network" and .status == "skipped")] | length == 0' >/dev/null && break
	echo "the first scan ran before the RIB was ready; restarting packeteer for a new first scan"
	"${compose[@]}" restart -t 20 packeteer
	wait_for 120 "packeteer session" session_up
	wait_for 60 "ops API" api_up
	wait_for 60 "packeteer learned $all_net" learned "$all_net"
	wait_for 60 "packeteer learned $new_net" learned "$new_net"
	wait_for 240 "the new first registry scan" scanned
done

rep=$(api registry)
jq -e '.push_enabled == true' <<<"$rep" >/dev/null || fail "push_enabled is not on in the lab config"
jq -e '[.sections[] | select(.name == "irr" or .name == "rpki" or .name == "peeringdb")] | length == 3 and all(.status == "ok")' <<<"$rep" >/dev/null ||
	fail "an IRR, RPKI, or PeeringDB section is not ok: $(jq -c .sections <<<"$rep")"

want='["irr_missing | 203.0.113.128/25 AS64501","irr_stale | 192.0.2.0/24 AS64501 TEST","pdb_ix_speed | AS64501 ix-lab 198.51.100.130 speed","pdb_maxprefix | AS64501 info_prefixes4","rpki_maxlength | 203.0.113.128/25 AS64501"]'
got=$(jq -c '[.findings[] | .kind + " | " + .subject] | sort' <<<"$rep")
[ "$got" = "$want" ] || fail "findings are $got, want $want"
f() { jq -c --arg k "$1" '.findings[] | select(.kind == $k)' <<<"$rep"; }

echo "the diffs"
f irr_missing | jq -e '.severity == "warning" and .pushable == true and (.digest | length > 0) and .change.op == "create_object" and .change.class == "route" and
	(.diff | contains("+ route:") and contains("203.0.113.128/25") and contains("origin:         AS64501") and contains("mnt-by:         MAINT-LAB") and contains("source:         TEST"))' >/dev/null ||
	fail "irr_missing: $(f irr_missing)"
f irr_stale | jq -e '(.diff | contains("- route:          192.0.2.0/24") and contains("AS64501")) and .pushable == false and .change == null and (.note | contains("next scan"))' >/dev/null ||
	fail "irr_stale: $(f irr_stale)"
f rpki_maxlength | jq -e '.severity == "error" and .pushable == false and .change == null and (.message | contains("203.0.113.0/24") and contains("/24")) and
	(.diff | contains("maxLength 24") and contains("maxLength 25"))' >/dev/null || fail "rpki_maxlength: $(f rpki_maxlength)"
f pdb_maxprefix | jq -e '.pushable == true and .change.op == "update_field" and .change.field == "info_prefixes4" and .change.old == "1" and .change.new == "3" and
	(.diff | contains("- info_prefixes4: 1") and contains("+ info_prefixes4: 3"))' >/dev/null || fail "pdb_maxprefix: $(f pdb_maxprefix)"
f pdb_ix_speed | jq -e '.pushable == true and .change.op == "update_field" and .change.class == "netixlan" and .change.field == "speed" and .change.old == "1000" and .change.new == "10000" and
	(.diff | contains("- speed: 1000") and contains("+ speed: 10000"))' >/dev/null || fail "pdb_ix_speed: $(f pdb_ix_speed)"

echo "the scan only read the stand-in"
st=$(state)
jq -e '.requests | length > 0 and all(.service == "whois" or .service == "peeringdb" or .service == "vrp" or .service == "ripe")' <<<"$st" >/dev/null || fail "unexpected stand-in traffic: $st"
jq -e '[.requests[] | select(.method != "GET" and .method != "QUERY")] | length == 0' <<<"$st" >/dev/null || fail "the scan wrote to the stand-in: $st"
jq -e '[.requests[].service] | index("whois") != null and index("peeringdb") != null and index("vrp") != null' <<<"$st" >/dev/null || fail "the scan did not read all three stand-ins: $st"
routes_before=$(jq -c .routes <<<"$st")
jq -e '.peeringdb["net/1"].info_prefixes4 == 1 and .peeringdb["netixlan/11"].speed == 1000' <<<"$st" >/dev/null || fail "unexpected stand-in data: $st"

push() { post registry/push "{\"id\":\"$1\",\"digest\":\"$2\"}"; }
code_of() { tail -n1 <<<"$1"; }

echo "a wrong digest, a ROA, and the not-yet-offered delete change nothing"
id_missing=$(f irr_missing | jq -r .id)
digest_missing=$(f irr_missing | jq -r .digest)
resp=$(push "$id_missing" 0000000000000000)
[ "$(code_of "$resp")" = 409 ] || fail "a wrong digest answered $(code_of "$resp"): $resp"
resp=$(push "$(f rpki_maxlength | jq -r .id)" "")
[ "$(code_of "$resp")" = 409 ] || fail "a ROA finding answered $(code_of "$resp"): $resp"
resp=$(push "$(f irr_stale | jq -r .id)" "")
[ "$(code_of "$resp")" = 409 ] || fail "the stale delete answered $(code_of "$resp"): $resp"
st=$(state)
jq -e '[.requests[] | select(.method != "GET" and .method != "QUERY")] | length == 0' <<<"$st" >/dev/null || fail "a refused push wrote to the stand-in: $st"
[ "$(jq -c .routes <<<"$st")" = "$routes_before" ] || fail "a refused push changed the route objects"

echo "confirmed pushes reach the stand-in with the lab credentials"
resp=$(push "$id_missing" "$digest_missing")
[ "$(code_of "$resp")" = 200 ] || fail "the route object push answered $(code_of "$resp"): $resp"
for kind in pdb_maxprefix pdb_ix_speed; do
	resp=$(push "$(f "$kind" | jq -r .id)" "$(f "$kind" | jq -r .digest)")
	[ "$(code_of "$resp")" = 200 ] || fail "the $kind push answered $(code_of "$resp"): $resp"
done
resp=$(push "$id_missing" "$digest_missing")
[ "$(code_of "$resp")" = 409 ] || fail "the same change pushed twice answered $(code_of "$resp"): $resp"

st=$(state)
jq -e '.routes | length == 3 and (map(select(contains("route:          203.0.113.128/25") and contains("origin:         AS64501") and contains("source:         TEST"))) | length == 1) and
	(map(select(contains("192.0.2.0/24"))) | length == 1)' <<<"$st" >/dev/null || fail "route objects after the pushes: $(jq -c .routes <<<"$st")"
jq -e '.peeringdb["net/1"].info_prefixes4 == 3 and .peeringdb["netixlan/11"].speed == 10000' <<<"$st" >/dev/null || fail "PeeringDB records after the pushes: $(jq -c .peeringdb <<<"$st")"
jq -e '[.requests[] | select(.method != "GET" and .method != "QUERY")] | length == 3 and all(.authorized == true) and
	(map(.service) | sort == ["peeringdb", "peeringdb", "ripe"]) and (map(.method) | sort == ["POST", "PUT", "PUT"])' <<<"$st" >/dev/null || fail "stand-in writes: $(jq -c '[.requests[] | select(.method != "GET" and .method != "QUERY")]' <<<"$st")"

echo "audit log: each push, no credential"
audit=$(api "audit?limit=1000")
jq -e 'any(.records[]; .action == "POST /api/registry/push" and .result == "ok" and .target == "ripe route 203.0.113.128/25AS64501" and (.detail | contains("registry push create_object") and contains("203.0.113.128/25")))' <<<"$audit" >/dev/null ||
	fail "no audit record for the route object push: $audit"
jq -e 'any(.records[]; .action == "POST /api/registry/push" and .result == "ok" and (.detail | contains("registry push update_field info_prefixes4: 1 -> 3")))' <<<"$audit" >/dev/null ||
	fail "no audit record for the max-prefix push: $audit"
jq -e 'any(.records[]; .action == "POST /api/registry/push" and .result == "ok" and (.detail | contains("registry push update_field speed: 1000 -> 10000")))' <<<"$audit" >/dev/null ||
	fail "no audit record for the port-speed push: $audit"
jq -e 'any(.records[]; .action == "POST /api/registry/push" and .result == "failed" and (.detail | contains("differs from the one shown")))' <<<"$audit" >/dev/null ||
	fail "no audit record for the refused digest: $audit"
for secret in lab-ripe-password-not-a-secret lab-peeringdb-key-not-a-secret; do
	if grep -q "$secret" <<<"$audit$(api registry)"; then fail "the audit log or the API holds a credential"; fi
	if "${compose[@]}" logs --no-color packeteer | grep -q "$secret"; then fail "the Packeteer log holds a credential"; fi
done

quiet
api overview | jq -e '.mode == "observe"' >/dev/null || fail "packeteer is not in observe mode"

echo "SIGTERM: packeteer stops cleanly"
"${compose[@]}" stop -t 20 packeteer
code=$(docker inspect -f '{{.State.ExitCode}}' "$("${compose[@]}" ps -aq packeteer)")
[ "$code" = 0 ] || fail "packeteer exited $code on SIGTERM"
only_transit || fail "the edge holds a route that did not come from transit-a"

echo "registry hygiene lab passed"
