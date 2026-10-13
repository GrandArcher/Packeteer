# Mitigation: an RTBH route and a FlowSpec drop rule for 198.51.100.0/24,
# added through the ops API (lab/e2e-mitigation.sh's lab). Sourced by
# lab/e2e-failure-matrix.sh.
COMPOSE=(lab/docker-compose-mitigation.yml lab/failure-matrix/override.yml)
ROUTERS=(edge transit-a transit-b)
SVCS=(packeteer)
ACTIVE=packeteer
ACTIVE_TAG=-
HOLD_FILE=lab/frr-mit-edge/frr.conf
EVER="198.51.100.0/24 fs:198.51.100.0/24"
MAX_ROUTES=2
GEO_DB=lab/mitigation-country.mmdb
CLEANUP_FILES=("$GEO_DB")
export PACKETEER_LAB_CONFIG="$lab_dir/config.yaml"

api=http://192.0.2.10:8080/api/mitigations
# The lab's throwaway basic auth, set in lab/docker-compose-mitigation.yml.
auth="lab:${PACKETEER_HTTP_PASSWORD:-lab-only}"
both=("- 198.51.100.0/24" "- fs:198.51.100.0/24")

# Rules are in memory only, so every case adds them again. The "ttl"
# variant gives them a short life and nobody renews them.
variant_source_gone=ttl

# The RTBH route and the FlowSpec rule. FlowSpec rules are in their own
# table, not in the unicast one.
surface_routes() {
	local fs
	unicast_routes - 192.0.2.10 || return 1
	fs=$(edge_vty -c 'show bgp ipv4 flowspec detail' 2>/dev/null) || return 1
	if grep -q '198\.51\.100\.0/24' <<<"$fs"; then
		echo "- fs:198.51.100.0/24"
	fi
}

surface_seed() {
	if [ ! -f "$GEO_DB" ]; then
		go run ./lab/mkgeoip -o "$GEO_DB" 203.0.113.0/26=XA 203.0.113.64/26=XA 192.0.2.224/27=XA 203.0.113.128/25=XB
		chmod 0644 "$GEO_DB"
	fi
	place_config config.yaml lab/packeteer-mitigation.yaml
}

post() {
	local want=$1 body=$2 got
	got=$(curl -sS -o /dev/null -w '%{http_code}' -u "$auth" -H 'Content-Type: application/json' -d "$body" "$api")
	[ "$got" = "$want" ] || fail "POST $body: HTTP $got, want $want"
}

surface_baseline() {
	local i ttl=30m
	if [ "$1" = ttl ]; then
		ttl=30s
	fi
	for i in $(seq 1 90); do
		if curl -sf -o /dev/null -u "$auth" "$api" &&
			[[ "$(edge_vty -c 'show bgp neighbors 192.0.2.10' 2>/dev/null || true)" == *"BGP state = Established"* ]]; then
			break
		fi
		sleep 1
	done
	post 201 '{"prefix":"198.51.100.0/24","action":"blackhole","ttl":"'"$ttl"'"}'
	post 201 '{"prefix":"198.51.100.0/24","action":"flowspec_drop","match":{"protocols":["udp"]},"ttl":"'"$ttl"'"}'
	wait_routes 120 "baseline" "${both[@]}"
}

case_sigkill() { do_sigkill; }

case_session_loss() { do_session_loss; }

# Probe results neither trigger nor keep a mitigation route: the rules stay
# until their TTL.
case_stale_measurements() {
	rm -f "$lab_dir/state.yaml"
	stay_routes 25 "probe results gone" "${both[@]}"
}

# The rules came from an API client that has gone: nothing renews them, and
# the TTL withdraws them.
case_source_gone() {
	wait_routes 60 "rules past their TTL"
	stay_routes 10 "rules past their TTL"
}

case_reload_observe() {
	edit_config config.yaml "$OBSERVE_SED"
	hup packeteer
	wait_routes 30 "reload to observe"
	stay_routes 10 "reload to observe"
}

# mitigation.max_rules is restart-only: the reload is refused by name and
# the running config, with its two routes, stays.
case_lowered_cap() {
	edit_config config.yaml 's/max_rules: 2/max_rules: 1/'
	hup packeteer
	need_log 30 packeteer 'config reload refused; the running config stays'
	need_log 5 packeteer 'restart required: changed mitigation'
	stay_routes 15 "refused cap change" "${both[@]}"
}
