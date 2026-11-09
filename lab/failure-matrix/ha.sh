# HA standby takeover: pk-a active, pk-b standby on one lease
# (lab/e2e-ha.sh's lab). Sourced by lab/e2e-failure-matrix.sh.
COMPOSE=(lab/docker-compose-ha.yml lab/failure-matrix/ha-override.yml)
ROUTERS=(edge)
SVCS=(packeteer-a packeteer-b)
ACTIVE=packeteer-a
ACTIVE_TAG=a
HOLD_FILE=lab/frr-ha/frr.conf
EVER="198.51.100.0/24"
MAX_ROUTES=1
export PACKETEER_LAB_CONFIG_A="$lab_dir/config-a.yaml"
export PACKETEER_LAB_CONFIG_B="$lab_dir/config-b.yaml"

# After the active instance dies or loses its session, the standby takes
# over: one instance's route, never both.
KILL_FINAL=("b 198.51.100.0/24")
SESSION_FINAL=("b 198.51.100.0/24")

surface_routes() {
	unicast_routes a 192.0.2.10 || return 1
	unicast_routes b 192.0.2.20
}

# The edge never holds routes from both instances at once.
surface_check() {
	if grep -q '^a ' <<<"$1" && grep -q '^b ' <<<"$1"; then
		fail "the router holds Packeteer routes from both instances: [$(echo $1)]"
	fi
}

surface_seed() {
	place_config config-a.yaml lab/packeteer-ha-a.yaml
	place_config config-b.yaml lab/packeteer-ha-b.yaml
	seed_file state.yaml lab/probes/prefer-b.yaml
}

# A fresh lease volume every case: a record left by a killed instance would
# make the next start wait it out.
surface_reset() {
	"${dc[@]}" down -v --remove-orphans >/dev/null
	"${dc[@]}" up -d --no-deps edge
	wait_edge
	surface_seed "$1"
	"${dc[@]}" up -d --no-deps packeteer-a
}

standby_ready() {
	local out
	out=$("${dc[@]}" exec -T packeteer-b wget -qO- http://127.0.0.1:8080/api/ha 2>/dev/null) || return 1
	[[ "$out" == *'"role":"standby"'* && "$out" == *'"eligible":true'* ]]
}

surface_baseline() {
	local i
	wait_routes 120 "pk-a active" "a 198.51.100.0/24"
	"${dc[@]}" up -d --no-deps packeteer-b
	for i in $(seq 1 60); do
		if standby_ready; then
			stay_routes 15 "pk-b standby" "a 198.51.100.0/24"
			return 0
		fi
		sleep 1
	done
	fail "pk-b is not an eligible standby"
}

edit_both() {
	edit_config config-a.yaml "$1"
	edit_config config-b.yaml "$1"
}

case_sigkill() { do_sigkill; }

case_session_loss() { do_session_loss; }

# No instance can measure: the active one withdraws and the standby has
# nothing to announce, even past the time a takeover takes (12s).
case_stale_measurements() {
	rm -f "$lab_dir/state.yaml"
	wait_routes 40 "probe results gone"
	stay_routes 20 "probe results gone"
}

# The prefix leaves both instances' target source: the active one keeps its
# improvement (#116) and the standby has nothing to take over with; the
# route goes with the measurements.
case_source_gone() {
	edit_both 's#prefix: 198.51.100.0/24#prefix: 203.0.113.0/24#; s#host: 198.51.100.1#host: 203.0.113.1#'
	hup packeteer-a packeteer-b
	stay_routes 20 "prefix left the target source" "a 198.51.100.0/24"
	rm -f "$lab_dir/state.yaml"
	wait_routes 40 "source gone, then probe results gone"
	stay_routes 20 "source gone, then probe results gone"
}

case_reload_observe() {
	edit_both "$OBSERVE_SED"
	hup packeteer-a packeteer-b
	wait_routes 30 "reload to observe"
	stay_routes 20 "reload to observe"
}

case_lowered_cap() {
	edit_both 's/^max_improvements: 50/max_improvements: 0/'
	hup packeteer-a packeteer-b
	wait_routes 30 "max_improvements lowered to 0"
	stay_routes 20 "max_improvements lowered to 0"
}
