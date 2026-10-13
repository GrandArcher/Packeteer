# Outbound steering: an improvement for 198.51.100.0/24 (lab/e2e.sh's lab).
# Sourced by lab/e2e-failure-matrix.sh.
COMPOSE=(lab/docker-compose.yml)
ROUTERS=(edge)
SVCS=(packeteer)
ACTIVE=packeteer
ACTIVE_TAG=-
HOLD_FILE=lab/frr/frr.conf
EVER="198.51.100.0/24"
MAX_ROUTES=1
export PACKETEER_LAB_CONFIG="$lab_dir/config.yaml"

surface_routes() { unicast_routes - 192.0.2.10; }

surface_seed() {
	place_config config.yaml lab/packeteer.yaml
	seed_file state.yaml lab/probes/prefer-b.yaml
}

surface_baseline() { wait_routes 120 "baseline" "- 198.51.100.0/24"; }

case_sigkill() { do_sigkill; }

case_session_loss() { do_session_loss; }

# The fixed prober fails every probe, so no result is fresh any more. The
# improvement's provider is unusable and the route is withdrawn.
case_stale_measurements() {
	rm -f "$lab_dir/state.yaml"
	wait_routes 40 "probe results gone"
	stay_routes 10 "probe results gone"
}

# The prefix leaves the static target source on a reload. An active
# improvement keeps its prefix probed after its source drops it (#116), so
# the route stays; it must not outlive its measurements, so once those go
# the route is withdrawn.
case_source_gone() {
	edit_config config.yaml 's#prefix: 198.51.100.0/24#prefix: 203.0.113.0/24#; s#host: 198.51.100.1#host: 203.0.113.1#'
	hup packeteer
	stay_routes 20 "prefix left the target source" "- 198.51.100.0/24"
	rm -f "$lab_dir/state.yaml"
	wait_routes 40 "source gone, then probe results gone"
	stay_routes 10 "source gone, then probe results gone"
}

case_reload_observe() {
	edit_config config.yaml "$OBSERVE_SED"
	hup packeteer
	wait_routes 30 "reload to observe"
	stay_routes 10 "reload to observe"
}

case_lowered_cap() {
	edit_config config.yaml 's/^max_improvements: 50/max_improvements: 0/'
	hup packeteer
	wait_routes 30 "max_improvements lowered to 0"
	stay_routes 10 "max_improvements lowered to 0"
}
