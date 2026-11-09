# More-specific injection: a /24 and its three learned more-specifics
# (lab/e2e-more-specific.sh's lab). Sourced by lab/e2e-failure-matrix.sh.
COMPOSE=(lab/docker-compose-more-specific.yml lab/failure-matrix/override.yml)
ROUTERS=(edge)
SVCS=(packeteer)
ACTIVE=packeteer
ACTIVE_TAG=-
HOLD_FILE=lab/frr-ms-edge/frr.conf
# Every prefix the edge advertises there. A Packeteer route for anything
# else is an unlearned more-specific.
EVER="198.51.100.0/24 198.51.100.0/25 198.51.100.128/26 198.51.100.192/27"
MAX_ROUTES=4
export PACKETEER_LAB_CONFIG="$lab_dir/config.yaml"

surface_routes() { unicast_routes - 192.0.2.10; }

surface_seed() { place_config config.yaml lab/packeteer-more-specific.yaml; }

surface_baseline() {
	wait_routes 120 "baseline" "- 198.51.100.0/24" "- 198.51.100.0/25" "- 198.51.100.128/26" "- 198.51.100.192/27"
}

case_sigkill() { do_sigkill; }

case_session_loss() { do_session_loss; }

# The more-specifics go with their improvement: all four or none.
case_stale_measurements() {
	rm -f "$lab_dir/state.yaml"
	wait_routes 40 "probe results gone"
	stay_routes 10 "probe results gone"
}

# The /24 leaves the static target source. Its improvement keeps the prefix
# probed (#116), so all four routes stay; they go with the measurements.
case_source_gone() {
	edit_config config.yaml '/- prefix: 198.51.100.0\/24/,/host: 198.51.100.1/d'
	hup packeteer
	stay_routes 20 "prefix left the target source" "- 198.51.100.0/24" "- 198.51.100.0/25" "- 198.51.100.128/26" "- 198.51.100.192/27"
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

# more_specific.max_routes is restart-only; the cap that reloads is
# max_improvements, and its improvement owns all four routes.
case_lowered_cap() {
	edit_config config.yaml 's/^max_improvements: 50/max_improvements: 0/'
	hup packeteer
	wait_routes 30 "max_improvements lowered to 0"
	stay_routes 10 "max_improvements lowered to 0"
}
