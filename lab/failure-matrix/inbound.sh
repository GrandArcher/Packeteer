# Inbound steering: a steer route for 203.0.113.0/24 toward the edge
# (lab/e2e-inbound.sh's lab). Sourced by lab/e2e-failure-matrix.sh.
COMPOSE=(lab/docker-compose-inbound.yml lab/failure-matrix/override.yml)
ROUTERS=(edge transit-a transit-b)
SVCS=(packeteer)
ACTIVE=packeteer
ACTIVE_TAG=-
HOLD_FILE=lab/frr-inbound/frr.conf
EVER="203.0.113.0/24"
MAX_ROUTES=1
export PACKETEER_LAB_CONFIG="$lab_dir/config.yaml"

# The default baseline steers on the commit trigger (transit-a's inbound
# 95th over its commit). The "perf" baseline steers on the performance
# trigger instead (transit-a's probes 240 ms slower, usage under commit).
variant_source_gone=perf

surface_routes() { unicast_routes - 192.0.2.10; }

surface_seed() {
	place_config config.yaml lab/packeteer-inbound.yaml
	if [ "$1" = perf ]; then
		seed_file usage.yaml lab/probes/inbound-under.yaml
		seed_file paths.yaml lab/probes/inbound-paths-slow-a.yaml
	else
		seed_file usage.yaml lab/probes/inbound-over.yaml
		seed_file paths.yaml lab/probes/inbound-paths-equal.yaml
	fi
}

surface_baseline() { wait_routes 120 "baseline" "- 203.0.113.0/24"; }

case_sigkill() { do_sigkill; }

case_session_loss() { do_session_loss; }

# The telemetry file is gone: a telemetry error releases a commit steer.
case_stale_measurements() {
	rm -f "$lab_dir/usage.yaml"
	wait_routes 60 "telemetry gone"
	stay_routes 10 "telemetry gone"
}

# The probe source is gone: no fresh probe result for the provider releases
# a performance steer.
case_source_gone() {
	rm -f "$lab_dir/paths.yaml"
	wait_routes 60 "probe source gone"
	stay_routes 10 "probe source gone"
}

case_reload_observe() {
	edit_config config.yaml "$OBSERVE_SED"
	hup packeteer
	wait_routes 30 "reload to observe"
	stay_routes 10 "reload to observe"
}

# max_improvements is shared with inbound, so lowering it is a restart-only
# change: the reload is refused by name and the running config, with its
# steer route, stays.
case_lowered_cap() {
	edit_config config.yaml 's/^max_improvements: 50/max_improvements: 1/'
	hup packeteer
	need_log 30 packeteer 'config reload refused; the running config stays'
	need_log 5 packeteer 'max_improvements (shared with inbound)'
	stay_routes 15 "refused cap change" "- 203.0.113.0/24"
}
