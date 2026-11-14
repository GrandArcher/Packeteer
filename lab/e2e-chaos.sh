#!/bin/bash
# Chaos soak (#585) on the HA lab (lab/docker-compose-ha.yml): one FRR edge
# and the pk-a/pk-b pair on one lease. lab/chaos flaps the active
# instance's session, fails transit-b's probe source, and stops the active
# instance with SIGTERM and SIGKILL until the profile's window is over,
# checking the safety invariants on the edge on every sample. It writes
# chaos-result.json and chaos-summary.md to $CHAOS_OUT (default
# chaos-out) and fails on a broken invariant. Documentation prefix and
# private ASN only.
#
#   lab/e2e-chaos.sh [PROFILE]     default lab/chaos/short.yaml
set -euo pipefail

root=$(cd "$(dirname "$0")/.." && pwd)
cd "$root"
profile=${1:-lab/chaos/short.yaml}
out=${CHAOS_OUT:-chaos-out}
export COMPOSE_FILE=lab/docker-compose-ha.yml
compose=(docker compose)

lab_dir=$(mktemp -d)
chaos_bin=$(mktemp)
trap 'rc=$?; if [ "$rc" -ne 0 ]; then echo "---- lab logs ----"; "${compose[@]}" logs --no-color || true; "${compose[@]}" ps -a || true; fi; "${compose[@]}" down -v --remove-orphans || true; rm -f "$chaos_bin"; rm -rf "$lab_dir"; exit "$rc"' EXIT

echo "building chaos harness"
go build -o "$chaos_bin" ./lab/chaos
cp lab/probes/prefer-b.yaml "$lab_dir/state.yaml"
chmod 755 "$lab_dir"
chmod 644 "$lab_dir/state.yaml"
export PACKETEER_LAB_DIR="$lab_dir"

echo "building lab"
"${compose[@]}" build
"${compose[@]}" up -d edge packeteer-a packeteer-b

"$chaos_bin" -profile "$profile" -lab-dir "$lab_dir" -out "$out"
