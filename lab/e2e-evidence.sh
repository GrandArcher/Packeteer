#!/bin/bash
# FRR lab for thresholds.require_evidence (#202): with the rule on, a
# clearly faster provider measured by a prober that is not tcp or udp (the
# lab's fixed prober) is not announced, and /api/decisions says why with
# the confidence of every sample. A SIGHUP that drops the key announces the
# same win; SIGTERM withdraws. Documentation prefix and private ASN only.
set -euo pipefail

root=$(cd "$(dirname "$0")/.." && pwd)
cd "$root"
compose=(docker compose -f lab/docker-compose.yml)
prefix=198.51.100.0/24

lab_dir=$(mktemp -d)
trap 'rc=$?; if [ "$rc" -ne 0 ]; then echo "---- lab logs ----"; "${compose[@]}" logs --no-color || true; "${compose[@]}" ps || true; fi; "${compose[@]}" down -v --remove-orphans || true; rm -rf "$lab_dir"; exit "$rc"' EXIT

cp lab/probes/move-b.yaml "$lab_dir/state.yaml"
cp lab/packeteer-evidence.yaml "$lab_dir/config.yaml"
chmod 0644 "$lab_dir/config.yaml"
export PACKETEER_LAB_DIR="$lab_dir"
export PACKETEER_LAB_CONFIG="$lab_dir/config.yaml"

echo "building lab"
"${compose[@]}" build
"${compose[@]}" up -d

vtysh() { "${compose[@]}" exec -T edge vtysh "$@"; }
api() { "${compose[@]}" exec -T packeteer wget -qO- "http://127.0.0.1:8080$1" 2>/dev/null || true; }
prefix_text() { vtysh -c "show bgp ipv4 unicast $prefix" 2>/dev/null || true; }

dump() {
	vtysh -c 'show bgp summary' >&2 || true
	prefix_text >&2
	api /api/decisions >&2 || true
	"${compose[@]}" logs --no-color packeteer >&2 || true
}

fail() {
	echo "$1" >&2
	dump
	exit 1
}

# ours prints the next hop of each Packeteer path the edge holds for the
# prefix. FRR prints a path as "<next hop> ... from 192.0.2.10 (...)".
ours() { printf '%s\n' "$1" | sed -n 's/^[[:space:]]*\([0-9][0-9.]*\) .*from 192\.0\.2\.10 (.*/\1/p'; }

# decisions <jq filter>: wait until /api/decisions matches it.
decisions() {
	local i
	for i in $(seq 1 30); do
		if api /api/decisions | jq -e "$1" >/dev/null 2>&1; then
			return 0
		fi
		sleep 1
	done
	fail "/api/decisions never matched: $1"
}

echo "rule on: the faster transit-b is measured by the fixed prober only, so it is refused"
decisions '.decisions[] | select(.prefix == "198.51.100.0/24")
  | .action == "none" and .recommended == "transit-b"
  and (.reason | startswith("require_evidence: no evidence beyond ICMP for transit-a (fixed, 4/4 replies) and transit-b (fixed, 4/4 replies)"))
  and ([.candidates[] | .confidence.level == "medium" and .confidence.protocol == "fixed" and .confidence.replies == 4] | all)'
echo "the edge must hold no Packeteer path while the rule refuses the move"
for _ in $(seq 1 10); do
	paths=$(ours "$(prefix_text)")
	[ -z "$paths" ] || fail "edge holds a Packeteer path via $paths with require_evidence on"
	sleep 1
done
[[ "$(prefix_text)" == *"available"* ]] || fail "the native path for $prefix left the edge"

echo "SIGHUP drops require_evidence: the same win is announced"
tmp=$(mktemp "$lab_dir/.cfg.XXXXXX")
grep -v '^  require_evidence: true$' "$lab_dir/config.yaml" >"$tmp"
cat "$tmp" >"$lab_dir/config.yaml"
rm -f "$tmp"
grep -q '^  require_evidence:' "$lab_dir/config.yaml" && fail "config still has require_evidence"
cid=$("${compose[@]}" ps -q packeteer)
[ -n "$cid" ] || fail "no packeteer container"
docker kill -s HUP "$cid" >/dev/null
for i in $(seq 1 40); do
	text=$(prefix_text)
	if [ "$(ours "$text")" = 192.0.2.2 ] && [[ "$text" == *"64512:666"* && "$text" == *"no-export"* ]]; then
		break
	fi
	[ "$i" -lt 40 ] || fail "no Packeteer path via 192.0.2.2 after the reload"
	sleep 2
done
logs=$("${compose[@]}" logs --no-color packeteer 2>&1 || true)
grep -qF 'applied=thresholds' <<<"$logs" || fail "reload did not apply thresholds"
decisions '.decisions[] | select(.prefix == "198.51.100.0/24") | .current == "transit-b"'

echo "SIGTERM withdraws"
"${compose[@]}" stop -t 20 packeteer
for i in $(seq 1 40); do
	[ -z "$(ours "$(prefix_text)")" ] && break
	[ "$i" -lt 40 ] || fail "Packeteer path still on the edge after SIGTERM"
	sleep 2
done

echo "evidence lab passed"
