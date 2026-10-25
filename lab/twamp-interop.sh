#!/bin/bash
# Reflector interop (#224): nokia/twampy, an independent TWAMP-Light
# (RFC 5357) session sender, sends a train to packeteer-reflector on
# loopback. Every direction must report 0.0% loss, which only holds if the
# reflector's reply is laid out as that sender expects. Needs python3 (3.11+),
# git, and Go. No Docker, no BGP, nothing announced.
set -euo pipefail

root=$(cd "$(dirname "$0")/.." && pwd)
twampy_commit=885b986d277bfcd7dac2954f96fc9f4d18779b11
port=18620
work=$(mktemp -d)
reflector_pid=
trap 'rc=$?; [ -n "$reflector_pid" ] && kill "$reflector_pid" 2>/dev/null || true; rm -rf "$work"; exit "$rc"' EXIT

git clone -q https://github.com/nokia/twampy "$work/twampy"
git -C "$work/twampy" checkout -q "$twampy_commit"
(cd "$root" && go build -o "$work/packeteer-reflector" ./cmd/reflector)

"$work/packeteer-reflector" -listen "127.0.0.1:$port" >"$work/reflector.log" 2>&1 &
reflector_pid=$!
sleep 1

cd "$work"
out=$(PYTHONPATH="$work/twampy/src" python3 -m twampy sender "127.0.0.1:$port" --count 50 --interval 20)
echo "$out"

for dir in Outbound Inbound Roundtrip; do
	line=$(printf '%s\n' "$out" | grep "^ *$dir:" || true)
	if [ -z "$line" ] || ! printf '%s\n' "$line" | grep -q ' 0\.0%$'; then
		echo "twampy reports loss or no $dir row: '$line'" >&2
		cat "$work/reflector.log" >&2
		exit 1
	fi
done
echo "twampy sender and packeteer-reflector interoperate"
