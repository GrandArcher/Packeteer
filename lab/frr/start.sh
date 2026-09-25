#!/bin/sh
# Start FRR and load the integrated config. The image entrypoint only execs
# watchfrr, which does not apply frr.conf on its own.
set -eu
mkdir -p /var/run/frr
if id frr >/dev/null 2>&1; then
	chown -R frr:frr /etc/frr /var/run/frr 2>/dev/null || true
fi
/usr/lib/frr/docker-start &
pid=$!
trap 'kill "$pid" 2>/dev/null || true; wait "$pid" 2>/dev/null || true' TERM INT
i=0
until vtysh -c 'show version' >/dev/null 2>&1; do
	i=$((i + 1))
	if [ "$i" -gt 60 ]; then
		echo "frr: vtysh did not come up" >&2
		exit 1
	fi
	sleep 1
done
i=0
while true; do
	vtysh -b || true
	if vtysh -c 'show running-config' 2>/dev/null | grep -q 'router bgp'; then
		break
	fi
	i=$((i + 1))
	if [ "$i" -gt 20 ]; then
		echo "frr: bgp config did not load" >&2
		vtysh -c 'show running-config' >&2 || true
		exit 1
	fi
	sleep 1
done
wait "$pid"
