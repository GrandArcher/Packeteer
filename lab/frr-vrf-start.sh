#!/bin/sh
# Edge of the VRF lab (#206): move the lab interface into a kernel VRF
# named internet (table 10) before FRR starts, so every session and route
# on it lives in that VRF and the default VRF keeps only loopback. Then
# start FRR as lab/frr-start.sh does. Needs the host's vrf module; the
# container is privileged.
set -eu
dev=$(ip -o -4 addr show | awk '$4 == "192.0.2.254/24" { print $2 }')
if [ -z "$dev" ]; then
	echo "vrf: no interface has 192.0.2.254/24" >&2
	exit 1
fi
ip link add internet type vrf table 10
ip link set internet up
ip link set "$dev" master internet
exec /bin/sh /lab/frr-start.sh
