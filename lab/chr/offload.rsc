# Lab only (lab/e2e-chr.sh, #740): the router side of offload_aware with
# offload_community 64512:777, as `packeteer -snippet mikrotik` prints it
# (internal/snippet tests keep the rules below identical to that text).
# Documentation addresses and private/documentation ASNs only. The two
# chains this replaces come from lab/chr/edge.rsc.
/routing filter rule remove [find where chain=packeteer-in]
/routing filter rule remove [find where chain=ebgp-out]
/routing filter rule add chain=ebgp-out rule="accept"

/routing filter rule add chain=packeteer-in \
    rule="if (bgp-communities includes 64512:666) { set suppress-hw-offload yes }"
/routing filter rule add chain=packeteer-in \
    rule="if (bgp-communities includes 64512:777) { set suppress-hw-offload no }"
/routing filter rule add chain=packeteer-in \
    rule="if (bgp-communities includes 64512:666) { accept }"
/routing filter rule add chain=packeteer-in rule="reject"

/routing filter rule add chain=ebgp-out place-before=0 \
    rule="if (bgp-communities includes 64512:777) { reject }"
/routing filter rule add chain=ebgp-out place-before=0 \
    rule="if (bgp-communities includes 64512:666) { reject }"

/routing filter rule add chain=ebgp-in place-before=0 \
    rule="if (dst == 0.0.0.0/0) { set suppress-hw-offload yes }"
