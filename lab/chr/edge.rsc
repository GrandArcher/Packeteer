# Simulated MikroTik edge for lab/e2e-chr.sh (#52). Free CHR image, no
# license. Documentation addresses (RFC 5737) and private/documentation
# ASNs only. Packeteer is 192.0.2.10; this router is 192.0.2.254 on ether2.
/ip address add address=192.0.2.254/24 interface=ether2 comment=lab
/system identity set name=chr-edge

# ---- begin docs/mikrotik.md (kept identical by lab/doccmds tests) ----
# Router ASN 64512, router address 192.0.2.254, Packeteer at 192.0.2.10.
# Community 64512:666 must match packeteer_community in config.yaml.
/routing bgp instance add name=edge as=64512 router-id=192.0.2.254
/routing bgp connection add name=packeteer instance=edge \
    local.address=192.0.2.254 local.role=ibgp \
    remote.address=192.0.2.10 remote.as=64512 \
    output.redistribute=bgp output.default-originate=never \
    input.filter=packeteer-in

# From Packeteer: accept only routes that carry the Packeteer community.
/routing filter rule add chain=packeteer-in \
    rule="if (bgp-communities includes 64512:666) { accept }"
/routing filter rule add chain=packeteer-in rule="reject"

# Toward every eBGP peer: never export that community, even if no-export
# were missing. Attach ebgp-out to each transit/peer/IX connection.
/routing filter rule add chain=ebgp-out \
    rule="if (bgp-communities includes 64512:666) { reject }"
/routing filter rule add chain=ebgp-out rule="accept"
/routing bgp connection set [find where local.role=ebgp] output.filter-chain=ebgp-out
# ---- end docs/mikrotik.md ----

# Lab only: a 9s hold time bounds the frozen-process and SIGKILL checks.
# Graceful restart is never configured.
/routing bgp connection set [find where name=packeteer] hold-time=9s

# Transits (eBGP, lab/chrpeer speakers). Both originate 198.51.100.0/24.
/routing bgp connection add name=transit-a instance=edge \
    local.address=192.0.2.254 local.role=ebgp \
    remote.address=192.0.2.1 remote.as=64496 hold-time=9s
/routing bgp connection add name=transit-b instance=edge \
    local.address=192.0.2.254 local.role=ebgp \
    remote.address=192.0.2.2 remote.as=64497 hold-time=9s

# eBGP collector: records what this router exports. It must never see a
# Packeteer route.
/routing bgp connection add name=collector instance=edge \
    local.address=192.0.2.254 local.role=ebgp \
    remote.address=192.0.2.20 remote.as=64498 hold-time=9s \
    output.redistribute=bgp

# The guide's export rule again, now that the eBGP connections exist.
/routing bgp connection set [find where local.role=ebgp] output.filter-chain=ebgp-out

# A second iBGP speaker on the same input filter as Packeteer. It sends
# 203.0.113.0/24 without the Packeteer community; packeteer-in rejects it.
/routing bgp connection add name=untagged instance=edge \
    local.address=192.0.2.254 local.role=ibgp \
    remote.address=192.0.2.30 remote.as=64512 hold-time=9s \
    input.filter=packeteer-in
