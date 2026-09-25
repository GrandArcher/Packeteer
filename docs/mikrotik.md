# MikroTik RouterOS 7

This guide grows with each milestone. It currently covers:

1. **Probe sourcing**: see [policy-routing.md](policy-routing.md#mikrotik-routeros-7-probe-box-behind-the-router).
2. **iBGP session** so Packeteer can see the router's best paths: below.
3. **Injected routes**: accept only the Packeteer community from that session, and never export it to eBGP. FRR, Junos, and IOS snippets are in [routers.md](routers.md).

## iBGP session to Packeteer

Packeteer needs the router's **best paths** to know which provider each prefix uses today. It peers over iBGP with the router's own ASN. In `observe` and `suggest` it announces nothing. In `inject` it announces only allowlisted improvements, each tagged with `packeteer_community` and `no-export`.

```routeros
# Router ASN 64512, router loopback 192.0.2.254, Packeteer at 192.0.2.10.
# Community 64512:666 must match packeteer_community in config.yaml.
/routing bgp template add name=packeteer as=64512 router-id=192.0.2.254
/routing bgp connection add name=packeteer templates=packeteer \
    remote.address=192.0.2.10 remote.as=64512 local.role=ibgp \
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
/routing bgp connection set [find where remote.as!=64512] output.filter=ebgp-out
```

- `output.redistribute=bgp` sends the eBGP-learned best paths (the full table if you take one) to Packeteer. Route reflection is not needed for a single edge. For iBGP-learned routes, make the router a route reflector for this session (`/routing bgp template set packeteer route-reflect=yes`) or use BMP later (#26).
- Keep graceful restart **off** on this session. Packeteer never enables it, so its routes can never linger after it dies.

Packeteer side (`config.yaml`):

```yaml
mode: observe                 # inject only after the filters above are in place
asn: 64512
router_id: 192.0.2.10
packeteer_community: "64512:666"
local_pref: 250               # required for mode: inject; higher than the native paths
# more_specific_bits: 0       # 0 = the same prefix; 1 = two covering more-specifics
bgp:
  listen_port: 179            # optional: let the router connect in
  neighbors:
    - address: 192.0.2.254
      description: edge1
announcer:
  type: gobgp
```

`local_pref`, `more_specific_bits`, and `announcer` are used only when `mode: inject`. Inject also requires a non-empty allowlist, at least one BGP neighbor, a positive hold time, and positive loss and latency thresholds.

RouterOS 7 syntax changes between minor releases, so check these commands against your version.

Check the session with `/routing bgp session print`. Packeteer logs `bgp session ... state=ESTABLISHED`, then a periodic `rib ready=true prefixes=N`. In inject mode an accepted route shows up in `/routing route print where bgp-communities~"64512:666"`. Clearing it is `mode: observe` (Packeteer withdraws) or stopping the container (the session drops; graceful restart is off, so the route does not stick).

FRR, Junos, and IOS equivalents: [routers.md](routers.md).
