# MikroTik RouterOS 7

This guide grows with each milestone. It currently covers:

1. **Probe sourcing**: see [policy-routing.md](policy-routing.md#mikrotik-routeros-7-probe-box-behind-the-router).
2. **iBGP session for the RIB view (learn-only)**: below.
3. **Accepting injected routes** (filters for the Packeteer community, never exporting it to eBGP): added with the announcer (#8).

## iBGP session to Packeteer (learn-only, v0.1 RIB view)

Packeteer needs the router's **best paths** to know which provider each prefix uses today. It peers over iBGP with the router's own ASN and, for now, announces nothing. Its export policy rejects everything.

```routeros
# Router ASN 64512, router loopback 192.0.2.254, Packeteer at 192.0.2.10
/routing bgp template add name=packeteer as=64512 router-id=192.0.2.254
/routing bgp connection add name=packeteer templates=packeteer \
    remote.address=192.0.2.10 remote.as=64512 local.role=ibgp \
    output.redistribute=bgp output.default-originate=never \
    input.filter=packeteer-in
# Nothing from Packeteer is accepted until the announcer milestone
/routing filter rule add chain=packeteer-in rule="reject;"
```

- `output.redistribute=bgp` sends the eBGP-learned best paths (the full table if you take one) to Packeteer. Route reflection is not needed for a single edge. For iBGP-learned routes, make the router a route reflector for this session (`/routing bgp template set packeteer route-reflect=yes`) or use BMP later (#26).
- Keep graceful restart **off** on this session. Packeteer never enables it, so its routes can never linger after it dies.

Packeteer side (`config.yaml`):

```yaml
asn: 64512
router_id: 192.0.2.10
bgp:
  listen_port: 179            # optional: let the router connect in
  neighbors:
    - address: 192.0.2.254
      description: edge1
```

RouterOS 7 syntax changes between minor releases, so check these commands against your version.

Check it with `/routing bgp session print` on the router. Packeteer logs `bgp session ... state=ESTABLISHED`, followed by a periodic `rib ready=true prefixes=N`.
