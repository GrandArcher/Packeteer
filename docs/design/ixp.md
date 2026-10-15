# IXP mode (#160)

Status: charter and config gate. The `ixp` block is accepted and the
refusals below are enforced. Member import, fabric probing, route-server
history, signals, member pages, and multi-site fabric health are
#161-#167 and are not built. An `ixp` block does not announce, probe
members, or open a route-server session.

An Internet exchange operator runs Packeteer to observe its fabric,
route servers, and members. It does not route for them. This is not the
`exchanges` block, which is an edge network's own peering sessions.

## Turning it on

`ixp: {}` in the config. The block has no keys. A key inside it is an
error until the issue that adds it. Omitted, or `ixp: null`, is not IXP
mode. `mode` stays `observe`. `mode: suggest` is accepted and announces
nothing. The shipped example leaves the block commented out.

IXP mode does not need `bgp.neighbors`. With no neighbors the controller
does not build a RIB view. A neighbor list is still allowed; it is the
operator's own iBGP, not route-server data. Providers are still
required. Fabric vantages are #162 (`ixp.vantages`), not providers.

Adding or removing `ixp` needs a restart. An online reload cannot do it.

## Refused

When the block is present, validation refuses:

- `mode: inject`
- `announcer`
- `mitigation` (any mode, including observe)
- `inbound` (any mode, including observe)
- `synthesize`
- `more_specific` (including `enabled: false`)

`more_specific_bits` is already refused in every mode. Nothing in IXP
mode changes member routing.

## Route-server data

Route-server data (#164, #165) lives in a separate read-only store.
That store is not the RIB view and is not an input to `Decide`. No
later issue may copy those routes into the RIB view or announce from
them. The store is not built yet.

## External reads

IXP Manager and Birdseye are read with GET only. No other method. The
path allowlist is not enforced in code yet; #161 and #164 must refuse
anything else:

- IXP Manager member export: `GET /api/v4/member-export/ixf/1.0` on the
  operator's base URL (#161). Auth is the `X-IXP-Manager-API-Key`
  header. The key is the environment variable
  `PACKETEER_IXP_MANAGER_API_KEY`. It is not a config key and not a
  query parameter. The controller does not read it yet. The log may
  record that a key is set, never the secret. A warning fires 14 days
  before the key expires. Use a low-privilege user. Superuser endpoints
  are not called.
- An IX-F JSON document the operator names (#161) is also GET only.
- Birdseye, GET only (#164): `api/status`, `api/protocols/bgp`,
  `api/routes/count/protocol/{protocol}`,
  `api/routes/lc-zwild/protocol/{protocol}/{rs-asn}/1101`.

IXP Manager's per-interface "Can Ping" opt-out is honored (#162). A
member interface that opts out is not probed.

## Lab data

Member data is never committed. Lab fixtures use documentation prefixes
(192.0.2.0/24, 198.51.100.0/24, 203.0.113.0/24, 2001:db8::/32) and
documentation or private ASNs (64496-64511, 65536-65551, or
64512-65534).

Rollback: remove the `ixp` block and restart.
