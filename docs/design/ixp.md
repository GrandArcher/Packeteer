# IXP mode (#160)

Status: charter, config gate, IX-F member import (#161), and fabric
probes (#162). Route-server history, signals, member pages, and
multi-site fabric health are #163-#167 and are not built. An `ixp`
block does not announce or open a route-server session.

An Internet exchange operator runs Packeteer to observe its fabric,
route servers, and members. It does not route for them. This is not the
`exchanges` block, which is an edge network's own peering sessions.

## Turning it on

`ixp: {}` in the config. The keys are `members` (#161), `vantages`,
and `fabric` (#162). Any other key is an error. Omitted, or `ixp: null`,
is not IXP mode. `mode` stays `observe`. `mode: suggest` is accepted
and announces nothing. The shipped example leaves the block commented
out.

IXP mode does not need `bgp.neighbors`. With no neighbors the controller
does not build a RIB view. A neighbor list is still allowed; it is the
operator's own iBGP, not route-server data. Providers are still
required. Fabric vantages are `ixp.vantages` (#162), not providers.

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

IXP Manager and Birdseye are read with GET only. No other method.

- IXP Manager member export (#161, enforced): `GET /api/v4/member-export/ixf/1.0`
  on the operator's base URL, including a subdirectory install whose
  path ends with that suffix. A bare origin uses that path. The only
  query keys kept are `ignore_missing_ixfid=1` and `ixfid_<digits>=<digits>`.
  `apikey`, `api_key`, `access_key`, `key`, `token`, `password`, and any
  other query key are refused. Auth is the `X-IXP-Manager-API-Key`
  header. The key is `PACKETEER_IXP_MANAGER_API_KEY`. It is not a config
  value and not a query parameter. A URL that contains the key, including
  a percent-encoded form, is refused, so the secret is not stored on the
  member list or sent in the request target. The log records the key
  identifier, never the secret. `key_expires` (`YYYY-MM-DD`) is required when the
  key is set, because the token and this export do not carry the expiry.
  A warning fires when 14 days or fewer remain, including a key that is
  already expired. A date more than 366 days ahead is refused. Redirects
  are not followed. The response is capped (`max_bytes`, default 8 MiB)
  and refreshed on `refresh` (default 15m, 1m-24h). Use a low-privilege
  user. The list is served at
  `GET /api/ixp/members`. It is not the RIB and not an input to Decide.
- IXP Manager customers document (#162, enforced):
  `GET /admin/api/v4/nagios/customers/{vlanid}/4` and
  `GET /admin/api/v4/nagios/customers/{vlanid}/6` on the same origin as
  the member export, including a subdirectory install. `vlanid` is the
  VLAN database id. The last segment is `4` or `6`. No template suffix
  and no query string. Auth is the same `X-IXP-Manager-API-Key` header.
  This is the one route in IXP Manager's external superuser group that
  this process GETs. Redirects are not followed. The body is capped at
  2 MiB. A host is probed only when its service use is
  `ixp-manager-member-ping-service`, or
  `ixp-manager-member-ping-busy-service` for a busy host. The document
  does not include `service_description` or `check_command`. The busy
  template's warning is 1000ms or 80% loss; otherwise 250ms or 20%
  loss. The busy critical RTT (2000ms) is the minimum per-packet
  timeout for that host. A failed fetch keeps the last successful
  list. With no successful list, that VLAN is not probed: the member
  export omits `can_ping`. A named IX-F URL does not use this GET.
  Switch, birdseye, and template nagios routes are not called.
- An IX-F JSON document the operator names (#161) is GET of that exact
  URL, with no API key. Setting the key with a URL that is not the
  member export is a config error.
- Birdseye, GET only (#164, not built): `api/status`, `api/protocols/bgp`,
  `api/routes/count/protocol/{protocol}`,
  `api/routes/lc-zwild/protocol/{protocol}/{rs-asn}/1101`.

An IX-F address with `can_ping: false` is not probed. Probes stay inside
the VLAN prefix. Nothing is announced, and the measurements are not an
input to Decide.

## Lab data

Member data is never committed. Lab fixtures use documentation prefixes
(192.0.2.0/24, 198.51.100.0/24, 203.0.113.0/24, 2001:db8::/32) and
documentation or private ASNs (64496-64511, 65536-65551, or
64512-65534).

Rollback: remove `ixp.members`, or `ixp.vantages` and `ixp.fabric`, or
the `ixp` block, and restart. Nothing was announced.
