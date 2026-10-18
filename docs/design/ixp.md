# IXP mode (#160)

Status: charter, config gate, IX-F member import (#161), fabric
probes (#162), fabric incident correlation (#163), route-server
history and alerts (#164), route-server signals (#165), and member pages
and series (#166). Multi-site fabric health is #167 and is not built. An `ixp` block does not announce or open a route-server
session.

An Internet exchange operator runs Packeteer to observe its fabric,
route servers, and members. It does not route for them. This is not the
`exchanges` block, which is an edge network's own peering sessions.

## Turning it on

`ixp: {}` in the config. The keys are `members` (#161), `vantages`
and `fabric` (#162), `routeservers` (#164), and `correlate` (#163). Any other key is an error. Omitted, or `ixp: null`,
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
them. #164 keeps counts and large-community tallies per member session,
never the routes themselves, in memory inside the `birdseye` plugin.
With `route_signals` (#165), the plugin also keeps each session's accepted
prefix to origin AS table in memory, up to 250000 pairs per server, to
compare members. It is never served by the API or written to disk.

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
  and refreshed on `refresh` (default 15m, 1m-24h). This export does not
  require a superuser. The list is served at
  `GET /api/ixp/members`. It is not the RIB and not an input to Decide.
- IXP Manager customers document (#162, enforced):
  `GET /admin/api/v4/nagios/customers/{vlanid}/4` and
  `GET /admin/api/v4/nagios/customers/{vlanid}/6` on the same origin as
  the member export, including a subdirectory install. `vlanid` is the
  VLAN database id. The last segment is `4` or `6`. No template suffix
  and no query string. Auth is the same `X-IXP-Manager-API-Key` header.
  This is the one route in IXP Manager's external superuser group that
  this process GETs, so the key's user has to be a superuser. A 401 is
  a failed fetch like any other. IXP Manager mounts that group at
  `/admin/api/v4` (its own `tools/runtime/nagios/update-nagios.sh` uses
  that prefix). The HTML docs still show
  `/api/v4/nagios/customers/{vlanid}/4`, which is registered only when
  `UNSECURED_API_ACCESS` is on (off by default since v7.2) and is not
  called. Redirects are not followed. The body is capped at
  2 MiB. A host is probed only when its service use is
  `ixp-manager-member-ping-service`, or
  `ixp-manager-member-ping-busy-service` for a busy host. The document
  does not include `service_description` or `check_command`. The busy
  template's warning is 1000ms or 80% loss; otherwise 250ms or 20%
  loss. The busy critical RTT (2000ms) is the minimum per-packet
  timeout for that host. A failed fetch keeps the last successful
  list for three prober intervals after the last successful fetch,
  then the VLAN is not probed until a fetch succeeds. With no successful list, that VLAN is not
  probed: the member export omits `can_ping`. A named IX-F URL does not use this GET.
  Switch, birdseye, and template nagios routes are not called.
- An IX-F JSON document the operator names (#161) is GET of that exact
  URL, with no API key. Setting the key with a URL that is not the
  member export is a config error.
- Birdseye, GET only (#164, enforced): `api/status`, `api/protocols/bgp`,
  `api/routes/count/protocol/{protocol}`,
  `api/routes/lc-zwild/protocol/{protocol}/{rs-asn}/1101`, on the origin
  or subdirectory URL of each `ixp.routeservers` server. Birdseye has no
  key, so none is sent: the IXP Manager key never goes to a Birdseye
  host, and a URL with userinfo or a query is refused. Redirects are not
  followed. A response is capped (`max_bytes`, default 8 MiB). `protocol`
  is a name Birdseye returned, limited to letters, digits, `_`, `.`, `-`.
  `rs-asn` is the server's configured `asn`. `lc-zwild` lists the routes
  of one session that carry `rs-asn:1101:x`; IXP Manager tags a route it
  filters that way and does not export it. Per session, `received` is
  the protocol's route count, `filtered` is the number of routes with
  such a tag, `accepted` is the difference, and the reasons are the
  counts by `x`. If a route listing reaches the `api.max_routes` that
  `api/status` reports, it may be cut short, so the session's counts are
  not read (`counted: false`, `error` set). `max_prefix` is the IX-F value for the neighbor address
  when `ixp.members` is set, else Birdseye's import limit. A state or
  count change raises an `ixp.rs_*` event (docs/EVENTS.md). History is
  288 samples per session in memory; a restart empties it.
- Birdseye route listing (#165, only with `route_signals`):
  `api/routes/protocol/{protocol}` on the same origin, GET, same limits.
  Birdseye refuses it above its own `max_routes`, so a session over that
  count is not requested. It gives the origin AS, the standard
  communities (`65535:666`, RFC 7999), and the `rs-asn:1101:x` tags of
  each route. Signals: a jump in the count tagged `1101:9`, `10`, `13`, or
  `14`; a new origin AS for a prefix another member's accepted route has;
  a burst of new more-specifics of another member's prefix with another
  origin; blackhole routes per member over time. They are hints; nothing
  is announced or changed.

An IX-F address with `can_ping: false` is not probed. Probes stay inside
the VLAN prefix. Nothing is announced, and the measurements are not an
input to Decide.

## Fabric incident correlation

`ixp.correlate` (#163) makes no request of its own. It reads the latest
fabric probe round and groups the measured member addresses by the
switches of their IX-F connection, the colo of those switches, and the
operator's `bundles`. IX-F has no core bundle, so a bundle is a name and
a list of switch ids. A member is degraded in a group when every measured
address it has behind the group is past the ping tolerance from every
vantage that measured it. A probe error is not a measurement.

A group is a fabric problem (`ixp.fabric_degraded`) when `min_members`
members and `degraded_pct` percent of its measured members are degraded.
A member that is degraded on every address and is in no such group is a
member problem (`ixp.member_degraded`). A member inside a fabric problem
is reported only by that fabric event. Both need `rounds` consecutive
rounds, and both clear after as many. With one vantage, a fault on the
vantage's own link looks like a fabric fault; use two vantages on a LAN
to tell them apart. The state is in memory.

## Member pages

`/ixp/member/{asn}` (#166) shows one member: its IX-F connections, its
latest fabric samples by vantage (loss, RTT, jitter, past tolerance), its
route-server sessions with the filter history, and a link to IXP Manager.
`/ixp/member/` lists the members. The page reads `GET /api/ixp/members/{asn}`
and `GET /api/ixp/routeservers/history`. It is built from the views the
other `ixp` endpoints serve, so it fetches nothing and announces nothing. An
ASN with no IX-F entry and no route-server session is a 404.

Access is the same as every other page: every Packeteer login is staff
(viewer and above). IXP Manager's `GRAPHER_ACCESS_CUSTOMER` default is
`own_graphs_only`, where a member sees only its own graphs; Packeteer has no
such scope yet. A member-scoped login through OIDC
claims is a later step; until then do not give a member a Packeteer account.

The IXP Manager link is `{base}/admin/search?search=AS{asn}`. IXP Manager's
IX-F export does not carry its customer id, and its admin search takes an
ASN and lists the customer with a link. The base is the member export URL
without `/api/v4/member-export/ixf/1.0`, so a subdirectory install works. It
is shown only for the manager export, never for a named IX-F document. The
link is for the staff browser, which signs in to IXP Manager itself;
Packeteer does not request it and sends no key.

IXP Manager can link back with a skin: set `VIEW_SKIN=<name>` in its `.env`
and copy `resources/views/customer/overview.foil.php` to
`resources/skins/<name>/customer/overview.foil.php`, then add, where `$c` is
the customer the template already has:

```php
<a class="btn btn-white" href="https://packeteer.example.net/ixp/member/<?= (int)$c->autsys ?>">Packeteer</a>
```

The series are `packeteer_ixp_member_rtt_ms`, `packeteer_ixp_member_loss_pct`,
and `packeteer_ixp_member_jitter_ms` with labels `asn`, `vlan` (the VLAN id),
`vantage`, and `family` (`ipv4` or `ipv6`). With more than one address in a
VLAN and family the worst value shows, so a series never repeats. A probe
error and a stale member list make no series. The count is members times
vantages times families; size Prometheus accordingly.

## Lab data

Member data is never committed. Lab fixtures use documentation prefixes
(192.0.2.0/24, 198.51.100.0/24, 203.0.113.0/24, 2001:db8::/32) and
documentation or private ASNs (64496-64511, 65536-65551, or
64512-65534).

Rollback: remove `ixp.members`, `ixp.routeservers`, `ixp.correlate`, or
`ixp.vantages` and `ixp.fabric`, or the `ixp` block, and restart. The member pages and series need no config of
their own and are empty without those sources. Nothing was announced.
