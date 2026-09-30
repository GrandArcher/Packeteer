# Threat mitigation: RTBH, BGP redirect, and FlowSpec

Lab-proven only (#28). It has not been run on a public edge.

Packeteer can ask your edge to drop, rate-limit, or redirect traffic toward a prefix under attack:

- **RTBH (blackhole).** Packeteer announces the prefix to the edge with a discard next hop, the RFC 7999 BLACKHOLE community (`65535:666`, configurable), its marker, `packeteer_community`, and `no-export`. The edge routes the discard address to null, so traffic toward the prefix is dropped at your edge.
- **BGP redirect.** Packeteer announces the prefix with a named target's next hop (a scrubbing center or a sinkhole) and that target's communities. The edge forwards traffic toward the prefix to that next hop.

- **FlowSpec (RFC 8955).** Packeteer sends a FlowSpec rule whose destination is the prefix, optionally narrowed by source prefix, source countries, IP protocols, and ports. The action is an extended community: `flowspec_drop` (traffic-rate 0), `flowspec_rate_limit` (traffic-rate `rate_mbps`, sent as bytes per second), or `flowspec_redirect` (redirect to a named route target, which the edge maps to a scrubbing VRF). FlowSpec leaves the prefix's unicast route alone, so only the matching traffic is affected.

All of them are sent only to your own edge routers on the existing iBGP session. They carry `no-export`, so the edge must not pass them to a transit. Sending a blackhole or FlowSpec rule to a provider is the edge's job and is not covered here.

## Safety

- `mitigation.mode` defaults to `observe`: rules are accepted and listed as a dry run and nothing is announced. `inject` also needs top-level `mode: inject`.
- **Exact learned prefix only.** A rule is announced only while the exact prefix is in the learned RIB. A more-specific of a learned prefix (for example one host) is accepted as a rule but waits forever with `pending: not in the learned RIB`. Packeteer never synthesizes a prefix. A FlowSpec rule's destination is always the rule's exact learned prefix; source prefixes and countries only narrow the match and are never announced as reachability.
- **Its own allowlist.** `mitigation.allowlist` is separate from `allowlist.prefixes`. A rule outside it is refused, and the announcer checks it again on every announce.
- **A cap.** `mitigation.max_rules` (default 10) caps mitigation routes held at once, announced or waiting. RTBH, redirect, and a FlowSpec rule count once; a FlowSpec rule with `source_countries` counts once per source network, and is refused (`409`) when it does not fit. The announcer enforces the same cap on its routes, RTBH and FlowSpec together. Mitigation routes do not count toward `max_improvements`.
- **Every rule expires.** A request may give a `ttl` up to `max_ttl` (default 24h, at most 168h); without one it gets `default_ttl` (default 1h). An expired rule is withdrawn within one decision round.
- **No stale intent.** Rules live in memory only. A restart, a crash, or a redeploy drops them, and nothing is announced again until someone adds a rule again.
- **Withdraw on failure.** SIGTERM withdraws every mitigation route while the session is up. A crash drops the session and, with no graceful restart, the edge forgets the routes within its hold time. RIB session loss withdraws them.
- **One Packeteer route per prefix.** While an RTBH or redirect rule holds a prefix (or its route is still on the wire), outbound improvements and inbound steers for that prefix are withdrawn and not announced again until the rule is gone. The mitigation route goes out on the next round, once the edge advertises the prefix again.
- **No provider next hops.** A catalog next hop equal to a provider's `next_hop` is refused at startup, so a mitigation route never looks like an outbound improvement.
- **FlowSpec sessions only when used.** The iBGP sessions offer the FlowSpec address families only when `mitigation.mode` is `inject` and the announcer has a `flowspec` block. In `observe` the sessions are unchanged.
- In-process only. There is no `exec` mitigation announcer.

Probe results do not trigger or keep mitigation routes, so a probe-source failure does not withdraw them; the TTL bounds them instead. Automatic detection (#33) is not built.

## Config

```yaml
mode: inject                 # lab only; the shipped example stays observe
packeteer_community: "64512:666"
local_pref: 250
announcer:
  type: gobgp
mitigation:
  mode: inject
  allowlist: [203.0.113.0/24]
  max_rules: 10
  default_ttl: 1h
  max_ttl: 24h
  announcer:
    type: gobgp
    config:
      marker: "64512:668"
      blackhole:
        next_hop: 192.0.2.66          # the edge routes this to null
        # next_hop_v6: "2001:db8::66"
        # communities: ["65535:666"]  # default
      redirect:
        - name: scrubber
          next_hop: 192.0.2.77
          communities: ["64512:777"]
      flowspec:                       # drop and rate-limit
        redirect:
          - name: scrub-vrf
            route_target: "64512:779" # the edge imports it into a VRF
  # For source_countries: a MaxMind-format country database you mount.
  # geoip_db: /etc/packeteer/GeoLite2-Country.mmdb
```

Every key is in [CONFIG.md](CONFIG.md#mitigation).

### Country policies (GeoIP)

`source_countries` (up to 8 ISO codes) turns a FlowSpec rule into one rule per network of those countries, read from `mitigation.geoip_db` when the rule is added. Adjacent networks are merged first. The database is yours: mount it read-only (`-v "$PWD/GeoLite2-Country.mmdb:/etc/packeteer/GeoLite2-Country.mmdb:ro"`). Packeteer ships and downloads none. A country with no networks in the database is refused; one that needs more routes than `max_rules` is refused. The networks are fixed when the rule is added; add the rule again to pick up a newer database.

## API

Writes need basic auth (`PACKETEER_HTTP_USER` and `PACKETEER_HTTP_PASSWORD`) and `Content-Type: application/json`.

```sh
# list rules, the catalog, and the allowlist
curl -u ops:secret http://127.0.0.1:8080/api/mitigations

# blackhole for 30 minutes
curl -u ops:secret -H 'Content-Type: application/json' \
  -d '{"prefix":"203.0.113.0/24","action":"blackhole","ttl":"30m","reason":"ddos ticket 42"}' \
  http://127.0.0.1:8080/api/mitigations

# redirect to a catalog target (replaces the rule for the same prefix)
curl -u ops:secret -H 'Content-Type: application/json' \
  -d '{"prefix":"203.0.113.0/24","action":"redirect","target":"scrubber","ttl":"2h"}' \
  http://127.0.0.1:8080/api/mitigations

# FlowSpec: drop DNS floods toward the prefix from one source
curl -u ops:secret -H 'Content-Type: application/json' \
  -d '{"prefix":"203.0.113.0/24","action":"flowspec_drop","match":{"source":"198.51.100.0/24","protocols":["udp"],"destination_ports":[53]},"ttl":"30m"}' \
  http://127.0.0.1:8080/api/mitigations

# FlowSpec: rate-limit UDP from two countries to 50 Mbit/s
curl -u ops:secret -H 'Content-Type: application/json' \
  -d '{"prefix":"203.0.113.0/24","action":"flowspec_rate_limit","rate_mbps":50,"source_countries":["XA","XB"],"match":{"protocols":["udp"]},"ttl":"1h"}' \
  http://127.0.0.1:8080/api/mitigations

# FlowSpec: redirect web traffic into the scrubbing VRF
curl -u ops:secret -H 'Content-Type: application/json' \
  -d '{"prefix":"203.0.113.0/24","action":"flowspec_redirect","target":"scrub-vrf","match":{"protocols":["tcp"],"destination_ports":["80","443"]}}' \
  http://127.0.0.1:8080/api/mitigations

# remove a rule (its routes are withdrawn within a second)
curl -u ops:secret -X DELETE http://127.0.0.1:8080/api/mitigations/<id>
```

`match` keys, all optional (a rule with no `match` covers all traffic toward the prefix): `source` (a prefix of the same family; not with `source_countries`), `protocols` (up to 8, names `tcp` `udp` `icmp` `icmpv6` `gre` `esp` `ah` `sctp` or numbers), `destination_ports` and `source_ports` (up to 8 each, `53` or `"1000-2000"`). Every given key must match; within a list any entry matches. Rule keys: an RTBH or redirect rule replaces the rule for the same prefix; a FlowSpec rule replaces the one with the same prefix, match, and `source_countries` (so a rate limit can replace a drop in place). An RTBH rule and FlowSpec rules may share a prefix. Two different FlowSpec rules may not send the same route: a `source_countries` rule and a rule whose `match.source` is one of those countries' networks with the same other match keys, or `[XA]` and `[XA, XB]` with the same match, are refused with `409` naming the rule already held. Remove that rule first, or send the same match and `source_countries` to replace it.

`POST` returns `201` with the rule, `400` for an invalid rule (outside the allowlist, host bits set, unknown action or target, bad match, unknown country, TTL out of bounds), and `409` when `max_rules` is reached or a FlowSpec rule would send a route another rule already sends. A replaced rule does not count twice. `GET` lists each rule with `routes`, `announced` and, when it is not on the wire, `pending` (the reason).

## Monitor, feed, and history

- **Monitor.** The dashboard's Threat mitigation section shows the rules, their state, and routes held against `max_rules`. `/metrics` has `packeteer_mitigation_rules{action,state}`, `packeteer_mitigation_routes_held`, `packeteer_mitigation_routes_announced`, and `packeteer_mitigation_max_rules`.
- **Feed.** `GET /api/mitigations` returns `feed`: the last 200 changes, newest first (`added`, `replaced`, `announced`, `withdrawn`, `expired`, `removed`). The same changes go to every notifier as `mitigation.added`, `mitigation.announced`, `mitigation.withdrawn`, and `mitigation.ended` ([EVENTS.md](EVENTS.md)), so a webhook or SNMP trap receiver sees each rule go on and off the wire.
- **History.** With a storage plugin (`sqlite`), every rule is stored from creation to its end (expired, removed, replaced, controller stopped or restarted) with when it first went on the wire. `GET /api/reports/mitigations?days=7` (and `&format=csv`) lists them, newest first.

## Edge setup (FRR)

The edge must: accept routes with the marker from Packeteer, prefer them over its native route, keep their next hop, route the discard address to null, and never export them. For FlowSpec it must also activate the FlowSpec family on the Packeteer session and install the rules in its data plane (FRR: `local-install` on the interfaces under `address-family ipv4 flowspec`, which needs ipset/iptables PBR; Junos, IOS XR, and EOS have native FlowSpec). This is the lab edge (`lab/frr-mit-edge/frr.conf`):

```
ip route 192.0.2.66/32 blackhole
!
bgp community-list standard packeteer permit 64512:666
bgp community-list standard packeteer-mitigation permit 64512:668
!
route-map from-packeteer permit 5
 match community packeteer-mitigation
 set weight 65535
route-map from-packeteer permit 10
 match community packeteer
route-map from-packeteer deny 100
!
router bgp 64512
 address-family ipv4 flowspec
  neighbor 192.0.2.10 activate
 exit-address-family
```

**FlowSpec validation.** RFC 8955 §6 has the edge accept a FlowSpec route only when the best unicast route for its destination came from the same peer. Here the unicast route comes from a transit and the FlowSpec rule from Packeteer over iBGP, so strict validation rejects every rule. Relax it on the Packeteer session: RFC 9117 validation if the router supports it, or turn validation off for that neighbor only (Junos: `family inet flow no-validate <policy>` on the Packeteer group; other vendors have a per-neighbor FlowSpec validation option). Keep the marker-matching import policy above, so only Packeteer's rules are accepted without validation. Check that a rule shows as installed (not invalid) in the router's FlowSpec table before relying on it.

`no-export` stays on the route, so it is not sent to an eBGP neighbor. A redirect target's next hop must be reachable from the edge (connected or through your IGP). On other routers the rule is the same: match the marker, raise the preference, leave the next hop, keep `no-export`, and point the discard address at a null route.

## Lab

`lab/e2e-mitigation.sh` runs an FRR edge that learns 198.51.100.0/24 from a simulated transit and exports to a second one; the edge and the second transit also negotiate FlowSpec. It proves, on the routers themselves: a rule outside the mitigation allowlist refused; an allowlisted more-specific that is not in the RIB never announced (RTBH and FlowSpec); the cap; RTBH on the edge (BGP next hop `192.0.2.66`, BLACKHOLE, and a blackhole route in the edge's FIB) and nothing leaked to the other transit; redirect replacing it in place (next hop `192.0.2.77` in the FIB); removal restoring the native route; TTL expiry; a FlowSpec drop from test country XA (a lab GeoIP database from `lab/mkgeoip`) as one rule per network in the edge's FlowSpec table and none on the other transit; the cap counting those routes; a rate limit replacing the drop in place; DELETE; a FlowSpec redirect to a route target; SIGTERM withdrawing RTBH and FlowSpec; no rule after a restart; and SIGKILL dropping both within the BGP hold time. The lab checks the edge's BGP tables; it does not install FlowSpec in FRR's data plane.

## Rollback

Set `mitigation.mode: observe` (or remove `mitigation`, or only its `flowspec` block) and restart: every mitigation route and FlowSpec rule is withdrawn, the sessions stop offering FlowSpec, and a restart drops every rule anyway. To clear one rule without a restart, `DELETE /api/mitigations/{id}`.
