# Threat mitigation: RTBH and BGP redirect

Lab-proven only (#28, first half). It has not been run on a public edge. FlowSpec (drop, rate-limit, redirect) and country policies are the second half of #28 and are not built yet.

Packeteer can ask your edge to drop or redirect traffic toward a prefix under attack:

- **RTBH (blackhole).** Packeteer announces the prefix to the edge with a discard next hop, the RFC 7999 BLACKHOLE community (`65535:666`, configurable), its marker, `packeteer_community`, and `no-export`. The edge routes the discard address to null, so traffic toward the prefix is dropped at your edge.
- **BGP redirect.** Packeteer announces the prefix with a named target's next hop (a scrubbing center or a sinkhole) and that target's communities. The edge forwards traffic toward the prefix to that next hop.

Both are sent only to your own edge routers on the existing iBGP session. They carry `no-export`, so the edge must not pass them to a transit. Sending a blackhole to a provider (provider RTBH) is the edge's job and is not covered here.

## Safety

- `mitigation.mode` defaults to `observe`: rules are accepted and listed as a dry run and nothing is announced. `inject` also needs top-level `mode: inject`.
- **Exact learned prefix only.** A rule is announced only while the exact prefix is in the learned RIB. A more-specific of a learned prefix (for example one host) is accepted as a rule but waits forever with `pending: not in the learned RIB`. Packeteer never synthesizes a prefix.
- **Its own allowlist.** `mitigation.allowlist` is separate from `allowlist.prefixes`. A rule outside it is refused, and the announcer checks it again on every announce.
- **A cap.** `mitigation.max_rules` (default 10) caps rules held at once, announced or waiting. The announcer enforces the same cap on its routes. Mitigation routes do not count toward `max_improvements`.
- **Every rule expires.** A request may give a `ttl` up to `max_ttl` (default 24h, at most 168h); without one it gets `default_ttl` (default 1h). An expired rule is withdrawn within one decision round.
- **No stale intent.** Rules live in memory only. A restart, a crash, or a redeploy drops them, and nothing is announced again until someone adds a rule again.
- **Withdraw on failure.** SIGTERM withdraws every mitigation route while the session is up. A crash drops the session and, with no graceful restart, the edge forgets the routes within its hold time. RIB session loss withdraws them.
- **One Packeteer route per prefix.** While a rule holds a prefix (or its route is still on the wire), outbound improvements and inbound steers for that prefix are withdrawn and not announced again until the rule is gone. The mitigation route goes out on the next round, once the edge advertises the prefix again.
- **No provider next hops.** A catalog next hop equal to a provider's `next_hop` is refused at startup, so a mitigation route never looks like an outbound improvement.
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
```

Every key is in [CONFIG.md](CONFIG.md#mitigation).

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

# remove a rule (its route is withdrawn within a second)
curl -u ops:secret -X DELETE http://127.0.0.1:8080/api/mitigations/<id>
```

`POST` returns `201` with the rule, `400` for an invalid rule (outside the allowlist, host bits set, unknown action or target, TTL out of bounds), and `409` when `max_rules` is reached. A rule for a prefix that already has one replaces it and does not count twice. `GET` lists each rule with `announced` and, when it is not on the wire, `pending` (the reason).

## Edge setup (FRR)

The edge must: accept routes with the marker from Packeteer, prefer them over its native route, keep their next hop, route the discard address to null, and never export them. This is the lab edge (`lab/frr-mit-edge/frr.conf`):

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
```

`no-export` stays on the route, so it is not sent to an eBGP neighbor. A redirect target's next hop must be reachable from the edge (connected or through your IGP). On other routers the rule is the same: match the marker, raise the preference, leave the next hop, keep `no-export`, and point the discard address at a null route.

## Lab

`lab/e2e-mitigation.sh` runs an FRR edge that learns 198.51.100.0/24 from a simulated transit and exports to a second one. It proves, on the routers themselves: a rule outside the mitigation allowlist refused; an allowlisted more-specific that is not in the RIB never announced; the cap; RTBH on the edge (BGP next hop `192.0.2.66`, BLACKHOLE, and a blackhole route in the edge's FIB) and nothing leaked to the other transit; redirect replacing it in place (next hop `192.0.2.77` in the FIB); removal restoring the native route; TTL expiry; SIGTERM withdraw; no rule after a restart; and SIGKILL dropping the route within the BGP hold time.

## Rollback

Set `mitigation.mode: observe` (or remove `mitigation`) and restart: every mitigation route is withdrawn, and a restart drops every rule anyway. To clear one rule without a restart, `DELETE /api/mitigations/{id}`.
