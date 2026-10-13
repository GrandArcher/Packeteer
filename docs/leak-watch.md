# Keeping Packeteer routes inside your AS

In June 2019 a BGP optimizer split prefixes into more-specifics, a customer leaked them upstream, and the more-specifics spread across the Internet ([Cloudflare's account](https://blog.cloudflare.com/how-verizon-and-a-bgp-optimizer-knocked-large-parts-of-the-internet-offline-today/), [NANOG thread](https://seclists.org/nanog/2019/Jun/321)). Optimizer routes tagged NO_EXPORT only when an operator remembered to is an older complaint ([2017](https://seclists.org/nanog/2017/Aug/318), [2020](https://seclists.org/nanog/2020/Aug/16)). This page says what keeps Packeteer's routes inside your AS, and how `leak_watch` checks it while it runs.

## The rails

Each is enforced in code and covered by tests. `mode`, the allowlist, and `max_improvements` are settings you choose, so keep them tight.

- **Exact learned prefixes.** Packeteer announces a prefix only when a neighbor advertises that exact prefix in the learned RIB view. It never splits a prefix. `more_specific_bits` is rejected. The opt-in `more_specific` block announces only more-specifics a neighbor already advertises ([design](design/more-specific.md)).
- **Allowlist and cap.** In `inject` mode only allowlisted prefixes are announced, at most `max_improvements` of them.
- **Tagged.** Every route carries `packeteer_community` and the well-known NO_EXPORT community. The import filter on your edge accepts only the former.
- **Withdrawn on failure.** Shutdown, SIGTERM, probe-source loss, stale data, and RIB session loss withdraw. Graceful restart is never enabled, so a crash drops the routes with the iBGP session.
- **Default `observe`.** Nothing is announced until `mode: inject`.

The one thing Packeteer does not control is your router's export policy. NO_EXPORT is honored by routers by default, but a policy that removes communities on import, or an eBGP export that ignores them, undoes it. [routers.md](routers.md) lists the two filters the edge needs: accept only the Packeteer community from Packeteer, and reject it toward every eBGP session ([per vendor](routers.md#export-filters-on-every-ebgp-session)).

## What `leak_watch` adds

`leak_watch` (off by default) continuously checks that the filters hold. Leak sources report routes seen outside your iBGP sessions. A sighting is a leak when it

- carries `packeteer_community`, standard or large, or
- with `as_path_rule: true`, is for a prefix Packeteer has injected and has your `asn` in its AS path. Your own prefixes, which are seen outside with your ASN all the time, are not injected routes and are never flagged by this rule. Leave the rule off if you export transit routes to customers, or a customer feeds RIS or is a BMP `external_routers` source: the native route for an injected prefix then carries your ASN legitimately, and the rule would withdraw and hold every injected prefix.

On a leak Packeteer, for that one prefix only:

1. withdraws the outbound route (and the learned more-specifics announced with it), at once and without waiting for a decision round. An inbound steer is only held: it is removed at the next inbound sync, and the leak shows `action: held`;
2. holds the prefix out of outbound improvements and inbound steers, so no later round announces it again;
3. emits the `leak.detected` event (critical) and lists the prefix on `GET /api/leaks`.

It never withdraws anything in bulk. The hold lasts until an operator clears it with `POST /api/leaks/clear {"prefix": "..."}` (operator role, auth required) after fixing the filter, which emits `leak.cleared`. If the route is still visible outside, the next sighting holds it again. Holds are in memory: a restart clears them, and a route that is still leaking is held again at its next sighting.

A sighting for a prefix that is not an outbound route on the wire is held and reported but has nothing to withdraw (`action: held`). The held set keeps at most 1000 such prefixes, since anyone downstream can tag routes with the community; an outbound route on the wire is always withdrawn and held. Inbound steers count toward that limit. Routes from threat mitigation rules are reported, not withdrawn: a rule is an operator's decision.

## Sources

| Type | What it reads |
|---|---|
| `bmp` | A BMP station for the post-policy Adj-RIB-In of routers outside your AS (`external_routers`) and the post-policy Adj-RIB-Out of your own edge toward eBGP peers (`own_routers`, RFC 8671). |
| `rislive` | The public RIPE RIS Live stream, filtered by the service to announcements whose path contains your ASN. Read-only. |

Sources only read. They cannot announce, and an out-of-process plugin cannot be one. Public collectors see a route only after it left your AS and spread, so use them as a backstop next to a router you control.

A source that is down or has not connected is **unknown**, not clean: `/api/leaks` reports `state: unknown`, `packeteer_leak_source_up` is 0 for it, and the log says so. This never delays or blocks a withdraw, and the other sources keep working. The NLNOG RING looking glass is not a source yet.

## Lab proof

`lab/e2e-leak-watch.sh` runs on FRR in CI (see [lab/README.md](../lab/README.md)). It checks a clean run (no flag, no flap, the own prefix visible outside), then misconfigures the edge: the import policy strips communities and the export filter lets one injected prefix through to a router outside the AS. That router streams BMP to Packeteer, which withdraws the leaked route and no other, keeps it out across decision rounds, restores it after the fix and a clear, reports unknown when the BMP feed stops, and withdraws on SIGTERM and SIGKILL.

## Configuration

Keys are in [CONFIG.md](CONFIG.md#leak_watch). `packeteer_community` is required when `leak_watch` is enabled. Rollback: set `enabled: false` (or remove the block) and restart.
