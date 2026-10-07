# More-specific injection with a route cap (#56)

IRP 2.9 more-specific injection, redesigned after `more_specific_bits` was
removed (#44). That knob split one learned prefix into 2^n longer prefixes
that no neighbor had advertised, and `max_improvements` counted decisions,
so 50 improvements at 8 bits could install 12,800 routes. This design
announces no prefix that is missing from the learned RIB, and its cap
counts routes on the router.

Synthesized sub-ranges, which IRP also announces, are a separate opt-in
block, `synthesize` (#114 charter, #122 feature), described at the end of
this file. `more_specific` itself never synthesizes, and
`more_specific_bits` stays removed.

## Problem it solves

An improvement steers a prefix P (for example 198.51.100.0/24) with a higher
local preference. If a neighbor also advertises longer prefixes inside P
(198.51.100.0/25, 198.51.100.128/26), the router forwards traffic to those
addresses on the longest match: the native more-specific. The improvement
then misses part of P. More-specific injection also announces those learned
more-specifics, toward the same provider, so the whole of P moves.

## Config

```yaml
more_specific:
  enabled: false   # default; absent is the same
  max_routes: 100  # default when enabled; 1-1000
```

The feature is off unless `more_specific.enabled: true`. Off, Packeteer
announces exactly what it did before: one route per improvement, the
improvement's own learned prefix. `more_specific_bits` is still a config
error with any value, including `0`. `more_specific` changes need a restart
(SIGHUP refuses them like every key outside `bgp.neighbors`).

## Which prefixes may be announced

Only in `mode: inject`. With the feature on, the announced set for an
active improvement on P is:

1. P itself, under the existing rules (exact learned prefix, allowlisted,
   not reserved by inbound steering or mitigation, provider has a next hop,
   `max_improvements`).
2. Each prefix M where **all** of these hold:
   - a configured neighbor is advertising exactly M in the learned RIB view
     (the same `Exact` lookup P uses) when M is first announced;
   - M is strictly inside P (longer mask, same family);
   - M is inside the allowlist;
   - M is not reserved by inbound steering or a mitigation rule;
   - M is not itself an improvement prefix, and P is the longest improvement
     prefix that contains M (nested improvements each own their own
     more-specifics).

Nothing else. Packeteer never computes a prefix by splitting P, never
announces a sibling or child that no neighbor advertised, and never
announces a covering prefix. If no neighbor advertises a more-specific
inside P, only P is announced. Every route, P or M, uses the improvement's
provider next hop (per-router rewrites from `bgp.neighbors` still apply),
`local_pref`, `packeteer_community`, NO_EXPORT, and the `bgp.as_path` mode
applied to that exact prefix.

Announcing an unlearned child is the separate opt-in `synthesize` block
below, which AGENTS.md now allows under its rails. `more_specific` does not
use it.

## Route cap

`more_specific.max_routes` is the number of unicast routes the outbound
and inbound controllers together may have installed on a router: every P,
every M, and every inbound steer route. The default is **100** and the
largest accepted value is 1000. Packeteer sends one path per prefix per
router, so no router receives more than `max_routes` of these routes.
`max_improvements` still bounds decisions (improvements plus inbound
steers) on its own. Threat-mitigation routes have their own cap,
`mitigation.max_rules`.

With the feature off, the route count is the improvement count, bounded by
`max_improvements` as before.

## When the cap is reached

The cap is never exceeded, and nothing already on the router is withdrawn
to make room.

- **New improvement:** all or nothing. It needs 1 + (its learned
  more-specifics not yet on the wire) routes. If that does not fit, neither
  P nor any M is announced. Sync reports
  `announce: more_specific.max_routes (N) reached: P needs k routes, r in use`,
  the improvement stays a decision (visible in the API), and every later
  round retries it. Improvements are tried in prefix order.
- **Active improvement gains a newly learned more-specific:** it is
  announced only if one route fits. Otherwise it is skipped with the same
  error; P and the routes already on the wire stay.
- Room appears when routes leave (an improvement retires, a more-specific
  really leaves the RIB). The next round announces what now fits.

## Withdraw

- The improvement leaves (flip-back, TTL, policy, P leaves the RIB): P and
  every M it owns are withdrawn.
- Provider switch: P and every M are re-announced toward the new provider.
- M really leaves the RIB: withdrawn. The rule is the one improvements use
  (`policy.NativePathConfirm`, 5s): a more-specific the neighbor kept
  advertising for at least 5s while Packeteer's route was on the wire, and
  then stopped, is a real leave. One that disappears sooner is the router
  hiding the native path because Packeteer's route won; it stays, because
  withdrawing it would flap.
- M becomes reserved or leaves the allowlist: withdrawn.
- No BGP session up (RIB not ready), probe source loss or stale data
  (improvements retire), shutdown or SIGTERM (`WithdrawAll`): everything is
  withdrawn, more-specifics included.
- SIGKILL or crash: the iBGP session drops and the router removes every
  Packeteer route. Graceful restart stays off.

## Proof

- Unit tests (`internal/announce`): only learned prefixes announced, never
  an unlearned child; the cap holds for new and growing improvements, all
  or nothing; a real RIB leave withdraws, a best-path hide does not;
  retire, switch, RIB not ready, and `WithdrawAll` withdraw every
  more-specific. Config tests: off by default, bounds, `more_specific_bits`
  still rejected.
- FRR lab (`lab/e2e-more-specific.sh`): an edge advertises a /24 with three
  learned more-specifics and, later, a second /24 with one. With
  `max_routes: 4` the lab asserts, on the router, the exact set and count of
  Packeteer routes, that no prefix the edge does not advertise ever appears,
  that the second /24 waits at the cap, that a real `no network` on the edge
  withdraws that more-specific and frees room, and that SIGTERM and SIGKILL
  leave zero Packeteer routes.

Lab-proven only, not on a public edge.

## Synthesized sub-ranges (`synthesize`, opt-in)

Status: charter only (#114). The feature is #122 and is not implemented.
Until it merges, nothing outside the learned RIB is announced.

IRP disaggregates a large prefix and can announce the more-specific it
measured, so a bad part of a /16 can be steered as a /24. No attribute on
the covering route (local preference, next hop, communities, AS path, MED)
can steer part of it, because the router forwards by longest match. Only a
longer route does. `synthesize` is that longer route, under these rails:

1. **Off by default.** Nothing happens unless `synthesize.enabled: true`.
   It takes effect only in `mode: inject`. Observe and suggest list the
   would-be routes on `/api/decisions` and announce nothing. No shipped
   example turns it on.
2. **Covering-prefix allowlist.** `synthesize.covering_prefixes` lists the
   prefixes that may be split. Each entry must be inside
   `allowlist.prefixes`.
3. **Only sub-ranges of a prefix a neighbor already advertises.** A
   sub-range S is eligible only while a configured neighbor advertises a
   covering prefix C exactly in the learned RIB view (the same `Exact`
   lookup improvements use), with S strictly inside C and C inside
   `covering_prefixes`.
4. **Bounded size.** `max_bits` (how far past C's length S may go; small
   default, hard maximum 8) and `max_prefix_len` (no longer than a floor
   such as /24 for IPv4 and /48 for IPv6). Synthesized routes count toward
   the same per-router route cap as `more_specific` (`max_routes`), so
   `max_improvements` counting decisions can never install thousands of
   routes again.
5. **No overlap.** S is never announced where a neighbor advertises a
   more-specific that overlaps it (that one goes through `more_specific`),
   and never for a prefix held by inbound steering or a mitigation rule.
6. **Tagged.** Every synthesized route carries `packeteer_community`,
   NO_EXPORT, and a separate marker community, so an edge can accept
   Packeteer's exact-prefix routes and refuse synthesized ones.
7. **Measured on its own.** S is announced only from its own sub-range
   measurement (#121), under the same thresholds, confirmation, hold time,
   cooldown, and `max_improvements` as a performance move.
8. **Withdrawn.** With its improvement; when C really leaves the RIB (the
   `policy.NativePathConfirm` rule above); when S becomes reserved or leaves
   the allowlists; when the RIB is not ready, probe sources fail, or data
   goes stale; on SIGTERM (`WithdrawAll`); on SIGKILL or a crash (the
   session drops, graceful restart stays off); and on an HA standby, which
   announces nothing.
9. **Proof before merge.** Unit tests for every rail above, and an FRR lab
   that announces a synthesized route inside a learned prefix, holds a
   second one at the cap, withdraws on the covering prefix's `no network`,
   SIGTERM, and SIGKILL, and shows nothing reaching the other transit. With
   the feature off, the existing labs keep proving that no unlearned prefix
   is announced.

`more_specific_bits` stays a config error with any value. Rollback:
`synthesize.enabled: false` and restart.
