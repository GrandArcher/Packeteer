# Non-BGP mode (#300)

For a site whose router has no BGP. Flow records name the destinations in
use, and an improvement becomes a static route on the router (RouterOS 7
REST, or netlink with protocol 250 on Linux). User guide: [../nonbgp.md](../nonbgp.md).

## Owner decision

The owner approved this mode as an exception to the learned-RIB rule on
2026-11-10, modeled on the `synthesize` exception (#122):
"Override the not-in-RIB stop for #300 like #122: opt-in, off by default,
warning, crash cleanup, lab job."
([issue #300 comment](https://github.com/GrandArcher/Packeteer/issues/300#issuecomment-6770537176)).
The exception covers this mode only. Every other code path still never
announces or installs a prefix that is not in the learned RIB view.

## Rails

- Off by default. Routes are installed only with `mode: inject` and
  `nonbgp.install_routes: true`; validation refuses inject without it. The
  shipped config and every example stay `mode: observe`. Observe and
  suggest install nothing and only list the routes inject would install.
- Warnings: a WARN log line at start and on `-check`, a banner on every UI
  page and in the config editor, and WARNING blocks in
  [../CONFIG.md](../CONFIG.md#nonbgp) and [../nonbgp.md](../nonbgp.md). They
  say the routes are not from a learned RIB view, are derived from flow
  data, can black-hole or misroute traffic, and leak into BGP if the router
  redistributes static routes.
- Inject keeps the BGP inject checks: allowlist, `hold_time`, thresholds,
  `packeteer_community`, and `local_pref` (a static route cannot carry the
  last two; the router's export filter must set them, with NO_EXPORT, if it
  redistributes the routes). `max_improvements` caps the routes on the
  router, left-over routes included.
- A route is never more specific than /24 or /48. A widened prefix stays
  inside the announced prefix a `covering` plugin found and holds at least
  as many blocks with flow as without; the idle part is not measured.
- Only a tagged route is changed or removed (RouterOS comment
  `packeteer-steer`, Linux `proto 250`).
- Withdraw: on SIGTERM and shutdown, and when the improvement retires
  because the steered link is lost, its probe source fails, or the
  measurements go stale, or when the prefix ages out. The first four are
  tested in `cmd/controller/nonbgp_test.go`, the age-out in
  `internal/nonbgp/steer_test.go`.
- Crash cleanup: neither router has a route lease, so every start with a
  steerer, in any mode, removes all tagged routes before the first round.
  After SIGKILL or power loss the routes stay until that next start. A
  route that cannot be removed is retried each round and counts against the
  cap; it does not stop other steering.
- Lab: `lab/e2e-nonbgp.sh` (CI) installs a route with the `linux` steerer
  in a simulated router's network namespace, withdraws it on probe-source
  failure and SIGTERM, and proves that `kill -9` leaves it and the next start
  sweeps it. Documentation prefixes and ASNs only.
- Steerers are in-process only. Router credentials come from environment
  variables and the URL must be https (http only to a loopback host).
- No graceful restart is involved: there is no BGP session.
- Herd sharing is not part of this mode.
