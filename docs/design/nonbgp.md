# Non-BGP mode (#300)

For a site whose router has no BGP. Flow records name the destinations in
use, and an improvement becomes a static route on the router (RouterOS 7
REST or Linux `ip route`). User guide: [../nonbgp.md](../nonbgp.md).

## Rails that hold

- Off unless the `nonbgp` block is set; the default stays `mode: observe`,
  and observe and suggest never call the steerer.
- Inject needs an allowlist, `hold_time`, the loss and RTT thresholds, and
  `max_improvements`, which caps the routes on the router.
- A route is never more specific than /24 or /48, and only a tagged route
  is changed or removed (RouterOS comment `packeteer-steer`, Linux
  `proto 250`).
- Routes are removed on SIGTERM, shutdown, retirement, provider loss,
  probe-source failure, and stale data. A new start removes tagged routes a
  previous process left.
- Steerers are in-process only. Router credentials come from environment
  variables and the URL must be https (http only to a loopback host).
- Nothing is exported over BGP; the herd sees the announced prefix only.

## Rules it does not meet

AGENTS.md and BOT.md have no exception for this mode on four points. The
code is kept off the default path and marked partial in FEATURES.md until
the owner either amends the charter or drops the mode.

1. **Prefixes outside a learned RIB view.** There is no RIB. Synthetic
   prefixes come from flow data and may widen inside an announced prefix
   found by a `covering` plugin (RIPEstat). The charter allows one such
   exception, `synthesize`, under its own rails.
2. **No withdraw on a crash.** A static route does not leave with a
   session. After SIGKILL or power loss the routes stay until the next
   start sweeps them, or an operator deletes them.
3. **No community or NO_EXPORT.** A static route has neither; the tag is a
   comment or protocol number.
4. **No lab job.** Announce, withdraw, and crash-withdraw are covered by
   unit and daemon tests with a fake router, not by the lab (a netns or CHR
   job would be needed, and the lab runs only in CI).

An amendment would need to state: static routes may follow flow-derived
prefixes inside an announced prefix; a crash may leave them until the next
start or a router-side expiry; and the lab job that proves it.
