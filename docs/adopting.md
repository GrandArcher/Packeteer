# Adopting Packeteer alongside or in place of a route optimizer

This page is for a network that already runs a route optimizer, or buys one, and wants to try Packeteer without a risky switch. It maps the common optimizer concepts to Packeteer config and gives a cut-over plan that starts in observe. To estimate what the move is worth, use the [ROI worksheet](roi.md).

Packeteer does not read another product's configuration. You copy the intent by hand, using the table below.

## What does not change

- The default mode is `observe`. `observe` and `suggest` announce nothing.
- A move is made per prefix through the decision engine, never in bulk. The prefix must be in the RIB Packeteer learned from your router, and in inject it must be in `allowlist.prefixes`.
- Steering uses the exact learned prefix. The opt-in `synthesize` and `more_specific` blocks are the only exceptions and are not part of this plan.
- Every injected route carries `packeteer_community` and `no-export`. `max_improvements`, `hold_time`, the thresholds, and the withdraw on shutdown, probe-source loss, stale data, and RIB session loss stay as documented in the [README](../README.md#safety-model).
- MED is display only. Every probe packet still waits on `probe.rate_limit_pps`.

## Concepts and where they live

| Common concept | Packeteer | Reference |
|---|---|---|
| Provider, transit, peer | `providers[]`: `name`, `source_ip` (probe source), `next_hop` (matches learned routes and is the injected next hop), optional `type`, `asn`, `cost`, `group`, `precedence`. `exchanges[]` for IX peers. | [CONFIG.md](CONFIG.md#providers) |
| Improvement (a prefix moved to a better exit) | An improvement on `/api/improvements`. In observe and suggest it is a recommendation. In inject it is the route being announced. Causes: `performance`, `commit`, `cost`, `static`. | [API.md](API.md) |
| Performance thresholds | `thresholds`: `min_loss_delta_pct`, `min_rtt_delta_ms`, optional `min_rtt_delta_pct` and `confirm_rounds`. With both deltas at `0` no improvement is recorded. | [CONFIG.md](CONFIG.md#thresholds) |
| Hysteresis, minimum time on a path | `hold_time`, `confirm_rounds`, `improvement_ttl`, and `flap_quarantine`. | [CONFIG.md](CONFIG.md#thresholds) |
| Limit on concurrent moves | `max_improvements` (default 50). | [CONFIG.md](CONFIG.md) |
| Commit control, keep a provider under its commit | `scorer.type: commit`, plus `telemetry` (`snmp`) with `commit_mbps` per provider and a `flow` source for prefix volume. Provider groups, `precedence`, and `cc_disable` shape where traffic goes. | [CONFIG.md](CONFIG.md#scorer-commit), [ui.md](ui.md#commit--cost) |
| Cost optimization | `providers[].cost` (price per Mbps) and `scorer.type: cost`. Moves only onto a cheaper provider whose path is inside a performance floor. | [CONFIG.md](CONFIG.md#scorer-cost) |
| VIP or critical prefixes and ASNs | `vip` source (faster probing of listed prefixes and ASNs) and a `rules` policy with `action: vip` (admitted ahead of other performance moves when the cap binds). | [CONFIG.md](CONFIG.md#source-vip), [CONFIG.md](CONFIG.md#policies) |
| Pin a prefix to a provider | `rules` policy with `action: static`, a provider, and `max_loss_pct`. The pin holds only while the path stays healthy. | [CONFIG.md](CONFIG.md#policies) |
| Never touch a prefix, or never use a provider | `rules` policy with `action: ignore`, `allow`, or `deny`. | [CONFIG.md](CONFIG.md#policies) |
| Maintenance window | `maintenance` policy (cron windows, one-off windows, or `POST /api/maintenance`). | [CONFIG.md](CONFIG.md#policy-maintenance) |
| Circuit or upstream outage detection | `outage` source: re-probes when several prefixes degrade together, and emits `outage.as` or `outage.circuit`. The probe-path check marks a provider down when its probes do not leave through its `next_hop`. | [CONFIG.md](CONFIG.md#source-outage), [EVENTS.md](EVENTS.md) |
| Probe targets from traffic | `flow` source (NetFlow, IPFIX, sFlow), `span`, `traceroute`, and `static` sources. | [CONFIG.md](CONFIG.md#source-flow) |
| Reports, before and after, savings | `storage: {type: sqlite}` and the reports `summary`, `improvements`, `timeseries`, `savings`. | [ui.md](ui.md#reports) |
| Alerts | `notifiers`: `webhook`, `smtp`, `snmptrap`. | [EVENTS.md](EVENTS.md) |
| Monitoring only, no changes to routing | `mode: observe` (the default). | [README](../README.md#safety-model) |

## Cut-over plan

Each step ends with something you can check. Do not skip ahead: nothing before step 5 announces a route.

### 1. Write down what the current optimizer does

List, per the table above: the providers and their next hops, each provider's commit and price per Mbps, the VIP prefixes and ASNs, the prefixes it must never move, the exclusions, and the thresholds and hold times it uses. Keep the list; step 6 compares against it.

### 2. Install in observe

Follow the [quickstart](quickstart.md) or `scripts/install.sh` ([onboarding](onboarding.md)). Config for the first run is the minimal file from the README with `mode: observe`. Add the pieces from your list. A sketch with documentation addresses:

```yaml
mode: observe
asn: 64512
router_id: 192.0.2.10
providers:
  - name: transit-a
    source_ip: 192.0.2.11
    next_hop: 192.0.2.1
    cost: 2.00
    group: transit
  - name: transit-b
    source_ip: 192.0.2.12
    next_hop: 192.0.2.2
    cost: 1.20
    group: transit
thresholds:
  min_loss_delta_pct: 1
  min_rtt_delta_ms: 15
  confirm_rounds: 3
hold_time: 15m
max_improvements: 50
probe:
  interval: 30s
  timeout: 2s
  packets: 10
sources:
  - type: static
    config:
      targets:
        - prefix: 198.51.100.0/24
          host: 198.51.100.1
  - type: vip
    config:
      interval: 10s
      prefixes:
        - prefix: 203.0.113.0/24
          host: 203.0.113.1
  - type: outage
    config:
      min_prefixes: 3
      interval: 5s
policies:
  - type: rules
    config:
      rules:
        - name: critical
          action: vip
          prefixes: [203.0.113.0/24]
scorer:
  type: weighted
http:
  listen: "127.0.0.1:8080"
```

Run `-check` on it before you start the container. The probe sources need the host policy routing in [policy-routing.md](policy-routing.md), or every provider measures the same path.

### 3. Connect to the router read-only

Add the iBGP neighbor so Packeteer learns the router's exits ([routers.md](routers.md) and the guide for your router). With no `announcer` and `mode: observe` the session only learns. Packeteer then knows which provider each prefix uses today and can compare it with the others.

Check on the Settings page that the preflight checks pass, that every provider is up and its probes leave through its `next_hop`, and that the dashboard's current exit matches what the router shows.

### 4. Run beside the existing optimizer

Leave the current optimizer in charge. Packeteer observes the router's chosen exit, which includes whatever the other optimizer has injected, so its "current exit" is the exit your traffic really takes. Do not give Packeteer a path to inject while another system also injects for the same prefixes: two injectors for one prefix is a conflict that no Packeteer setting resolves.

Collect at least one billing period if you want a commit comparison, and a few days if you only want a performance comparison. Use:

- `/api/improvements` and the dashboard for the recommended exit against the current exit, with the reason sentence;
- the `summary`, `improvements`, and `savings` reports for before and after loss and latency and for estimated savings (`est_savings`, or `cost_delta` per Mbps when no `flow` source gives a volume);
- `/commit.html` for the 95th percentile against the commit, when telemetry is configured;
- the VIP and outage events, to compare with what the other optimizer reported.

Move to `mode: suggest` when you are ready to read the log as a list of proposed moves. It is the same process and announces nothing.

### 5. Inject on a small allowlist

Injection is proven in the lab against simulated routers. Turning it on for your own edge is your decision and your risk. Do it only after step 4 shows recommendations you would accept, and only with these limits:

1. Stop the other optimizer's injection for the prefixes you hand to Packeteer, and confirm on the router that its routes for them are gone. The two must never announce the same prefix.
2. Put the router filters from your router guide in place: accept from Packeteer only `packeteer_community`, and reject that community on every eBGP session. Leave graceful restart off.
3. Fill in the [inject checklist](CONFIG.md#inject-checklist): `mode: inject`, a short `allowlist.prefixes`, `packeteer_community`, `local_pref`, a positive `hold_time`, both thresholds, an iBGP neighbor, and `announcer.type: gobgp`.
4. Start with a small `max_improvements` and one or two prefixes. Check one route on the router for the community and `no-export` before you widen the allowlist ([operating.md](operating.md#suggest-then-inject)).
5. Add commit control or cost optimization last, and one at a time: `scorer.type: commit` with telemetry, or `scorer.type: cost`. Each has its own rollback (switch back to `weighted` and restart).

The full sequence with expected output is the [walkthrough](walkthrough.md).

### 6. Retire the old optimizer

Retire it per prefix set, not at once. Keep its configuration and its ability to start until Packeteer has covered a full billing period you are satisfied with. Compare against the list from step 1: commit overages, the prefixes it protected, and the outages it reported.

## Rolling back

Set `mode: observe` and restart, or stop the container with `docker stop -t 30 packeteer`. Packeteer withdraws every route it announced and the router's own BGP decision stands. If the old optimizer was stopped, start it again for the prefixes it covered. The details and the show commands to confirm are in [operating.md](operating.md#rollback).

## Not covered

- Packeteer does not import another optimizer's configuration or history.
- This page does not compare products. Verify any claim about another product with its own documentation.
