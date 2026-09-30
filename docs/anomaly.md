# Traffic anomaly (DDoS) detection

Lab-proven only (#33). It has not been run on a public edge.

Packeteer can watch flow data for traffic floods and, when you tell it to, answer them with a [threat mitigation](mitigation.md) rule (RTBH, redirect, or FlowSpec).

- **Baselines.** The `flow` source counts bytes per destination prefix and IP protocol. Every `anomaly.interval` (default 10s) the controller turns the counter deltas into rates and hands them to the detector plugin. The built-in `baseline` detector keeps an exponentially weighted mean and variance for each key.
- **Detection.** A round is anomalous when the rate is at least `min_mbps`, at least `min_ratio` × the mean, and more than `sensitivity` standard deviations above the mean, once the key has learned for `warmup` rounds; or, with `max_mbps` set, when the rate reaches that ceiling. An anomaly opens after `trigger_rounds` anomalous rounds and clears after `clear_rounds` normal rounds. Anomalous rounds are not learned, so a long attack does not become the baseline.
- **Alerts.** Every anomaly is logged, listed on `GET /api/anomalies` with a feed of the last 200 changes, sent to the notifiers as `anomaly.*` events ([EVENTS.md](EVENTS.md)), and stored as history with a storage plugin.
- **Actions only by explicit rule.** An anomaly becomes a mitigation rule only when one of `anomaly.rules` matches it: the destination is inside the rule's `prefixes`, the protocol is one of its `protocols`, and the rate is at least its `min_mbps`. With no rule, or no match, nothing is announced.

## Safety

- **Through mitigation only.** The detector never announces. A matched rule is a request to the mitigation controller, which applies its own `mode` (`observe` is a dry run), allowlist, `max_rules`, TTL, `packeteer_community`, the marker, and NO_EXPORT, and announces only while the exact prefix is in the learned RIB. Rule prefixes must be inside `mitigation.allowlist` at startup.
- **Exact learned prefix.** The flow source maps each destination to its covering prefix in the RIB view. The detector adds a rule only when that prefix is an exact prefix in the learned RIB (otherwise it waits: `anomaly.held`). An aggregate the flow source made up is never announced.
- **Rate limit and cap.** `max_actions_per_hour` (default 6) caps rules added in any rolling hour; `max_active` (default 4, at most `mitigation.max_rules`) caps rules the detector holds at once. `mitigation.max_rules` still caps every mitigation route.
- **Operators win.** The detector never replaces a rule someone else holds for the same key (`refused`), and a rule that expired or was deleted is not added again for the same anomaly.
- **No stale intent.** The rule is removed when its anomaly clears, and it expires on its TTL in any case. When the flow source fails three rounds in a row every anomaly clears, its rule is removed, and the baselines are learned again. Baselines, anomalies, and rules live in memory only: a restart holds nothing and learns again.
- **Withdraw on failure.** Detector rules are ordinary mitigation rules: SIGTERM withdraws them while the session is up, RIB session loss withdraws them, and a crash drops them with the session (no graceful restart).
- **HA.** A standby detects but adds no rule.
- In-process only. There is no `exec` detector.

## Config

```yaml
sources:
  - type: flow
    config:
      listen: "0.0.0.0:2055"
mitigation:
  mode: observe                  # inject only in a lab
  allowlist: [203.0.113.0/24]
  max_rules: 10
  announcer:
    type: gobgp
    config:
      marker: "64512:668"
      flowspec: {}
anomaly:
  interval: 10s
  max_actions_per_hour: 6
  max_active: 4
  detector:
    type: baseline
    config:
      sensitivity: 3            # standard deviations; lower is more sensitive
      min_ratio: 3              # and at least 3x the baseline
      min_mbps: 50              # and at least 50 Mbit/s
      # max_mbps: 5000          # static ceiling, also for keys with no baseline
      warmup: 30                # rounds before a key can fire
      trigger_rounds: 2
      clear_rounds: 3
  rules:
    - name: udp-flood
      prefixes: [203.0.113.0/24]
      protocols: [udp]
      min_mbps: 100
      action: flowspec_drop     # matches the anomaly's protocol
      ttl: 30m
```

Every key is in [CONFIG.md](CONFIG.md#anomaly). Tuning: raise `sensitivity` and `min_ratio` to fire less often; set `min_mbps` above your normal per-prefix peaks; `warmup` × `interval` is how long a new key learns (5 minutes by default). A key that is idle has a baseline near zero, so any rate over `min_mbps` on it fires once it has learned.

## API

`GET /api/anomalies` (viewer): the detector, the source, `baselines` (keys tracked), the caps, `actions_last_hour`, the rules, the open anomalies (`prefix`, `protocol`, `mbps`, `peak_mbps`, `baseline_mbps`, `reason`, `since`, `rule`, `mitigation`, `state`), and `feed` (newest first: `detected`, `mitigated`, `held`, `mitigation_ended`, `cleared`). Mitigation rules the detector added are on `/api/mitigations` with the reason `anomaly <id> (rule <name>): ...`, and can be removed there. `/metrics` has `packeteer_anomalies_active`, `packeteer_anomaly_mitigating`, `packeteer_anomaly_baselines`, and `packeteer_anomaly_actions_last_hour`. With a storage plugin, `GET /api/reports/anomalies?days=7` (and `&format=csv`) lists every anomaly with the rule and mitigation.

## Lab

`lab/e2e-anomaly.sh` runs the FRR mitigation lab (an edge that learns 198.51.100.0/24 from a simulated transit and exports to a second one) with a flow source and synthetic NetFlow v5 from `lab/sendflow`. It proves on the routers: steady traffic raises nothing; a 1.6x rise stays under the detector's sensitivity; a TCP flood on the learned prefix is detected but has no rule and announces nothing; a UDP flood toward a documentation prefix that is not in the learned RIB is detected and never announced; a UDP flood on the learned prefix becomes a FlowSpec drop (`protocol udp`, marker, NO_EXPORT) on the edge and never reaches the other transit; the drop is withdrawn when the flood stops; RIB session loss withdraws it and it comes back with the session while the flood lasts; SIGTERM withdraws it; and SIGKILL drops it within the BGP hold time.

## Rollback

Remove `anomaly.rules` (alerts only) or the `anomaly` block and restart: every rule the detector added is gone with the restart, and nothing is added again. Setting `mitigation.mode: observe` also turns every detector rule into a dry run.
