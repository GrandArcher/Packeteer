# Threat-intelligence feeds

Lab-proven only (#134). It has not been run on a public edge.

Packeteer can fetch lists of networks from a threat-intelligence feed and, for an explicit rule, turn a listed network into a [threat mitigation](mitigation.md) rule (RTBH, redirect, or FlowSpec).

- **Feeds.** A `threat_feed` plugin fetches the whole list every `threat_feeds.interval` (default 15m). The built-in `http` feed reads plain CIDR lines or a documented JSON format ([CONFIG.md](CONFIG.md#threat-feed-http)).
- **Rules.** A listed network becomes a mitigation rule only when a rule in `threat_feeds.rules` reads its feed. With `match: destination`, a listed network that equals or sits inside the rule's `prefixes` is the rule's destination. With `match: source`, it is the FlowSpec `source` of a rule toward each of the rule's `prefixes` of the same address family. Rules are tried in order, then the feed's entries in its order.

## Safety

- **Through mitigation only.** A feed never announces. A rule is a request to the mitigation controller, which applies its own `mode` (`observe` is a dry run: the rules are listed on `/api/mitigations` and nothing is announced), allowlist, `max_rules`, TTL, `packeteer_community`, the marker, and NO_EXPORT. Rule prefixes must be inside `mitigation.allowlist` at startup, and rule actions must be in the mitigation announcer's catalog.
- **Exact learned destination.** A rule is added only while its destination is an exact prefix in the learned RIB. A listed network that is not learned waits, and is never announced. A source match only narrows a FlowSpec rule and is never announced as reachability.
- **Rate limit and cap.** `max_actions_per_hour` (default 6) caps rules added in any rolling hour; `max_active` (default 4, at most `mitigation.max_rules`) caps rules the feeds hold at once. `mitigation.max_rules` still caps every mitigation route. Past a cap the remaining entries wait; `/api/threat-feeds` says why (`waiting`).
- **Operators win.** Feeds never replace a rule someone else holds for the same key (`refused`). A rule removed or replaced by someone else before its TTL is not added again while the feed lists the network.
- **Delisting.** A rule is removed when a successful fetch no longer lists its network. A successful empty list removes every rule of that feed.
- **Feed failure.** A failed fetch (network error, non-2xx, a body that does not parse, too large) clears nothing and adds nothing. Rules already held stay until their TTL; an expired rule is not added again until the feed answers. Each failure is logged as a warning and shown on `/api/threat-feeds` (`error`) and in `packeteer_threat_feed_up`.
- **Expiry.** Every rule has a TTL. An expired rule is added again from the next successful list that still has the network (counted in `max_actions_per_hour`), so it is off the wire for up to one round in between.
- **No stale intent.** State is in memory only. A restart drops every rule; the feeds are fetched again and their rules added again from that fresh list.
- **Withdraw on failure.** Feed rules are ordinary mitigation rules: SIGTERM withdraws them while the session is up, RIB session loss withdraws them, and a crash drops them with the session (no graceful restart).
- **HA.** A standby fetches but adds no rule.
- **Credentials.** A feed token comes from an environment variable (`token_env`), never from the config file. The URL may not carry credentials.
- In-process only. There is no `exec` feed.

## Config

```yaml
mitigation:
  mode: observe                  # inject only in a lab
  allowlist: [203.0.113.0/24]
  max_rules: 10
  announcer:
    type: gobgp
    config:
      marker: "64512:668"
      blackhole: {next_hop: 192.0.2.66}
      flowspec: {}
threat_feeds:
  interval: 15m
  max_active: 4
  max_actions_per_hour: 6
  feeds:
    - name: drop-list
      type: http
      config:
        url: https://feeds.example.net/drop.txt
        format: cidr               # or json
        token_env: PACKETEER_FEED_TOKEN
  rules:
    - name: bad-sources            # drop listed sources toward our prefix
      feed: drop-list
      match: source
      prefixes: [203.0.113.0/24]
      action: flowspec_drop
      ttl: 1h
```

Every key is in [CONFIG.md](CONFIG.md#threat_feeds). The JSON format is `{"entries": [{"prefix": "192.0.2.0/24", "comment": "botnet"}]}`; a comment is kept in the mitigation rule's reason.

## API

`GET /api/threat-feeds` (viewer): `interval`, the caps, `actions_last_hour`, `held`, `waiting` (why listed networks wait, when they do), each feed (`entries`, `last_fetch`, `last_success`, `error`), the rules, and `proposals`: the listed networks a rule acted on (`rule`, `feed`, `entry`, `comment`, `prefix`, `action`, `mitigation`, `state`, `since`). Rules the feeds added are on `/api/mitigations` with the reason `threat feed <feed> (rule <name>): <network> listed`, and can be removed there. `/metrics` has `packeteer_threat_feed_up{feed}`, `packeteer_threat_feed_entries{feed}`, and `packeteer_threat_feed_mitigations`.

## Lab

`lab/e2e-threat-feed.sh` runs the FRR mitigation lab (an edge that learns 198.51.100.0/24 from a simulated transit and exports to a second one) with a static web server serving the feed. It proves on the routers: three listed sources become FlowSpec drops toward the learned prefix but only two reach the edge (`max_active`), with the marker and NO_EXPORT, never on the other transit, and the unicast path is untouched; a listed 203.0.113.0/24 (allowlisted, not learned) is never announced; a failed fetch (404) withdraws nothing; a source leaving the feed is withdrawn and the next one takes its slot; RIB session loss withdraws the drops and they come back with the session; SIGTERM withdraws them; a restart adds them again from a fresh fetch; and SIGKILL drops them within the BGP hold time.

## Rollback

Remove the `threat_feeds` block and restart: the restart drops every rule the feeds added, and nothing is added again. Setting `mitigation.mode: observe` also turns every feed rule into a dry run. To clear one rule without a restart, `DELETE /api/mitigations/{id}`; it is not added again while the feed lists the network.
