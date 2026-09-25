# Packeteer

Open-source BGP path performance controller for multi-homed networks. One container, a mounted config file, and the edge router you already run.

Packeteer sits off to the side of the edge. It probes each upstream from that upstream's source address, scores loss, latency, and jitter, and learns today's exit from iBGP. In the default mode it only reports. If you later turn injection on, it advertises a better exit back to the edge for prefixes you allowlisted. If Packeteer stops, those routes go away and the router's own BGP decision stands.

The capability matrix against Noction IRP is [docs/IRP_PARITY.md](docs/IRP_PARITY.md).

## Safety model

Read this before you change `mode`.

- The default mode is `observe`. The file in this repository stays `observe`. `suggest` probes and recommends, and announces nothing.
- `inject` is a separate config: `mode: inject`, a non-empty allowlist, `packeteer_community`, `local_pref`, a positive `hold_time`, positive loss and latency thresholds, an iBGP neighbor, and `announcer.type: gobgp`.
- Packeteer announces a prefix only when that exact prefix is in the RIB it learned from the router. It does not invent a more-specific. A config that sets `more_specific_bits` is rejected.
- Active improvements are capped (`max_improvements`, default 50).
- A new improvement waits for a real gain (the thresholds) and then stays up for at least `hold_time`.
- Every injected route carries your community and the well-known `no-export` community. The edge must accept only that community from Packeteer, and must reject it on every eBGP session. `no-export` is the second layer.
- Packeteer withdraws its routes on shutdown, when a probe source dies, when measurements go stale (including when a probe round never finishes), when every iBGP session drops, and when a prefix the router was still advertising leaves the RIB. Graceful restart is never enabled. A kill is covered by the BGP hold timer (Packeteer proposes 90 seconds; a shorter timer from the router wins).
- This repository uses documentation prefixes (RFC 5737, RFC 3849) and the private ASN 64512. Keep real prefixes and real ASNs out of commits, issues, and logs you paste in public.

Threat model: [docs/THREAT_MODEL.md](docs/THREAT_MODEL.md). Agent rules: [AGENTS.md](AGENTS.md).

## Install

The image is `ghcr.io/grandarcher/packeteer`, linux/amd64 and linux/arm64. It runs as root inside the container so it can open raw ICMP sockets and, if you ask it to, TCP port 179. Give it `NET_RAW` and `NET_ADMIN`. It needs host networking: probes must leave from each provider's source address, the iBGP session must reach the router, and a flow collector binds host UDP ports.

| Tag | What it is |
|---|---|
| `0.1.0` | This release. Pin this. |
| `latest` | The same release, updated when a release tag is published. |
| `edge` | The build from `main`. The Compose file in this repo uses it. |

The commands below use `:edge`, which is published on every push to `main`. For a pinned install, set `IMAGE=ghcr.io/grandarcher/packeteer:0.1.0`.

### docker run

```sh
curl -fsSLo config.yaml https://raw.githubusercontent.com/GrandArcher/Packeteer/main/config.example.yaml
# Edit providers and source IPs. Leave mode: observe.
mkdir -p plugins
IMAGE=ghcr.io/grandarcher/packeteer:edge

docker run --rm \
  -v "$PWD/config.yaml:/etc/packeteer/config.yaml:ro" \
  "$IMAGE" -check

docker run -d --name packeteer --network host \
  --cap-add NET_RAW --cap-add NET_ADMIN \
  --restart unless-stopped \
  -v "$PWD/config.yaml:/etc/packeteer/config.yaml:ro" \
  -v "$PWD/plugins:/etc/packeteer/plugins:ro" \
  "$IMAGE"
```

`-check` prints `mode: observe` and `check: ok (no probes sent, no BGP sessions opened)`. The image does not contain your config. It does contain the example at `/etc/packeteer/config.example.yaml`:

```sh
docker run --rm -e PACKETEER_CONFIG=/etc/packeteer/config.example.yaml \
  ghcr.io/grandarcher/packeteer:edge -check
```

The default config path inside the container is `/etc/packeteer/config.yaml` (`PACKETEER_CONFIG`, or `-config`).

### Docker Compose

From a checkout of this repository (or after you save [docker-compose.yml](docker-compose.yml) next to `config.yaml`):

```sh
curl -fsSLo config.yaml https://raw.githubusercontent.com/GrandArcher/Packeteer/main/config.example.yaml
curl -fsSLo docker-compose.yml https://raw.githubusercontent.com/GrandArcher/Packeteer/main/docker-compose.yml
mkdir -p plugins
# Edit config.yaml. Leave mode: observe.
docker compose up -d
docker compose logs -f
```

The Compose file uses `ghcr.io/grandarcher/packeteer:edge`, host networking, and the two capabilities. To pin the release, change the `image` line to `ghcr.io/grandarcher/packeteer:0.1.0`. There is no `ports:` map: with host networking, `http.listen` is already an address on the host.

Stop with `docker compose stop -t 30` (see [Rollback](#rollback)).

## Minimum config

The smallest file that validates, probes, and serves the dashboard is below. Addresses are documentation ranges. Replace `source_ip` and `next_hop` with addresses that exist on your host and on your transits. Leave `mode: observe`.

```yaml
mode: observe
asn: 64512
router_id: 192.0.2.10
providers:
  - name: transit-a
    source_ip: 192.0.2.11
    next_hop: 192.0.2.1
  - name: transit-b
    source_ip: 192.0.2.12
    next_hop: 192.0.2.2
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
http:
  listen: "127.0.0.1:8080"
```

One provider passes validation. Two is the useful case: Packeteer compares the same destination out of each. The file above omits `thresholds`, so both deltas stay `0` and no improvement is recorded. [config.example.yaml](config.example.yaml) sets `min_loss_delta_pct: 1` and `min_rtt_delta_ms: 15` and comments the rest of the keys.

Every key, default, and bound is in [docs/CONFIG.md](docs/CONFIG.md).

## Host policy routing

A probe toward a destination is sent with that provider's `source_ip`. The host routing table has to send packets from that address out of the matching transit. Otherwise every provider measures the same path. If `source_ip` is not configured on the host, that provider is marked down and left out.

The container uses `--network host`, so the rules live on the host. Full steps, reverse-path filtering, IPv6, and the MikroTik equivalent: [docs/policy-routing.md](docs/policy-routing.md). The addresses in that guide are a separate subnet per transit. The minimum config above uses one documentation subnet so the YAML stays short; on a real host, `source_ip` and `next_hop` have to be the addresses in the rules.

```sh
ip addr add 192.0.2.11/24 dev eth1
ip addr add 198.51.100.11/24 dev eth2
echo "101 transit-a" >> /etc/iproute2/rt_tables
echo "102 transit-b" >> /etc/iproute2/rt_tables
ip route add default via 192.0.2.1 dev eth1 table transit-a
ip route add default via 198.51.100.1 dev eth2 table transit-b
ip rule add from 192.0.2.11 lookup transit-a priority 1001
ip rule add from 198.51.100.11 lookup transit-b priority 1002
ip route get 203.0.113.1 from 192.0.2.11
ip route get 203.0.113.1 from 198.51.100.11
```

Use the `source_ip` and `next_hop` values from your config. Make the rules persistent with the host's network config. On the probe interfaces, loose reverse-path filtering avoids dropping replies that arrive on a different interface than the default route:

```sh
sysctl -w net.ipv4.conf.all.rp_filter=2
```

## Router setup

You can run observe with no BGP session. Packeteer then ranks paths and does not know which exit the router uses, so it will not recommend a move.

To learn current exits, peer iBGP, same ASN, between the router and Packeteer. In observe and suggest, Packeteer announces nothing on that session. Before inject, install both filters:

1. From Packeteer, accept only routes that carry `packeteer_community`.
2. Toward every eBGP neighbor, reject that community.

Leave graceful restart off on the session. Guides:

- [docs/mikrotik.md](docs/mikrotik.md) — RouterOS 7 iBGP, filters, and Traffic Flow
- [docs/routers.md](docs/routers.md) — FRR, Junos, IOS, and what happens when the native path disappears
- [docs/policy-routing.md](docs/policy-routing.md) — probe sources behind the router

A flow export (NetFlow, IPFIX, or sFlow) is optional. It only adds probe targets. It does not inject routes. With host networking the collector's UDP port is a host port; firewall it to the exporter.

A `udp` prober is an optional fallback after ICMP and TCP. It counts a reply from the target, not an ICMP unreachable from a firewall on the path. A `traceroute` source discovers the probe host in the background and moves the probe onto the last stable hop when the configured host does not answer. A `vip` source probes a capped prefix list, and a capped set of prefixes whose learned AS path contains a listed ASN, on an interval that must stay inside the staleness window. Set `probe.retry_loss_pct` to re-measure a lossy sample with more packets before it is stored; the default is off. An `outage` source watches completed rounds. When several prefixes that share an ASN, or that fail on one provider only, degrade together, it re-queues them and emits `outage.as` or `outage.circuit` to the configured notifiers. One noisy prefix does not. The re-queue is capped and is not an announcement. None of these announce a route. The global packet rate limit still applies. Details are in [docs/PLUGINS.md](docs/PLUGINS.md).

## Start in observe

1. Mount the minimum config, or `config.example.yaml`, with `mode: observe`.
2. `docker run ... -check` (or `go run ./cmd/controller -check -config config.yaml` from a checkout).
3. Start the container.
4. Open the dashboard at `http://127.0.0.1:8080/` when `http.listen` is the default. Logs show one line per probe (`loss_pct`, `rtt_avg`, `jitter`) and, once a session is up, `bgp session` state and a periodic `rib ready=true`.

```sh
curl -fsS http://127.0.0.1:8080/healthz
curl -fsS http://127.0.0.1:8080/readyz
curl -fsS http://127.0.0.1:8080/api/providers
curl -fsS http://127.0.0.1:8080/metrics
```

`/healthz` stays up while the process is serving. `/readyz` returns 503 until startup finishes, and until an iBGP session is up when `bgp.neighbors` is set. No neighbors means ready as soon as startup finishes.

Stay here until the numbers match what you expect from each transit. A `probe failed` line whose error contains `probe source address unavailable` means that `source_ip` is missing on the host or the policy route is wrong. A successful probe with high `loss_pct` is a measurement of that transit.

## Suggest, then inject

`mode: suggest` is the same process as observe. It writes recommendations to the log, the dashboard, and `/api/decisions`, and it still announces nothing. Set the thresholds from the example config first. With both deltas at `0`, no improvement is recorded.

Read `/api/improvements` and the dashboard's current exit against the recommended exit. An improvement appears only when the prefix is in the learned RIB, both the native provider and the candidate have fresh measurements, the gain clears the thresholds, the candidate's score is lower, the provider is not excluded, and the cap has room.

Inject only after the router filters in the guides are in place, and only for prefixes you mean to steer. Change the mounted config (do not change the example in this repository):

- `mode: inject`
- `allowlist.prefixes`: prefixes you operate. A learned prefix is eligible when it is equal to an entry or more specific and inside it. Packeteer announces that learned prefix.
- `packeteer_community`: `"<asn>:<value>"`, each half 0–65535. Quote it.
- `local_pref`: higher than the native local preference on the edge.
- `hold_time`: a positive duration (`15m` in the example).
- `thresholds.min_loss_delta_pct` and `thresholds.min_rtt_delta_ms`: both greater than 0.
- `bgp.neighbors`: at least one iBGP neighbor.
- `announcer` with `type: gobgp`. The announcer has no config block.

Packeteer reads the file at startup. Restart after you edit it:

```sh
docker restart -t 30 packeteer
# or, from the Compose directory:
docker compose restart -t 30
```

Then confirm one route on the router before you widen the allowlist.

On the router, an injected route shows your community and `no-export`:

- MikroTik: `/routing route print where bgp-communities~"64512:666"`
- FRR: `vtysh -c 'show bgp ipv4 unicast <prefix> json'` (communities `64512:666` and `no-export`, next hop of the chosen provider)
- Junos: `show route community 64512:666`
- IOS: `show ip bgp community 64512:666`

Replace `64512:666` with your community. The full filter snippets are in the router guides, not here, so this page cannot be copied onto an edge as an inject config.

## Rollback

Stopping the container withdraws every Packeteer route.

```sh
docker stop -t 30 packeteer
# or, from the Compose directory:
docker compose stop -t 30
```

`docker stop` sends SIGTERM. Packeteer withdraws, then closes the iBGP session. The Compose `restart: unless-stopped` policy does not start it again after `docker stop` or `docker compose stop`. Give the process 30 seconds so Docker does not SIGKILL it while the withdraw is in flight. The default Docker stop timeout is 10 seconds, which races the withdraw.

Confirm the routes are gone with the same show commands as above. The community lookup should be empty, and the prefix should be back on the provider exit. `docker compose down -t 30` stops and removes the container; the effect on BGP is the same.

`docker kill` does not withdraw. The routes remain until the router's BGP hold timer expires. The Compose restart policy also starts the container again after a kill. Use `docker stop` when you want the routes gone and the process left stopped.

Switching the file back to `mode: observe` and restarting withdraws as well: the old process withdraws on the way down, and the new process does not announce.

Other withdraws, while the container is still running:

- measurements older than about three probe intervals (a round that never finishes counts)
- a provider probe source that fails
- every iBGP session down
- the router withdraws a prefix it was still advertising after the improvement had been up for a few seconds

When Packeteer's route is best, a normal iBGP session stops sending the native path back. That hide is not a withdraw. The improvement stays until flip-back or `improvement_ttl`. See [docs/routers.md](docs/routers.md).

## Dashboard, API, and metrics

`http.listen` defaults to `127.0.0.1:8080`. Set it to `""`, or set `PACKETEER_HTTP_LISTEN=off`, to disable it. Any other value of `PACKETEER_HTTP_LISTEN` replaces `http.listen`. The image exposes port 8080 as documentation; with host networking you do not publish it.

The server is read-only (GET and HEAD). The dashboard loads no remote assets and refreshes every 5 seconds.

| Path | Body |
|---|---|
| `/` | Provider health, per-prefix loss / RTT / jitter, current vs recommended exit, active improvements. |
| `/healthz` | Liveness. JSON `status` is `ok`. |
| `/readyz` | Readiness. 503 until startup finishes, and until an iBGP session is up when neighbors are configured. |
| `/metrics` | Prometheus text. |
| `/api/providers` | Providers, probe-source health, and BGP sessions. |
| `/api/probes` | Latest probe per provider and prefix. |
| `/api/prefixes` | Probed prefixes with measurements, current exit, and recommended exit. Prefixes that are only in the RIB are not listed. |
| `/api/decisions` | Latest per-prefix decision. |
| `/api/improvements` | Active improvements. In observe and suggest these are recommendations. In inject they are the routes being announced. |
| `/api/telemetry` | Interface rates and 95th-percentile usage when a telemetry plugin is configured. Empty when it is not. This does not announce. |

Basic auth is off unless both `PACKETEER_HTTP_USER` and `PACKETEER_HTTP_PASSWORD` are set. Setting only one refuses to start. Set both when `http.listen` is not loopback. The password is not read from the config file and is not written to the log.

Prometheus metrics are `packeteer_up`, `packeteer_ready`, `packeteer_build_info`, `packeteer_provider_up`, `packeteer_probe_success`, `packeteer_probe_rtt_seconds`, `packeteer_probe_rtt_min_seconds`, `packeteer_probe_rtt_max_seconds`, `packeteer_probe_loss_ratio`, `packeteer_probe_jitter_seconds`, `packeteer_decisions`, `packeteer_decision`, `packeteer_improvements_active`, `packeteer_improvement`, `packeteer_bgp_configured`, `packeteer_bgp_ready`, `packeteer_bgp_session_up`, `packeteer_bgp_session`, and, when telemetry is configured, `packeteer_telemetry_up`, `packeteer_telemetry_in_bps`, `packeteer_telemetry_out_bps`, `packeteer_telemetry_in_95th_bps`, `packeteer_telemetry_out_95th_bps`, `packeteer_telemetry_usage_bps`, `packeteer_telemetry_commit_bps`, and `packeteer_telemetry_samples`. Scrape `http://127.0.0.1:8080/metrics` on the host.

`PACKETEER_LOG_LEVEL=debug` adds detail. `log.format: json` or `PACKETEER_LOG_FORMAT=json` switches the log to JSON.

## Plugins

Probers, target sources, the scorer, the announcer, notifiers, and telemetry are plugins selected by `type` in the config. Unknown types and unknown keys inside a plugin `config` block refuse startup. Built-ins: probers `icmp`, `tcp`, `udp`, and `fixed` (labs only); sources `static`, `flow`, `traceroute`, `vip`, and `outage`; scorers `weighted` (default) and `commit` (optional commit control and provider groups; does not announce); announcer `gobgp`; notifier `webhook`; telemetry `snmp` (interface counters and 95th percentile; credentials from the environment; does not announce) and `fixed` (labs only; a configured usage figure; does not announce). An `exec` plugin is any executable you mount at `/etc/packeteer/plugins` and works in the stock image. Announcers are in-process only. Telemetry is built in.

Details, the exec protocol, and a shell example: [docs/PLUGINS.md](docs/PLUGINS.md). Keys: [docs/CONFIG.md](docs/CONFIG.md).

## FAQ

**The container exits immediately.** The log line `refusing to start` is a config or plugin error. Run `-check`. Unknown YAML keys, a missing provider, and an inject file that omits the allowlist or the community all fail closed.

**The dashboard has no prefixes.** Add a `sources` entry. Prefixes that sit only in the RIB are not listed. A failed probe is a source address, a missing `NET_RAW`, or a filter in the path. ICMP falls back to TCP port 443 when ICMP cannot run.

**`/readyz` stays 503.** Neighbors are configured and no session is established. Check ASN, reachability, and whether Packeteer should connect out (`listen_port` 0) or wait (`passive` plus `listen_port`). Filters do not stop the session from coming up; they stop routes.

**Nothing is recommended.** Thresholds are still `0`, the prefix is not in the RIB, the RIB next hop matches no provider, the gain is inside the thresholds, or the provider is excluded.

**Inject is on and the router shows no route.** The prefix is not in the learned RIB, it is outside the allowlist, the cap is full, or the router rejected the community. Packeteer will not announce a prefix it has not learned.

**Will a stop leak routes to transit?** The route is withdrawn and tagged `no-export`. The eBGP community filter in the router guides is what you control if `no-export` is stripped. After `docker stop -t 30`, the community lookup on the router should be empty.

**Can I put my config in this git repo?** Keep it on the host you mount into the container. Do not commit real prefixes, ASNs, SNMP communities, or hook tokens.

## IRP parity

Feature parity with Noction IRP is the roadmap. Status as of v0.1.0, from [docs/IRP_PARITY.md](docs/IRP_PARITY.md):

| | Count |
|---|---|
| Done, v0.1 (this release) | 24 |
| Planned, v0.2 | 26 |
| Planned, v0.3 | 17 |
| Planned, v0.4 | 12 |
| Won't do | 3 |

v0.1 is the outbound loop: probes, static and flow targets, an iBGP RIB, scoring with hysteresis, optional injection, the read-only UI and API, the container, and the FRR lab. v0.2 through v0.4 are the remaining matrix rows (cost and commit, inbound, BMP, FlowSpec, multi-POP, HA, RBAC). v0.5 (issues #49–#54) is hardening and field feedback. It does not relax the safety rules above.

## Build from source

Go 1.26.

```sh
go build -o packeteer ./cmd/controller
./packeteer -check -config config.example.yaml
./packeteer -version
docker build -t packeteer .
```

`go test ./...`, `go vet ./...`, and an empty `gofmt -l .` are the local bar. BGP behavior is tested against the FRR lab in CI (`bash lab/e2e.sh`), not against a live edge. See [lab/README.md](lab/README.md).

## Layout

```
cmd/controller/     # entrypoint
internal/httpapi/   # health, metrics, JSON API, embedded dashboard
internal/probe/     # per-provider sourced measurements
internal/policy/    # score + hysteresis
internal/announce/  # inject-mode gate in front of the announcer plugin
internal/rib/       # learn-only iBGP view (embedded GoBGP)
internal/plugins/   # probers, target sources, scorer, announcer, notifier, telemetry
docs/CONFIG.md      # config reference
lab/                # FRR e2e lab (CI job e2e)
```

## Support the project

Packeteer is free and open source. If it helps your network, you can chip in to cover development and lab costs through [PayPal](https://paypal.me/GrandArcher) or the **Sponsor** button at the top of this page.

## License

Apache-2.0. See [LICENSE](LICENSE).
