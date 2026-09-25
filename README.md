# Packeteer

Open-source BGP path performance controller for multi-homed networks.

Packeteer measures loss, latency, and jitter toward destination prefixes over each upstream, scores the paths, and can optionally inject better routes into your edge via iBGP. It sits off-path. If Packeteer dies, native BGP remains in charge.

This is not a Noction IRP clone. v0 is observe-first: probe and score. Injection is opt-in, allowlisted, and community-tagged so you can filter it from eBGP.

## Status

M0 scaffold. Not production-ready. Do not point this at a live edge until observe mode is boring.

## Quick start (Docker)

Packeteer ships as one container. It needs host networking (probes leave through each transit's source IP, and the iBGP session must reach your edge router).

```sh
curl -fsSLo config.yaml https://raw.githubusercontent.com/GrandArcher/Packeteer/main/config.example.yaml
# edit config.yaml: providers, source IPs, next-hops. Keep mode: observe.
docker run --rm --network host --cap-add NET_RAW --cap-add NET_ADMIN \
  -v "$PWD/config.yaml:/etc/packeteer/config.yaml:ro" \
  ghcr.io/grandarcher/packeteer:edge
```

Or with Compose, using [docker-compose.yml](docker-compose.yml): `docker compose up`.

- `:edge` follows `main`. `:latest` and `:X.Y.Z` are published from release tags, starting with v0.1.0.
- The config path is `/etc/packeteer/config.yaml` by default. Override it with the `PACKETEER_CONFIG` env var or the `-config` flag.
- Out-of-process plugins can be mounted at `/etc/packeteer/plugins`.
- Images are built for linux/amd64 and linux/arm64.

In `observe` (the default) and `suggest`, Packeteer probes every target from each provider's source IP (ICMP echo, falling back to TCP 443) and logs loss, RTT min/avg/max, and jitter per provider. Targets come from `sources`. A `static` list is fixed. A `flow` source listens for NetFlow v5/v9, IPFIX, and sFlow, keeps the top destinations by bytes, and maps each one onto the covering prefix in the RIB (or a /24 or /48 when the RIB has no covering prefix). With `--network host` those UDP ports are the host's ports; there is nothing to publish. See [docs/PLUGINS.md](docs/PLUGINS.md) and [docs/mikrotik.md](docs/mikrotik.md). If `bgp.neighbors` is set, Packeteer keeps an iBGP session with the edge router(s) and learns which provider each prefix uses today. It announces nothing in `observe` or `suggest`.

`mode: inject` is opt-in. The `gobgp` announcer then advertises allowlisted improvements on that same iBGP session: the provider's next hop, your `local_pref`, `packeteer_community`, and `no-export`. The edge must accept only that community from Packeteer and must not export it to eBGP. See [docs/mikrotik.md](docs/mikrotik.md) and [docs/routers.md](docs/routers.md). Stopping the container, or switching back to `observe`, withdraws the routes. So does a withdraw of a prefix the router was still advertising. The router stopping sending the native path because Packeteer's route became best does not: that improvement stays until flip-back or `improvement_ttl`. Graceful restart is never enabled.

- Validate a config without probing: `docker run --rm -v "$PWD/config.yaml:/etc/packeteer/config.yaml:ro" ghcr.io/grandarcher/packeteer:edge -check`
- Each provider's `source_ip` must leave through that transit. See [docs/policy-routing.md](docs/policy-routing.md) for the Linux `ip rule` recipe and the MikroTik equivalent.
- Set `PACKETEER_LOG_LEVEL=debug` for more detail.

The CI lab (`lab/e2e.sh`, GitHub Actions job `e2e`) peers this image with FRR and checks that an injected route appears, is withdrawn when FRR drops a native route it was still advertising, stays up when FRR hides that route because Packeteer's path won, and is withdrawn when Packeteer stops. See [lab/README.md](lab/README.md).

### Security notes

The process runs as root inside the container because raw ICMP sockets and BGP port 179 need `CAP_NET_RAW` / `CAP_NET_BIND_SERVICE`. It gets only Docker's default capabilities plus the ones you add. The image contains no secrets and only the documentation-prefix example config.

### Build from source

```sh
go build -o packeteer ./cmd/controller
./packeteer -check -config config.example.yaml
docker build -t packeteer .
```

## Roadmap

Feature parity with Noction IRP is the top priority. See [docs/IRP_PARITY.md](docs/IRP_PARITY.md) for the capability matrix and the milestones (v0.1 through v0.4).

## Safety

- Default mode is `observe`
- Inject only when `mode: inject` and the prefix is allowlisted
- Never announce a prefix that was not learned from the local RIB
- Cap active improvements
- Hold time + thresholds before a flip
- Tag every injected route with a dedicated community
- No production RIBs, SNMP communities, or customer prefixes in this public repo

Read [docs/THREAT_MODEL.md](docs/THREAT_MODEL.md) and [AGENTS.md](AGENTS.md) before writing code that talks BGP.

## Layout

```
cmd/controller/     # entrypoint
internal/probe/     # per-provider sourced measurements
internal/policy/    # score + hysteresis
internal/announce/  # inject-mode gate in front of the announcer plugin
internal/rib/       # learn-only iBGP view (embedded GoBGP)
internal/plugins/   # probers, target sources (static, flow), scorer, announcer
lab/                # FRR e2e lab (CI job e2e)
```

Router filters: [docs/mikrotik.md](docs/mikrotik.md), [docs/routers.md](docs/routers.md).

## Support the project

Packeteer is free and open source. If it helps your network, you can chip in to cover development and lab costs through [PayPal](https://paypal.me/GrandArcher) or the **Sponsor** button at the top of this page. Thank you!

## License

Apache-2.0. See [LICENSE](LICENSE).
