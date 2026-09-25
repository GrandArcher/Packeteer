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

Right now the controller validates the config, prints the effective mode and providers, and exits. It sends no probes and opens no BGP sessions yet.

### Security notes

The process runs as root inside the container because raw ICMP sockets and BGP port 179 need `CAP_NET_RAW` / `CAP_NET_BIND_SERVICE`. It gets only Docker's default capabilities plus the ones you add. The image contains no secrets and only the documentation-prefix example config.

### Build from source

```sh
go build -o packeteer ./cmd/controller
./packeteer -config config.example.yaml
docker build -t packeteer .
```

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
internal/announce/  # ExaBGP / GoBGP speaker
deploy/             # example ExaBGP + MikroTik notes
```

## License

Apache-2.0. See [LICENSE](LICENSE).
