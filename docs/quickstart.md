# Quickstart: one container, observe mode

This page takes a Linux host with Docker from nothing to a running Packeteer in `observe` mode. Observe measures and reports. It never announces a route. Nothing on this page opens a BGP session.

Every command block on this page runs in CI, in order, against the image built from the same commit (the `docker` job in [.github/workflows/ci.yml](../.github/workflows/ci.yml), through `lab/e2e-docs.sh`). CI substitutes two things only: the image tag points at the image it just built, and the `raw.githubusercontent.com` downloads read the same files from the checkout.

You need:

- Linux with Docker Engine and the Compose plugin (`docker compose`). Packeteer uses host networking, which Docker Desktop on macOS and Windows does not give you.
- `curl`.
- Nothing else on the host listening on `127.0.0.1:8080`.

Addresses on this page are documentation ranges (RFC 5737) and loopback. The ASN is the private-use 64512.

## 1. Get the example config and check it

```sh
mkdir -p packeteer && cd packeteer
curl -fsSLo config.yaml https://raw.githubusercontent.com/GrandArcher/Packeteer/main/config.example.yaml
IMAGE=ghcr.io/grandarcher/packeteer:edge
docker run --rm -v "$PWD/config.yaml:/etc/packeteer/config.yaml:ro" "$IMAGE" -check
```
<!-- ci-expect: mode: observe -->
<!-- ci-expect: announce: disabled -->
<!-- ci-expect: check: ok -->

`-check` loads the file, validates every plugin block, prints a summary, and exits. It ends with `check: ok (no probes sent, no BGP sessions opened)`. `:edge` is the build from `main`; to pin a release use `IMAGE=ghcr.io/grandarcher/packeteer:0.4.0` (see the tags in the [README](../README.md#install)).

## 2. A first run on loopback

Before you touch policy routing, run a config that probes the host itself. It shows the container, the capabilities, the prober, and the dashboard working.

```sh
cat > hello.yaml <<'YAML'
mode: observe
asn: 64512
router_id: 192.0.2.10
providers:
  - name: loopback
    source_ip: 127.0.0.1
    next_hop: 127.0.0.1
probe: {interval: 5s, timeout: 1s, packets: 3}
sources:
  - type: static
    config:
      targets: [{prefix: 127.0.0.1/32}]
YAML
docker run -d --name packeteer --network host \
  --cap-add NET_RAW --cap-add NET_ADMIN \
  -v "$PWD/hello.yaml:/etc/packeteer/config.yaml:ro" \
  "$IMAGE"
```

Wait for the first probe round (one interval, 5 seconds here), then read the API:

```sh
curl -fsS http://127.0.0.1:8080/readyz
curl -fsS http://127.0.0.1:8080/api/probes
```
<!-- ci-retry: 60 -->
<!-- ci-expect: "provider":"loopback" -->
<!-- ci-expect: "ok":true -->

`/api/probes` lists one result for provider `loopback` with `"ok":true` and `loss_pct` 0. The same numbers are on the dashboard at <http://127.0.0.1:8080/> and in the log:

```sh
docker logs packeteer 2>&1 | grep 'msg=probe '
curl -fsS http://127.0.0.1:8080/metrics | grep '^packeteer_probe_rtt_seconds'
```
<!-- ci-expect: prober=icmp -->
<!-- ci-expect: loss_pct=0 -->
<!-- ci-expect: provider="loopback" -->

Stop it. `-t 30` gives Packeteer time to shut down cleanly; that matters once it has a BGP session.

```sh
docker stop -t 30 packeteer
docker rm packeteer
```

## 3. Describe your network

Edit `config.yaml`. Leave `mode: observe`. The keys you change first:

```yaml
asn: 64512                  # your ASN (the router's, for the iBGP session later)
router_id: 192.0.2.10       # an address of this host
providers:
  - name: transit-a
    source_ip: 192.0.2.11   # an address on this host that leaves through transit A
    next_hop: 192.0.2.1     # transit A's gateway, as the router sees it
  - name: transit-b
    source_ip: 198.51.100.11
    next_hop: 198.51.100.1
sources:
  - type: static
    config:
      targets:
        - {prefix: 198.51.100.0/24, host: 198.51.100.1}
```

- Each `source_ip` has to exist on the host, and the host has to route packets from it out of that provider: [policy-routing.md](policy-routing.md). A provider whose source address is missing is marked down and left out; it is never probed from another address.
- `sources` says what to measure. Start with a few destinations you care about in a `static` list. A `flow` source adds the busiest destinations from NetFlow, IPFIX, or sFlow ([PLUGINS.md](PLUGINS.md)).
- `bgp.neighbors` comes later, when you peer with the router ([walkthrough.md](walkthrough.md), router guides below). Without it Packeteer ranks providers but cannot know today's exit, so it recommends nothing.

Every key is in [CONFIG.md](CONFIG.md). The example file comments each one.

## 4. Run it

```sh
mkdir -p plugins
docker run --rm -v "$PWD/config.yaml:/etc/packeteer/config.yaml:ro" "$IMAGE" -check
docker run -d --name packeteer --network host \
  --cap-add NET_RAW --cap-add NET_ADMIN \
  --restart unless-stopped \
  -v "$PWD/config.yaml:/etc/packeteer/config.yaml:ro" \
  -v "$PWD/plugins:/etc/packeteer/plugins:ro" \
  -v packeteer-data:/var/lib/packeteer \
  "$IMAGE"
```
<!-- ci-expect: mode: observe -->
<!-- ci-expect: check: ok -->

- `--network host`: probes leave from each provider's `source_ip`, the iBGP session reaches the router, and a flow collector binds host UDP ports.
- `NET_RAW` opens ICMP sockets. `NET_ADMIN` binds probe sockets to their source.
- `plugins` holds `exec` plugins, if you write any ([PLUGINS.md](PLUGINS.md)). It can stay empty.
- The `packeteer-data` volume keeps report history (`storage: sqlite` in the example) across restarts and upgrades.

Check that it is up and in observe:

```sh
curl -fsS http://127.0.0.1:8080/healthz
curl -fsS http://127.0.0.1:8080/api/overview
```
<!-- ci-retry: 60 -->
<!-- ci-expect: "status":"ok" -->
<!-- ci-expect: "mode":"observe" -->

`/api/overview` carries the dashboard's setup checklist (`setup`): what to add next and what looks broken. The dashboard at <http://127.0.0.1:8080/> shows the same list until the instance is fully set up. `/readyz` returns 503 until startup finishes and, once `bgp.neighbors` is set, until an iBGP session is up.

```sh
docker logs packeteer 2>&1 | grep 'packeteer running'
```
<!-- ci-expect: mode=observe -->
<!-- ci-expect: announce=disabled -->

## 5. Or run it with Compose

The same container as a Compose service. Use one or the other, not both: they share the container name `packeteer`.

```sh
docker stop -t 30 packeteer && docker rm packeteer
curl -fsSLo docker-compose.yml https://raw.githubusercontent.com/GrandArcher/Packeteer/main/docker-compose.yml
docker compose up -d
docker compose ps
```
<!-- ci-expect: packeteer -->

```sh
curl -fsS http://127.0.0.1:8080/api/overview
docker compose logs packeteer
```
<!-- ci-retry: 60 -->
<!-- ci-expect: "mode":"observe" -->
<!-- ci-expect: packeteer running -->

The Compose file pins the same flags: host networking, the two capabilities, the config and plugin mounts, a data volume, and `restart: unless-stopped`. Its `image` line uses `:edge`; change it to a release tag to pin.

## 6. Stop

```sh
docker compose stop -t 30
docker compose down
```

With `docker run`, the same is `docker stop -t 30 packeteer`. A stop with a 30-second timeout is also the rollback once inject is on: Packeteer withdraws its routes before it exits. `docker kill` does not; see [Rollback](../README.md#rollback).

## Next

- Peer with the router and go from observe to suggest to inject, in the lab first: [walkthrough.md](walkthrough.md).
- Router guides: [MikroTik RouterOS 7](mikrotik.md), [FRR](frr.md), [Juniper Junos](junos.md), [Cisco IOS / IOS-XE](cisco.md), and the shared rules in [routers.md](routers.md).
- Something does not work: [troubleshooting.md](troubleshooting.md).
