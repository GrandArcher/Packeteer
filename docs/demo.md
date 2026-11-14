# Demo script: observe on a simulated edge

A short script to follow on screen, about five minutes. It starts the one-command lab ([lab/README.md](../lab/README.md#one-command-demo-586)), shows what Packeteer recommends in `observe`, shows that the edge router has accepted nothing from Packeteer, previews what inject would do without making any change, and stops the lab. For the long version that goes on to suggest and inject, read [walkthrough.md](walkthrough.md). For a host install, read [quickstart.md](quickstart.md).

Nothing here touches a real network. The routers are containers on a Docker bridge, the addresses are documentation ranges (RFC 5737), and the ASNs are the private-use 64512 and the documentation values 64496 and 64497. The mode stays `observe` from start to stop. Every command block after the clone runs in CI, in order, in the `e2e` job (`lab/e2e-docs.sh docs/demo.md`).

You need Linux with Docker Engine, the Compose plugin, `git`, `curl`, and nothing else on `127.0.0.1:18080` or the `192.0.2.0/24` bridge (stop the walkthrough lab first).

| Lab | Address | AS | Role |
|---|---|---|---|
| `edge` | 192.0.2.254 | 64512 | FRR edge router |
| `transit-a` | 192.0.2.21 | 64496 | sends `198.51.100.0/24`; the edge's native exit |
| `transit-b` | 192.0.2.22 | 64497 | sends the same prefix, prepended, so it is not best |
| `packeteer` | 192.0.2.10 | 64512 | iBGP to the edge; dashboard on <http://127.0.0.1:18080/> |

The lab has no real transits to measure, so Packeteer uses the `fixed` prober: transit-a answers in 60 ms and transit-b in 20 ms. No probe packet leaves the bridge.

## 1. Start the lab (1 minute)

Say: one command starts a router, two transits, and Packeteer, in observe.

```sh
git clone https://github.com/GrandArcher/Packeteer.git
cd Packeteer
```
<!-- ci-skip: CI runs the guide from its own checkout -->

Pick a password for this run. The script uses it for the `admin` account and never prints it. Generate one rather than typing one on camera:

```sh
PACKETEER_DEMO_PASSWORD=$(head -c 18 /dev/urandom | od -An -tx1 | tr -d ' \n')
export PACKETEER_DEMO_PASSWORD
./scripts/demo.sh
```
<!-- ci-expect: Packeteer demo is up (mode: observe; nothing is announced). -->
<!-- ci-expect: dashboard: http://127.0.0.1:18080/ -->

The calls below use this helper. It sends the password through standard input, so it is not on a command line or in the shell history:

```sh
api() { printf 'user = "admin:%s"\n' "$PACKETEER_DEMO_PASSWORD" | curl -fsS -K - "http://127.0.0.1:18080$1"; }
```

Wait for the edge's iBGP session to Packeteer, about 30 seconds:

```sh
docker exec pkd-edge vtysh -c 'show bgp neighbors 192.0.2.10'
```
<!-- ci-retry: 120 -->
<!-- ci-expect: BGP state = Established -->

## 2. Sign in and show Overview (1 minute)

Say: sign-in is on by default. Open <http://127.0.0.1:18080/>, sign in as `admin`, and paste the password from `printenv PACKETEER_DEMO_PASSWORD` (keep that terminal off screen). Overview shows the mode, observe. The same fact over the API:

```sh
api /api/overview
```
<!-- ci-expect: "mode":"observe" -->

Without credentials the API refuses:

```sh
curl -sS -o /dev/null -w '%{http_code}\n' http://127.0.0.1:18080/api/prefixes
```
<!-- ci-expect: 401 -->

## 3. Show a recommendation (1 minute)

Say: Packeteer learned `198.51.100.0/24` over iBGP. Today's exit is transit-a. It measured both providers, and transit-b is 40 ms faster, past the 15 ms threshold. On the dashboard this is the prefix card and the Improvements page.

```sh
api "/api/prefixes?limit=500"
```
<!-- ci-retry: 60 -->
<!-- ci-expect: "prefix":"198.51.100.0/24" -->
<!-- ci-expect: "in_rib":true -->
<!-- ci-expect: "rib_provider":"transit-a" -->
<!-- ci-expect: "recommended":"transit-b" -->

```sh
api /api/improvements
```
<!-- ci-retry: 30 -->
<!-- ci-expect: "provider":"transit-b" -->

Say: it is a recommendation and nothing more. The edge has no route from Packeteer, and the prefix still goes out transit-a, with no Packeteer community on it:

```sh
docker exec pkd-edge vtysh -c 'show bgp ipv4 unicast neighbors 192.0.2.10 routes'
```
<!-- ci-absent: 198.51.100.0/24 -->

```sh
docker exec pkd-edge vtysh -c 'show bgp ipv4 unicast 198.51.100.0/24'
```
<!-- ci-expect: 192.0.2.21 from 192.0.2.21 -->
<!-- ci-absent: 64512:666 -->

## 4. Preview what inject would do (1 minute)

Say: before anyone turns inject on, the blast-radius preview shows what it would do. On the dashboard it is Settings, Blast radius. `GET /api/blast` decides the latest round again on a copy, as if the mode were inject, and compares that with what is on the wire ([onboarding.md](onboarding.md#blast-radius-preview)). The running mode does not change and nothing is announced. This lab has no allowlist, so inject would add no route, and the report warns about it:

```sh
api /api/blast
```
<!-- ci-retry: 60 -->
<!-- ci-expect: "add":[] -->
<!-- ci-expect: "code":"no_allowlist" -->
<!-- ci-expect: the allowlist is empty, so inject announces nothing -->

Overview still says observe:

```sh
api /api/overview
```
<!-- ci-expect: "mode":"observe" -->

The preflight checks that gate inject are on the same Settings page, and the API says they are available:

```sh
api /api/preflight
```
<!-- ci-expect: "available":true -->

Say: turning inject on is a config change that Packeteer refuses until those checks pass, and it needs an allowlist. This demo never does either; the walkthrough does, in the lab.

## 5. Stop the lab (under 1 minute)

```sh
./scripts/demo.sh stop
```

```sh
docker ps -a --filter name=pkd- --format '{{.Names}}'
```
<!-- ci-absent: pkd- -->

Every container and the lab network are gone. Nothing was ever announced, so there is nothing to withdraw.

## Where next

- Host install, observe only: [quickstart.md](quickstart.md).
- Observe, suggest, inject, and the rollback, on a simulated network: [walkthrough.md](walkthrough.md).
- What the lab contains: [lab/README.md](../lab/README.md#one-command-demo-586).
