# Walkthrough: observe, suggest, inject, and roll back

This guide takes one prefix through every mode on a simulated network: an FRR edge router, two simulated transits, and Packeteer. You see what each mode shows, what the router sees, and how a stop withdraws. Then it lists what changes on a real edge.

Run it in the lab first. Nothing here touches a real network: the routers are containers on a Docker bridge, the addresses are documentation ranges (RFC 5737), and the ASNs are documentation and private-use values. Every command block below runs in CI, in order, in the `e2e` job (`lab/e2e-docs.sh docs/walkthrough.md`).

| Lab | Address | AS | Role |
|---|---|---|---|
| `edge` | 192.0.2.254 | 64512 | FRR, configured exactly as [frr.md](frr.md) |
| `transit-a` | 192.0.2.21 | 64496 | sends `198.51.100.0/24`; the edge's native exit |
| `transit-b` | 192.0.2.22 | 64497 | sends `198.51.100.0/24` prepended, so it is not best |
| `packeteer` | 192.0.2.10 | 64512 | iBGP to the edge; dashboard on <http://127.0.0.1:18090/> |

The lab has no real transits to measure, so Packeteer uses the `fixed` prober: transit-a answers in 60 ms and transit-b in 20 ms. A real edge uses `icmp` and `tcp` ([quickstart.md](quickstart.md)).

You need Linux with Docker Engine, the Compose plugin, `git`, and `curl`.

## 1. Start the lab in observe

```sh
git clone https://github.com/GrandArcher/Packeteer.git
cd Packeteer
```
<!-- ci-skip: CI runs the guide from its own checkout -->

Packeteer reads `lab/walkthrough/config.yaml`, a copy you edit as you go. It starts as [lab/packeteer-walkthrough.yaml](../lab/packeteer-walkthrough.yaml): `mode: observe`, two providers whose `next_hop` is each transit's address, one iBGP neighbor (the edge), one static target, and thresholds of 1% loss and 15 ms.

```sh
mkdir -p lab/walkthrough
cp lab/packeteer-walkthrough.yaml lab/walkthrough/config.yaml
docker compose -f lab/docker-compose-walkthrough.yml up -d --build
```

The edge peers with both transits and with Packeteer. Wait for the Packeteer session:

```sh
docker exec pkw-edge vtysh -c 'show bgp neighbors 192.0.2.10'
```
<!-- ci-retry: 120 -->
<!-- ci-expect: BGP state = Established -->

The edge's best path for `198.51.100.0/24` is transit-a (`192.0.2.21`, AS path `64496`):

```sh
docker exec pkw-edge vtysh -c 'show bgp ipv4 unicast 198.51.100.0/24'
```
<!-- ci-retry: 60 -->
<!-- ci-expect: 192.0.2.21 from 192.0.2.21 -->
<!-- ci-absent: 64512:666 -->

## 2. What observe shows

Packeteer learned the prefix over iBGP, matched its next hop to `transit-a`, and measured both providers:

```sh
curl -fsS http://127.0.0.1:18090/api/prefixes
```
<!-- ci-retry: 60 -->
<!-- ci-expect: "prefix":"198.51.100.0/24" -->
<!-- ci-expect: "in_rib":true -->
<!-- ci-expect: "rib_provider":"transit-a" -->
<!-- ci-expect: "recommended":"transit-b" -->

`rib_provider` is today's exit. `recommended` is the provider Packeteer would pick: transit-b is 40 ms faster, past the 15 ms threshold. The same recommendation is on the dashboard and in `/api/improvements`. In observe it is only a recommendation:

```sh
curl -fsS http://127.0.0.1:18090/api/improvements
curl -fsS http://127.0.0.1:18090/api/overview
```
<!-- ci-retry: 30 -->
<!-- ci-expect: "provider":"transit-b" -->
<!-- ci-expect: "mode":"observe" -->

Nothing is announced: the edge still has only the transit paths, and Packeteer advertises nothing to it.

```sh
docker exec pkw-edge vtysh -c 'show bgp ipv4 unicast neighbors 192.0.2.10 routes'
```
<!-- ci-absent: 198.51.100.0/24 -->

An improvement appears only when the prefix is in the learned RIB, both the native provider and the candidate have fresh measurements, the gain clears both thresholds, the provider is not excluded, and `max_improvements` has room. With the thresholds at 0 nothing is recommended.

## 3. Suggest

`suggest` runs the same probe and decision loop as observe and announces nothing. Switch to it when you start reviewing recommendations as candidate changes: the mode is in the log, on the dashboard banner, and in every event a notifier sends. Packeteer reads its config at startup, so restart after the edit. `-t 30` matters later, when a stop has routes to withdraw.

```sh
sed 's/^mode: observe$/mode: suggest/' lab/walkthrough/config.yaml > lab/walkthrough/config.new
mv lab/walkthrough/config.new lab/walkthrough/config.yaml
docker restart -t 30 pkw-packeteer
```

```sh
curl -fsS http://127.0.0.1:18090/api/overview
docker logs pkw-packeteer 2>&1 | grep 'improvement improve'
```
<!-- ci-retry: 60 -->
<!-- ci-expect: "mode":"suggest" -->
<!-- ci-expect: mode=suggest prefix=198.51.100.0/24 provider=transit-b -->

The log line is the recommendation: prefix, the provider it would move to, the native provider, and the reason. Still nothing on the edge:

```sh
docker exec pkw-edge vtysh -c 'show bgp ipv4 unicast 198.51.100.0/24'
```
<!-- ci-expect: 192.0.2.21 from 192.0.2.21 -->
<!-- ci-absent: 64512:666 -->

Stay in observe or suggest until the recommendations match what you know about your transits. On a real edge that is days, not minutes.

## 4. Inject

Before inject, the router needs the two filters from the router guide. The lab edge already has them ([frr.md](frr.md)):

- `packeteer-in` on the Packeteer session accepts only routes that carry `64512:666`.
- `ebgp-out` on both transit sessions rejects any route that carries `64512:666`, ahead of the normal export policy.

Inject needs all of these in the config, or Packeteer refuses to start: `mode: inject`, a non-empty `allowlist`, `packeteer_community`, `local_pref`, a positive `hold_time` (1 minute in this lab), both thresholds above 0, an iBGP neighbor, and `announcer.type: gobgp`. Add the missing keys and check the file with the same image before you restart:

```sh
sed 's/^mode: suggest$/mode: inject/' lab/walkthrough/config.yaml > lab/walkthrough/config.new
cat >> lab/walkthrough/config.new <<'YAML'
packeteer_community: "64512:666"
local_pref: 250
max_improvements: 5
allowlist:
  prefixes:
    - 198.51.100.0/24
announcer:
  type: gobgp
YAML
mv lab/walkthrough/config.new lab/walkthrough/config.yaml
docker run --rm -v "$PWD/lab/walkthrough/config.yaml:/etc/packeteer/config.yaml:ro" packeteer:walkthrough -check
```
<!-- ci-expect: mode: inject -->
<!-- ci-expect: announce: gobgp local_pref=250 -->
<!-- ci-expect: check: ok -->

```sh
docker restart -t 30 pkw-packeteer
```

Packeteer announces the exact prefix it learned, with transit-b's address as the next hop, local preference 250, the community, and `no-export`. It is now the edge's best path:

```sh
docker exec pkw-edge vtysh -c 'show bgp ipv4 unicast 198.51.100.0/24'
```
<!-- ci-retry: 90 -->
<!-- ci-expect: 192.0.2.22 from 192.0.2.10 -->
<!-- ci-expect: localpref 250 -->
<!-- ci-expect: Community: 64512:666 no-export -->

The log names the route it put on the wire:

```sh
docker logs pkw-packeteer 2>&1 | grep 'msg=injected'
```
<!-- ci-expect: prefix=198.51.100.0/24 provider=transit-b next_hop=192.0.2.22 local_pref=250 -->

The route does not leave the AS. Toward both transits the edge still advertises only its own prefix:

```sh
docker exec pkw-edge vtysh -c 'show bgp ipv4 unicast neighbors 192.0.2.21 advertised-routes'
docker exec pkw-edge vtysh -c 'show bgp ipv4 unicast neighbors 192.0.2.22 advertised-routes'
```
<!-- ci-expect: 203.0.113.0/24 -->
<!-- ci-absent: 198.51.100.0/24 -->

Once Packeteer's route is best, the edge stops advertising the transit-a path back to Packeteer (iBGP sends only the best path, and never back to the neighbor it came from). Packeteer keeps the improvement; that hide is not a withdraw. See [routers.md](routers.md#when-the-native-path-disappears) for add-path, BMP, and `advertise-best-external`, which keep the native path visible.

## 5. Roll back

Stopping the container withdraws every Packeteer route before the session closes:

```sh
docker stop -t 30 pkw-packeteer
docker exec pkw-edge vtysh -c 'show bgp ipv4 unicast 198.51.100.0/24'
```
<!-- ci-retry: 60 -->
<!-- ci-expect: 192.0.2.21 from 192.0.2.21 -->
<!-- ci-absent: 64512:666 -->

```sh
docker logs pkw-packeteer 2>&1 | grep -E 'withdrew all|shutting down'
```
<!-- ci-expect: withdrew all -->
<!-- ci-expect: shutting down -->

The edge is back on transit-a. Without the 30 seconds, Docker's default 10-second timeout can SIGKILL the process while the withdraw is in flight; the route then stays until the edge's hold timer (30 seconds in [frr.md](frr.md)) drops the session. Graceful restart is off on that session, so nothing keeps the route after that.

Going back to observe is the other rollback. Edit the mode and start again; the new process announces nothing:

```sh
sed 's/^mode: inject$/mode: observe/' lab/walkthrough/config.yaml > lab/walkthrough/config.new
mv lab/walkthrough/config.new lab/walkthrough/config.yaml
docker start pkw-packeteer
```

```sh
curl -fsS http://127.0.0.1:18090/api/overview
docker exec pkw-edge vtysh -c 'show bgp ipv4 unicast 198.51.100.0/24'
```
<!-- ci-retry: 60 -->
<!-- ci-expect: "mode":"observe" -->
<!-- ci-expect: 192.0.2.21 from 192.0.2.21 -->
<!-- ci-absent: 64512:666 -->

Clean up:

```sh
docker compose -f lab/docker-compose-walkthrough.yml down -v
rm -rf lab/walkthrough
```

## On a real edge

The steps are the same. What changes:

1. **Observe first, for days.** Install with [quickstart.md](quickstart.md). Set up probe sources with [policy-routing.md](policy-routing.md) and check each provider's numbers against what you know.
2. **Peer with the router** (still observe): `bgp.neighbors` in the config, and the session from the router guide for [MikroTik](mikrotik.md), [FRR](frr.md), [Junos](junos.md), or [Cisco IOS / IOS-XE](cisco.md). `/readyz` turns 200 once the session is up, and `/api/prefixes` fills `rib_provider`.
3. **Install both filters** on the router before inject, and test them: the guide for your router shows how to check that a tagged route is accepted from Packeteer and never exported.
4. **Suggest**, with the thresholds you mean to run, until the recommendations are ones you would make by hand.
5. **Inject one prefix.** Allowlist one prefix you operate, keep `max_improvements` small, and set `hold_time` (15 minutes in the example config) so a route that goes up stays up long enough to judge it. Confirm the route on the router with your router guide's check command, and confirm it is absent toward every eBGP neighbor.
6. **Widen slowly.** Add prefixes to the allowlist and raise `max_improvements` once the first one behaves.
7. **Know the rollback** before you need it: `docker stop -t 30 packeteer`, or `mode: observe` and a restart. [README: Rollback](../README.md#rollback) lists every withdraw trigger.

When something does not match this page: [troubleshooting.md](troubleshooting.md).
