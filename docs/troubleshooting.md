# Troubleshooting

Find the symptom, read the log line it names, apply the fix. Commands assume the container is called `packeteer` and the dashboard listens on the default `127.0.0.1:8080`.

The examples in [Startup errors](#startup-errors) and [Probes fail](#probes-fail) run in CI against the image built from the same commit (`lab/e2e-docs.sh docs/troubleshooting.md`), so the messages shown are the ones the image prints. They use documentation addresses (RFC 5737) and the private ASN 64512.

## First steps

```
docker ps -a --filter name=packeteer      # running, restarting, or exited?
docker logs --tail 100 packeteer          # the reason is usually here
docker run --rm -v "$PWD/config.yaml:/etc/packeteer/config.yaml:ro" ghcr.io/grandarcher/packeteer:edge -check
curl -fsS http://127.0.0.1:8080/api/overview   # mode, readiness, counts, and the setup checklist
```

More detail in the log: `-e PACKETEER_LOG_LEVEL=debug` on `docker run` (or `log.level: debug`). JSON logs: `-e PACKETEER_LOG_FORMAT=json`.

The dashboard's setup checklist (`setup` in `/api/overview`) names the most common gaps directly: no sources, no BGP neighbor, no history storage, a provider whose probes all fail, no iBGP session, and probed prefixes that are not in the learned RIB.

## Startup errors

The container exits at once, or keeps restarting under `--restart unless-stopped`. The log has `refusing to start` and the reason. `-check` prints the same reason without starting anything.

The examples below use the same image as the [quickstart](quickstart.md):

```sh
IMAGE=ghcr.io/grandarcher/packeteer:edge
```

**No config mounted.** The container looks for `/etc/packeteer/config.yaml` (or `PACKETEER_CONFIG`).

```sh
docker run --rm "$IMAGE" -check
```
<!-- ci-fails -->
<!-- ci-expect: refusing to start -->
<!-- ci-expect: no such file or directory -->

**The host file does not exist.** Docker creates a directory in its place when the source of a bind mount is missing, so the error is `is a directory`, and an empty directory is left behind on the host. Check the path and remove that directory.

```sh
docker run --rm -v "$PWD/missing.yaml:/etc/packeteer/config.yaml:ro" "$IMAGE" -check
```
<!-- ci-fails -->
<!-- ci-expect: is a directory -->

**A typo or an unknown key.** Every key is checked, inside plugin `config` blocks too. The message gives the line.

```sh
printf 'mode: observe\nasn: 64512\nrouter_id: 192.0.2.10\nprovidrs: []\n' > typo.yaml
docker run --rm -v "$PWD/typo.yaml:/etc/packeteer/config.yaml:ro" "$IMAGE" -check
```
<!-- ci-fails -->
<!-- ci-expect: line 4: field providrs not found -->

**Inject without its safety settings.** `mode: inject` fails closed and lists everything missing: the allowlist, a BGP neighbor, `local_pref`, the announcer, a positive `hold_time`, both thresholds, and `packeteer_community`.

```sh
printf 'mode: inject\nasn: 64512\nrouter_id: 192.0.2.10\npacketeer_community: "64512:666"\nhold_time: 15m\nthresholds: {min_loss_delta_pct: 1, min_rtt_delta_ms: 15}\nproviders: [{name: transit-a, source_ip: 192.0.2.11, next_hop: 192.0.2.1}]\n' > inject.yaml
docker run --rm -v "$PWD/inject.yaml:/etc/packeteer/config.yaml:ro" "$IMAGE" -check
```
<!-- ci-fails -->
<!-- ci-expect: mode inject requires a non-empty allowlist.prefixes -->
<!-- ci-expect: mode inject requires at least one bgp.neighbors entry -->
<!-- ci-expect: mode inject requires local_pref -->
<!-- ci-expect: mode inject requires an announcer -->

**Half of basic auth.** Set both `PACKETEER_HTTP_USER` and `PACKETEER_HTTP_PASSWORD`, or neither.

```sh
docker run --rm -e PACKETEER_HTTP_USER=ops \
  -e PACKETEER_CONFIG=/etc/packeteer/config.example.yaml "$IMAGE" -check
```
<!-- ci-fails -->
<!-- ci-expect: set both PACKETEER_HTTP_USER and PACKETEER_HTTP_PASSWORD, or neither -->

Other refusals name the key or the plugin at fault, for example an `exec` plugin that is missing from `/etc/packeteer/plugins`, or `more_specific_bits` (not a setting: Packeteer never invents a more-specific).

## The dashboard does not load

- **Connection refused.** `http.listen` defaults to `127.0.0.1:8080`: the host's loopback, because of `--network host`. Browse from the host itself, through an SSH tunnel (`ssh -L 8080:127.0.0.1:8080 host`), or set `http.listen` to an address on the host and set `PACKETEER_HTTP_USER` and `PACKETEER_HTTP_PASSWORD` (or `auth`) before you do. `PACKETEER_HTTP_LISTEN=off` turns it off; check the environment.
- **Docker Desktop (macOS, Windows).** Host networking there is the Docker VM's network, not your machine's. Packeteer needs a Linux host.
- **Port in use.** The log has `http server` with `address already in use`. Something else has 8080; set `http.listen` or `PACKETEER_HTTP_LISTEN` to another port.
- **401 or 403.** Basic auth or `auth` is on (`/api/me` says which), or `http.allow_from` does not include your address.
- **"Cannot reach the controller"** on the page: the browser lost the API. The page keeps the last data, marked stale, until it reconnects.

## Nothing to probe

The dashboard says "Nothing to probe yet" and the log has `no target sources configured; nothing to probe`. Add a `sources` entry: a `static` list to start, or a `flow` source ([quickstart.md](quickstart.md#3-describe-your-network)). Prefixes that are only in the learned RIB are not probed and not listed.

A `flow` source that stays empty: the exporter is not sending to the `listen` address and port, a host firewall drops the UDP, or every destination is private or excluded. With `--network host` the port is a host port; there is no `-p` mapping to add.

## Probes fail

A provider whose `source_ip` is not on the host is excluded, fail closed. Packeteer never probes it from another address. The log says why:

```sh
cat > nosource.yaml <<'YAML'
mode: observe
asn: 64512
router_id: 192.0.2.10
providers:
  - name: transit-a
    source_ip: 192.0.2.11
    next_hop: 192.0.2.1
probe: {interval: 2s, timeout: 500ms, packets: 2}
sources:
  - type: static
    config:
      targets: [{prefix: 198.51.100.0/24, host: 198.51.100.1}]
YAML
docker run -d --name pk-nosource --network host --cap-add NET_RAW --cap-add NET_ADMIN \
  -e PACKETEER_HTTP_LISTEN=off \
  -v "$PWD/nosource.yaml:/etc/packeteer/config.yaml:ro" "$IMAGE"
```

```sh
docker logs pk-nosource 2>&1 | grep 'probe'
```
<!-- ci-retry: 30 -->
<!-- ci-expect: msg="probe failed" provider=transit-a -->
<!-- ci-expect: probe source address unavailable -->
<!-- ci-expect: msg="probe source down; provider excluded (fail closed)" provider=transit-a -->

```sh
docker stop -t 30 pk-nosource
docker rm pk-nosource
```

| Log | Cause | Fix |
|---|---|---|
| `probe source address unavailable` | `source_ip` is not configured on the host | Add the address on the interface facing that provider ([policy-routing.md](policy-routing.md)), or correct `source_ip`. |
| `probe source down; provider excluded (fail closed)` | Every probe from that source failed | The same. The provider comes back on its own (`probe source recovered`). |
| Probe lines say `prober=tcp` where you expected ICMP | The host answered TCP, so later rounds start there until `probe.prober_recheck_rounds`, or ICMP cannot open its socket (no `NET_RAW`) and the chain fell back to TCP port 443 | Wait for the chain-head probe, or add `--cap-add NET_RAW` when ICMP cannot open a socket. |
| `probe ... loss_pct=100` on one provider only | That transit drops the probes, or replies come back on another interface and are dropped | Check the policy route with `ip route get <target> from <source_ip>`; set `rp_filter` to 2 (loose) on the probe interfaces. |
| Every provider has the same RTT to everything | Probes all leave by the default route | Policy routing is missing: [policy-routing.md](policy-routing.md). |
| `probe round timed out; keeping previous results` | A round took longer than about three intervals | Fewer targets, a longer `probe.interval`, or more `probe.workers`. Measurements older than that are stale, and stale data withdraws Packeteer's routes in inject. |

A probe with high loss that succeeds is a measurement, not an error.

## The BGP session does not come up

`/readyz` stays 503 and the dashboard checklist says there is no iBGP session. The log has `bgp session` lines with the state.

- **Same ASN.** The session is iBGP: `asn` in the config equals the router's ASN, and the router has Packeteer's address as an internal neighbor with that ASN.
- **Who connects.** By default Packeteer connects out to the router on TCP 179 (`bgp.listen_port: 0`). If the router is configured passive, nobody connects; remove `passive` on the router, or set `bgp.listen_port: 179` and `passive: true` on the neighbor so Packeteer waits. Listening on 179 needs root in the container (it runs as root) and a free port on the host.
- **Reachability.** From the host: `nc -vz 192.0.2.254 179`. A firewall between them, or a router ACL on 179, keeps the session in `Active`.
- **Source address.** The router sees the session from the host's address toward it. If the router expects another address, set `local_address` on the neighbor.
- **Filters do not stop the session.** They stop routes. A session that is up with nothing learned is a filter or an export problem on the router.

Router-side show commands are in each guide: [mikrotik.md](mikrotik.md), [frr.md](frr.md#checks), [junos.md](junos.md#checks), [cisco.md](cisco.md#checks).

## Prefixes are not in the RIB, or the current exit is empty

`/api/prefixes` shows `in_rib: false`, or `in_rib: true` with no `rib_provider`.

- `in_rib: false`: the router is not sending that prefix to Packeteer. Check what the router advertises to Packeteer (MikroTik `output.redistribute=bgp`; FRR, Junos, IOS send their best BGP paths by default). The probed prefix must match a learned route (the longest covering route counts for the current exit).
- No `rib_provider`: the learned next hop matches no provider's `next_hop`. The router may set `next-hop-self` toward Packeteer, or the provider `next_hop` is not the address the router uses. Compare `next_hop` in `/api/prefixes` with the config.
- The log's periodic `rib ready=true prefixes=N` shows how much Packeteer learned. `ready=false` means no session is established.

## Nothing is recommended

`/api/improvements` is empty while one provider is clearly better.

- Both `thresholds.min_loss_delta_pct` and `thresholds.min_rtt_delta_ms` are 0 (the minimum config omits them). Set them; the example config uses 1% and 15 ms.
- The gain is inside the thresholds. When `thresholds.min_rtt_delta_pct` is set, an RTT win also has to be that percent of the current path's RTT. A loss win does not use the percent.
- `thresholds.confirm_rounds` is greater than 1 and the streak is still short. `/api/decisions` says `confirming` with the count. The default is 1, which announces on the first fresh win. A stale round does not count. A round that cannot compare keeps the streak and does not ask for an early probe. Early probes wait a quarter of the probe interval.
- The prefix is not in the learned RIB, or its current exit is unknown (previous section).
- The native provider or the candidate has no fresh measurement, or the candidate's source is down.
- A policy excludes the provider (`rules`, `maintenance`, commit control), or `max_improvements` is full (`capped` in `/api/decisions`).

`/api/decisions` gives the action and the reason for every probed prefix, with each candidate's score and why it is or is not usable.

## Inject is on and the router shows no route

The log has `packeteer running ... mode=inject announce=gobgp`, but the router has no route with your community.

- **Not learned or not allowed.** Packeteer announces only a prefix it learned from the router, exactly as learned, and only inside `allowlist.prefixes`. A recommendation for a prefix outside the allowlist stays a recommendation.
- **Not yet.** An improvement needs a full probe round with fresh data on both providers. Look for `improvement improve` and then `injected` in the log.
- **Rejected by the router.** The import filter must match `packeteer_community` exactly. Quote it in YAML (`"64512:666"`). Check what the router received before policy (FRR `soft-reconfiguration inbound` and `received-routes`, Junos `show route receive-protocol bgp`, IOS `show ip bgp neighbors ... received-routes`).
- **Not best.** `local_pref` must be higher than the native path's. On FRR a `network` statement has weight 32768 and stays best whatever the local preference; that is a lab artifact, not an eBGP path.
- **Next hop unresolved.** The router must reach the provider `next_hop` (normally a connected transit address). An unresolvable next hop makes the route invalid.

## A route comes and goes

- **Flip-back.** When the native path is better again, the improvement is retired (`improvement retired` with the reason). `hold_time` keeps a new improvement up at least that long and is the cooldown after a flip-back.
- **Withdraw triggers.** Packeteer withdraws on stale measurements (`probe round timed out`), on a probe source that fails, when every iBGP session is down (`rib not ready; withdrawing announced routes`), and when the router withdraws a prefix it was still advertising. Each one is in the log.
- **The native path disappears once Packeteer's route is best.** That is normal on a best-path-only session; Packeteer keeps the improvement until flip-back or `improvement_ttl`. See [routers.md](routers.md#when-the-native-path-disappears).

## A route stays after Packeteer stopped

- `docker stop` without `-t 30` can SIGKILL the process during the withdraw after 10 seconds. Use `docker stop -t 30 packeteer` (Compose: `docker compose stop -t 30`).
- `docker kill`, an OOM kill, or a host crash do not withdraw. The route goes when the router's hold timer expires and the session drops. The router guides set it to 30 seconds.
- If the route stays after the session is down, the router kept it: graceful restart is on for that session. Turn it off ([routers.md](routers.md)). Packeteer never offers graceful restart.

## A Packeteer route reached a transit

Stop Packeteer first (`docker stop -t 30 packeteer`), then fix the router. The eBGP export filter that rejects `packeteer_community` is missing or below a permit, or the community was stripped before it. `no-export` should have stopped it too; check that nothing on the path removes communities. Re-check with the advertised-routes command for every eBGP neighbor in your router guide before you set `mode: inject` again.

## Reporting a problem

Open an issue with `-check` output, `-version`, the relevant log lines, and what the router shows. Replace real prefixes, addresses, ASNs, and community strings with documentation values (192.0.2.0/24, 198.51.100.0/24, 203.0.113.0/24, 2001:db8::/32, AS 64496–64511 or 64512–65534) before you paste. Never paste SNMP communities, passwords, or tokens.
