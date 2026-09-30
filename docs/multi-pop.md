# Multi-POP: routing domains, global commit, central view (#30)

Lab-proven only, not on a public edge. Default mode stays `observe`.

Run one Packeteer instance per POP (routing domain). A `federation` plugin connects them. Each instance keeps its own iBGP session, learned RIB, allowlist, and announcer. Nothing is announced across POPs: federation only adds decision inputs, and every route an instance announces goes through its own safety rules.

## What it does

- **Inter-DC RTT in the path cost (IRP routing domains).** A provider can belong to another POP (`providers[].domain`). This instance does not probe it: the peer in that POP measures it. Its path to a prefix is the peer's measurement plus `inter_dc_rtt` for that domain. When that total beats the local exits by the usual thresholds, this POP steers the prefix to its own edge with that provider's `next_hop`, the address this POP's routers use to reach the other POP's exit across the backbone.
- **Global commit (IRP Globalcc).** `global_commit` shares one commit across providers in several POPs, usually one carrier in each POP. With the `commit` scorer, each local member's commit becomes the global commit minus every other member's fresh usage, and never more than its own commit. Commit control then moves traffic off that member as usual.
- **Central view (IRP GMI).** `/api/federation` and the dashboard's POPs section list this instance and every peer. Each row shows mode, freshness, last error, providers up, improvements against the cap, inter-DC RTT, and the global commit totals with each member's usage. An instance with `listen` empty only polls, so it can serve the central view without anyone reading its data.

## Safety

A provider in another domain is usable for a prefix only while all of these hold:

1. the peer is fresh (a good snapshot within the plugin's `max_age`);
2. the peer's RIB is ready and it reports that provider up;
3. the peer's own traffic for that exact prefix leaves through that provider. Traffic this POP sends there then exits there and cannot come back. If two POPs steer the same prefix at each other in one interval, the POP whose domain sorts first keeps its steer and the other retires its own.

The steer is still an ordinary improvement:

- the prefix must be in this POP's learned RIB. A prefix only the other POP learned is never announced;
- the prefix must be in the allowlist;
- the route carries `packeteer_community` and NO_EXPORT;
- it counts toward `max_improvements`;
- it obeys `hold_time` and the thresholds.

If any condition fails, the provider becomes unusable and the improvement is retired and withdrawn. This happens when the peer goes stale, crashes, loses its RIB, or loses the provider. On shutdown an instance publishes its providers down before it withdraws its own routes, so peers retire their steers at the next poll. A crash is caught by `max_age`.

The global commit applies only when every member's usage is known and every peer involved is fresh. Otherwise each provider's own commit applies, as if the instance ran standalone.

Snapshot times are converted by age, so clock skew between POPs cannot make stale data look fresh. The federation plugin is in-process only and never announces. An out-of-process plugin cannot feed decisions.

## Config

The full reference is in [CONFIG.md](CONFIG.md#multi-pop-federation).

```yaml
instance: pop-a            # defaults to domain
domain: pop-a
inter_dc_rtt:
  pop-b: 12ms
providers:
  - name: x-a
    source_ip: 192.0.2.11
    next_hop: 192.0.2.1
  - name: x-b              # carrier X in POP B
    domain: pop-b
    next_hop: 192.0.2.253  # POP B's exit, reached across the backbone
    cc_disable: true       # moving carrier X to carrier X does not relieve the shared commit
global_commit:
  - name: carrier-x
    commit_mbps: 1000
    providers: [x-a, x-b]
federation:
  type: mtls
  config:
    listen: 0.0.0.0:9443
    cert_file: /etc/packeteer/certs/pop-a.crt
    key_file: /etc/packeteer/certs/pop-a.key
    ca_file: /etc/packeteer/certs/ca.crt
    peers:
      - name: pop-b
        url: https://192.0.2.20:9443
```

Each POP lists the other POPs' providers it may use, and gives each one a `next_hop` that its own edge routers can reach. Provider names must be the same in every POP.

## Docker

This uses the stock image. Mount the certificates next to the config:

```sh
docker run --network host --cap-add NET_RAW --cap-add NET_ADMIN \
  -v "$PWD/config.yaml:/etc/packeteer/config.yaml" \
  -v "$PWD/certs:/etc/packeteer/certs:ro" \
  ghcr.io/grandarcher/packeteer
```

Issue every instance's certificate from one CA, with the instance name as CN or DNS SAN. Keep keys out of git. Open `listen` only to the other POPs.

## Lab

`lab/e2e-multipop.sh` runs two POPs, each with an FRR edge and a Packeteer instance. The certificates are generated for that run only, and the prefixes are documentation ranges. The lab proves:

- the central view;
- a steer through the other POP's carrier because of the inter-DC RTT, with next hop, local-pref, community, and NO_EXPORT;
- withdraw on peer loss, then the re-steer;
- a commit move driven by the other POP's usage, and its release;
- a prefix only the other POP learned is never announced;
- the other instance never steers back;
- SIGTERM and SIGKILL.

## Rollback

Remove `federation`, `global_commit`, and the providers with another `domain`, then restart. Each instance runs standalone. SIGHUP refuses these keys, so they need a restart.
