# RIPE Atlas measurements

Optional (#213). Packeteer measures from its own providers only. With the `atlas` block it can also ask RIPE Atlas probes elsewhere to ping or traceroute a prefix's test address, so you can see whether the destination really changed and not just the local path. It uses your own API key and your own credits.

Atlas results are display and evidence. They are shown on the prefix page beside the local measurements and their confidence level (#202), and they never reach `Decide`, a scorer, or the announcer. Nothing here announces or moves a route. `mode` stays `observe` by default and the allowlist, learned-RIB check, `max_improvements`, community, hold time, and withdraw rules are unchanged.

## Turn it on

1. Create an API key on atlas.ripe.net with permission to create measurements. Packeteer also reads your credit balance with it; if the System row reports a refused credit read (HTTP 403), give the key that permission too. Without it, measurements still work, but the balance check is skipped.
2. Pass it as an environment variable, never in the config file:
   `docker run ... -e PACKETEER_ATLAS_API_KEY ...` (or `environment:` in Compose).
3. Add the block to the config and restart:

```yaml
atlas:
  enabled: true
  source: {type: area, value: WW}
  probes: 3
  max_credits_per_day: 500
  max_measurements_per_hour: 4
```

Without the key, or with `enabled: false`, no request is made; the System page says the key is missing. The keys are in [CONFIG.md](CONFIG.md#atlas).

## What it measures

- **On demand.** On the prefix page an operator presses "Measure with ping" or "Measure with traceroute", or calls `POST /api/atlas/measure`. The target is always a test address Packeteer already measures for that prefix; a caller cannot name an address. Before any request goes to RIPE Atlas, a target that is private (RFC 1918, IPv6 ULA), shared (100.64.0.0/10), loopback, link-local, unspecified, multicast, or in 0.0.0.0/8 or 240.0.0.0/4 (which includes 255.255.255.255) is refused: the API answers 400 and no credits are booked. Documentation ranges such as 198.51.100.0/24 and 2001:db8::/32 are not refused, and other reserved ranges are not checked.
- **After a move.** With `atlas.after_move: true`, once `after_move_delay` after Packeteer puts a route on the wire or moves it to another provider (`mode: inject` only), one ping runs (a deliberate choice: traceroute costs ten times as much) toward the address Packeteer measured through the provider traffic moved to. A prefix the announcer did not inject is skipped, and so is anything in `observe` or `suggest`. A newer move for the same prefix replaces the queued one. The latest on-demand measurement before the move is your "before"; the after-move row is the "after". Providers can measure different hosts of a prefix, so compare rows only when their target is the same; every row shows its target.

Every measurement is one-off, from `probes` probes picked by `source` (an area, a country, or an AS), plus your own probe when it is connected. Ping sends 3 packets of 48 bytes; traceroute is ICMP, 3 packets of 40 bytes. A result keeps the probe id, whether the destination answered, packets, average RTT, and the hop count; no probe or hop address is kept. A measurement still missing results after 10 minutes is closed with what arrived.

## Credits and hard caps

Atlas charges per result, and one-off results cost double (Atlas credits documentation): `2 x packets x (size/1500 + 1)` for ping, ten times that for traceroute. With the defaults one ping result costs 6 credits and one traceroute result 60. Packeteer books that estimate for every measurement and refuses before any request when:

- the estimates booked in the last 24 hours plus this one exceed `max_credits_per_day` (default 500, about 27 pings of 3 probes or 2 traceroutes);
- `max_measurements_per_hour` measurements were already created in the last hour (default 4);
- the last read credit balance is below the estimate.

The ledger is written to `atlas.state_file` (default `/var/lib/packeteer/atlas.json`, mode 0600), so a restart does not reset the caps. With HA, each instance keeps its own ledger, so the caps apply per instance and the combined limit is the cap times the number of instances. A spend is booked before the request is sent and released only when Atlas refuses the request outright, so a lost answer still counts. Without a writable file the caps hold only until a restart, and the log says so. Mount a volume on `/var/lib/packeteer` to keep it. The estimate can differ from what Atlas bills; the System page shows the real balance.

## Your own probe

Set `atlas.probe_id` to the id of a probe you host. Packeteer then reads its status and the credit balance every 5 minutes with your key and shows them on the System page ("RIPE Atlas") with a link to the probe's page on atlas.ripe.net. While the probe is `Connected` it is added as one more source of every measurement, and its rows are marked own. A probe that is not connected makes the System row degraded and is left out.

### Hosting the probe next to Packeteer

RIPE NCC publishes the Atlas software probe as packages and source, not as a Docker image. `docker-compose.yml` has an optional service, off unless you ask for its profile, that runs the community image `jamesits/ripe-atlas`, tag `5130-probe` (the unmodified RIPE software probe packaged in a container; check the tag before you update it):

```sh
docker compose --profile atlas up -d atlas-probe
docker compose exec atlas-probe cat /etc/ripe-atlas/probe_key.pub
```

Register that public key at atlas.ripe.net/apply/swprobe/. Registration is manual on RIPE's side; the probe then appears in your account and you copy its id to `atlas.probe_id`. The key pair lives in the `atlas-probe-key` volume. Keep the volume when you recreate the container, or the probe needs a new registration.

The probe is isolated from Packeteer. It runs in its own container on the default network, mounts only its own volumes (not `config.yaml`, not `packeteer-data`), has all capabilities dropped except those the image needs (`NET_RAW`, `KILL`, `SETUID`, `SETGID`, `CHOWN`, `FOWNER`, `DAC_OVERRIDE`), and has no access to the BGP sessions. It has IPv4 only. Its limits are `mem_limit: 64m` (the upstream compose example's), `cpus: 0.5`, and `pids_limit: 64`, so the measurements it runs for other Atlas users do not compete with Packeteer's own probing.

## API and tests

`GET /api/atlas?prefix=<cidr>` and `POST /api/atlas/measure` are in [API.md](API.md). The measure call is audited. `internal/atlas` tests use a fake Atlas API and cover both caps, the ledger across a restart, the balance check, result parsing for ping and traceroute, the queue after a move, and that the key is never in a log line, an error, the status, the records, or the state file. The `ui-smoke` steps of the docker job check the prefix page against canned answers, so CI never calls Atlas.

Rollback: remove the `atlas` block (or unset `PACKETEER_ATLAS_API_KEY`) and restart; stop the probe with `docker compose --profile atlas stop atlas-probe`.
