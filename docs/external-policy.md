# External policy feed

Packeteer can publish the routes it would inject instead of announcing them (#232). Your own BGP daemon (BIRD, OpenBGPD, ExaBGP, or anything that reads a config file) applies them. Packeteer then never needs an announcing session: the embedded speaker only learns the RIB.

Lab-proven only (`lab/e2e-interop.sh bird2|bird3 external`), not on a public edge.

## What is in the feed

The feed is a toggle beside the embedded announcer, not a separate decision path. The outbound announce controller drives it the same way it drives the `gobgp` announcer, so every route in it went through the same `Decide` output and the same rails: `allowlist.prefixes`, `max_improvements`, the learned-RIB check (never a prefix the RIB view has not learned), the leak-watch hold, flap quarantine, and the withdraw on stale data, RIB session loss, HA standby, and shutdown. `external_policy` is refused together with a `synthesize` block, because a synthesized sub-range is not in the learned RIB. With an announcer configured, a route is listed only after the announcer accepted it, so both outputs carry the same routes.

The feed carries routes only in `mode: inject`. In observe and suggest it is empty. Inbound steers and mitigation rules are not in it.

Three deployments:

| `announcer` | `external_policy.enabled` | Result |
|---|---|---|
| set | `false` | Embedded inject only (unchanged). |
| unset | `true` | Feed only. The session to the edge learns and announces nothing. |
| set | `true` | Both, for example the feed for a second site's daemon while injecting locally. |

`mode: inject` needs a RIB view: `bgp.neighbors`, or with feed only a `rib_sources` BMP station and no iBGP session at all (#237, [BMP alone](CONFIG.md#bmp-alone)). Then the feed empties whenever the BMP feed drops.

## Config

```yaml
external_policy:
  enabled: true
  listen: 192.0.2.10:9443
  cert_file: /etc/packeteer/tls/feed.crt
  key_file: /etc/packeteer/tls/feed.key
  token_env: PACKETEER_POLICY_TOKEN   # default
  ttl: 90s                            # default and minimum: three probe intervals
```

Keys: [CONFIG.md](CONFIG.md#external_policy). The token is read from the environment variable `token_env` names and must be at least 16 characters; without it Packeteer refuses to start. Every request needs `Authorization: Bearer <token>`. The feed is served over TLS only and is read-only. After a wrong token an address (an IPv6 /64) gets `429` with `Retry-After` for 1 s, doubling with each wrong token in a row up to 1 min; its token is not compared until then, and a right token clears it. The listener holds at most 128 connections and closes idle ones after 1 min. A long poll and the stream have no read or write timeout.

`enabled` and `ttl` reload online (SIGHUP or the config editor). Turning the feed off publishes an empty set that is already expired, so consumers drop every route at once. `listen`, `cert_file`, `key_file`, `token_env`, and adding or removing the block need a restart.

## The document

`GET /v1/recommendations` returns:

```json
{
  "revision": 7,
  "generated_at": "2026-11-01T12:00:00Z",
  "expires_at": "2026-11-01T12:01:30Z",
  "expires_in_ms": 88000,
  "heartbeat_ms": 30000,
  "routes": [
    {"prefix": "198.51.100.0/24", "provider": "transit-b", "next_hop": "192.0.2.22",
     "local_pref": 250, "communities": ["64512:666", "65535:65281"],
     "cause": "performance", "reason": "rtt 80ms -> 10ms"}
  ]
}
```

- `routes`: what the embedded announcer would send: the provider's next hop, the resolved local preference, `packeteer_community`, the cause's and the provider's extra communities, and NO_EXPORT (`65535:65281`). `as_path` is present when `bgp.as_path` sets one. A learned more-specific (`more_specific`) carries its covering improvement's cause and reason.
- `revision` changes whenever `routes` changes. It starts again when Packeteer restarts, so compare it for equality.
- `expires_in_ms` is the time left when the document was sent. Every decision round (at least once per probe interval) renews it to `ttl`. Add it to your own clock; clock skew between the hosts does not matter. When it is `0`, drop every route now: the feed is off, Packeteer is stopping, or no round has renewed the feed within `ttl`.
- `heartbeat_ms` is a third of `ttl`.

`GET /v1/recommendations?wait=<revision>` is a long poll: it answers as soon as the revision is not `<revision>`, or after `heartbeat_ms` with the renewed expiry. Poll again at once after each answer.

Apply a change within a few seconds. When your daemon is also the edge Packeteer learns from, applying the route makes the edge stop sending the native path to Packeteer. Packeteer reads that as its own route winning only if the path goes within 5 s of a round that still saw it (`policy.NativePathConfirm`); later, it reads it as the prefix leaving the RIB and retires the improvement. The long poll and the stream deliver a change at once; a plain poll every `heartbeat_ms` is too slow.

The gRPC stream is on the same port: service `packeteer.policy.v1.Recommendations`, server-streaming method `Watch`, request `google.protobuf.Empty`, each message a `google.protobuf.Struct` holding the fields above ([recommendations.proto](recommendations.proto)). Send the token as `authorization: Bearer <token>` metadata. A message comes at once, on every change, and every heartbeat. On shutdown the stream sends the empty, expired set and ends.

## Fail safe

A consumer must drop every route when `expires_in_ms` runs out without a newer document, when a document says `0`, and when it stops. That bounds how long routes outlive Packeteer:

- SIGTERM: the feed publishes the empty, expired set after the withdraw. A stream gets it at once; a poller that reaches the closed listener drops at the TTL.
- SIGKILL, a frozen process, or a lost network path: no round renews the feed, so the routes go at most `ttl` after the last round.
- A decision loop that stops running while the process lives: the documents keep being served, but with no time left once `ttl` passes.

The consumer is the one that enforces this on your daemon. If it dies, nothing removes the routes it applied (in render mode the file stays on disk) until it starts again and applies the empty set, so run it under your daemon's supervisor.

## Reference consumer

`packeteer-policy` ships in the image (`docker run ... --entrypoint packeteer-policy ghcr.io/grandarcher/packeteer`). It long-polls the JSON document and applies each change at once. It applies the empty set before it first reads the feed, so a file left by an earlier run is emptied. It keeps the last good set while the feed is unreachable until the expiry (a fetch never waits past it), then applies the empty set, and applies the empty set when stopped. A reload that runs longer than 30 s is killed and retried at the next poll.

It does not trust the feed. It drops a route, with a warning, unless the prefix is masked and inside `-allow`, the next hop is an address of the prefix's family, the communities include `-community` and NO_EXPORT, and every other community is a plain `asn:value` or `global:data1:data2` that is not `0:x` or `65535:x`. A template sees only `.Prefix`, `.NextHop`, `.LocalPref`, `.Communities`, and `.ASPath`; provider, cause, and reason are not passed on.

```sh
export PACKETEER_POLICY_TOKEN=...
# BIRD 2 or 3: render static routes and reconfigure.
packeteer-policy -url https://192.0.2.10:9443 -ca-file /etc/packeteer-policy/ca.pem \
  -community 64512:666 -allow 198.51.100.0/24 \
  -template bird.conf.tmpl -out /var/lib/packeteer-policy/routes.conf -reload "birdc configure"
```

| Flag | Meaning |
|---|---|
| `-url` | Feed base URL. `https`; `http` only to a loopback host. Redirects are not followed. |
| `-community` | Required: `packeteer_community`. |
| `-allow` | Comma-separated prefixes; a route outside them is dropped. Default: any prefix. Set it to your `allowlist.prefixes`. |
| `-ca-file` | PEM CA for the feed's certificate. Default: the system roots. |
| `-token-env` | Variable that holds the token (default `PACKETEER_POLICY_TOKEN`). |
| `-template`, `-out`, `-reload` | Render mode: execute the Go template with `.Routes`, replace `-out` in one rename, then run `-reload` (split on spaces, no shell). A failed reload is retried at the next poll. |
| `-exabgp` | ExaBGP process mode: `announce route` and `withdraw route` lines on stdout, logs on stderr. |

Examples in [examples/external-policy](../examples/external-policy):

- `bird.conf.tmpl`: one static protocol per family and a `packeteer_feed_session` BGP template with graceful restart and long-lived graceful restart off; include the rendered file at the top level of `bird.conf`, before the protocols, and build the session to the edge `from packeteer_feed_session`. A static route has preference 200, so it wins over the BGP paths. Lab-proven with BIRD 2 and 3.
- `openbgpd.conf.tmpl`: `network ... set { nexthop ... }` lines for `include` in `bgpd.conf`, reloaded with `bgpctl reload`. Set `announce restart no` on the neighbor to the edge. Rendering is tested; OpenBGPD itself is not in the lab.
- `exabgp.conf`: an ExaBGP 4 `process` running `packeteer-policy -exabgp`, with `graceful-restart disable` on the neighbor. Output is tested; ExaBGP itself is not in the lab.

Keep the daemon's own safety: export the applied routes to no eBGP neighbor, and honour NO_EXPORT. Keep graceful restart and long-lived graceful restart off on the session that carries them to the edge, so they go when the daemon or its session does.

## Rollback

Set `external_policy.enabled: false` and reload: consumers drop every route at once. With no `announcer`, set `mode: observe` in the same change: the config check refuses `mode: inject` with neither an announcer nor the feed.
