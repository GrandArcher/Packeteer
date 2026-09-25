# Packeteer

Open-source BGP path performance controller for multi-homed networks.

Packeteer measures loss, latency, and jitter toward destination prefixes over each upstream, scores the paths, and can optionally inject better routes into your edge via iBGP. It sits off-path. If Packeteer dies, native BGP remains in charge.

This is not a Noction IRP clone. v0 is observe-first: probe and score. Injection is opt-in, allowlisted, and community-tagged so you can filter it from eBGP.

## Status

M0 scaffold. Not production-ready. Do not point this at a live edge until observe mode is boring.

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
cmd/controller/     # entrypoint (coming in M1)
internal/probe/     # per-provider sourced measurements
internal/policy/    # score + hysteresis
internal/announce/  # ExaBGP / GoBGP speaker
deploy/             # example ExaBGP + MikroTik notes
```

## License

Apache-2.0. See [LICENSE](LICENSE).
