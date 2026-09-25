# Agent rules for Packeteer

This repository controls BGP in real networks when injection is enabled. Treat every change as if it will run on a multi-homed edge.

## Scope

- Implement one GitHub issue per pull request.
- Do not expand scope. Do not refactor unrelated packages.
- Default language is Go. Do not add a second implementation language.
- Do not commit secrets, production prefixes, live RIBs, SNMP communities, or customer data.

## Safety (non-negotiable)

- Default operating mode is `observe`.
- Injection requires explicit `mode: inject` and an allowlist.
- Never announce a prefix that was not present in the local RIB view.
- Cap active improvements. Start at 50 unless an issue says otherwise.
- Require hold time and loss/latency thresholds before flipping a path.
- Tag every injected route with the configured community.
- Controller crash or probe-source loss must withdraw Packeteer-originated routes or leave native BGP untouched. No stale intent.
- Tests are required for announce, withdraw, and crash/withdraw behavior before any inject-path code merges.

## Docker-first (non-negotiable)

- The primary install is ONE container:
  `docker run --network host --cap-add NET_RAW --cap-add NET_ADMIN -v "$PWD/config.yaml:/etc/packeteer/config.yaml" ghcr.io/grandarcher/packeteer`
- Every feature must work inside that container with a mounted config file and env vars (`PACKETEER_CONFIG`, etc.). No host-only assumptions (no systemd units, host paths, or host tools required at runtime).
- The CI `docker` job must stay green: the image builds and runs against a mounted config.

## Modularity

- New capabilities are added as plugins behind a small interface (prober, target source, scorer, announcer, notifier, exporter), selected by `type` in config. Do not hard-wire them into the core.
- Plugin config is validated at load time; unknown plugin types are errors.
- Plugins must work with the stock image (built-in or out-of-process `exec` / `webhook`); see docs/PLUGINS.md.

## Testing BGP

- All BGP tests use simulated routers (in-process GoBGP, or FRR/GoBGP containers in CI). Never real networks.
- No graceful-restart: Packeteer routes must disappear when Packeteer does.
- Use documentation prefixes (192.0.2.0/24, 198.51.100.0/24, 203.0.113.0/24, 2001:db8::/32) and documentation/private ASNs (64496-64511, 65536-65551, or 64512-65534) only.

## PR requirements

- Branch from `main`. Never push to `main`.
- Include tests for the behavior you changed.
- Update ARCHITECTURE.md only when the pipeline changes.
- Describe rollback in the PR body for any announce-path change.
