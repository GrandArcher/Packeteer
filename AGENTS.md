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

## PR requirements

- Branch from `main`. Never push to `main`.
- Include tests for the behavior you changed.
- Update ARCHITECTURE.md only when the pipeline changes.
- Describe rollback in the PR body for any announce-path change.
