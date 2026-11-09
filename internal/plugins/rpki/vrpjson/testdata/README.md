# Recorded VRP JSON

Captured on 2026-10-22. Documentation prefixes and ASNs only. Both hold `192.0.2.0/24-24 AS64496`, `203.0.113.0/24-25 AS64497`, and `2001:db8::/32-48 AS64498`.

| File | Source |
|---|---|
| `routinator.json` | `GET /json` from Routinator 0.15.1 running with no TALs and the ROAs as SLURM (RFC 8416) `prefixAssertions`. ASNs are strings (`"AS64496"`); the time is `metadata.generated`. |
| `rpki-client.json` | The `json` file rpki-client 9.9 wrote with `-j` after validating a local Krill 0.15.1 testbed trust anchor over RRDP. ASNs are numbers; the time is `metadata.buildtime`. `metadata.buildmachine` was replaced with `lab`. |

The tests rewrite the time fields to the test clock.
