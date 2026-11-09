# Recorded RTR answers

Raw RTR (RFC 8210, version 1) bytes captured from real caches on 2026-10-22 by a client that sent a Reset Query, changed the ROA set, waited for the Serial Notify, and sent a Serial Query from the session and serial of the first End of Data. Documentation prefixes and ASNs only.

| File | What |
|---|---|
| `<cache>-reset.bin` | The response to the Reset Query: Cache Response, Prefix PDUs, End of Data. |
| `<cache>-notify.bin` | The Serial Notify sent after the change. |
| `<cache>-serial.bin` | The response to the Serial Query: one withdrawal and one announcement, End of Data. |

ROA set before the change: `192.0.2.0/24-24 AS64496`, `203.0.113.0/24-25 AS64497`, `2001:db8::/32-48 AS64498`. After it, `203.0.113.0/24-25 AS64497` is withdrawn and `198.51.100.0/24-24 AS64499` is announced.

| Cache | Version | Where its VRPs came from |
|---|---|---|
| `routinator` | Routinator 0.15.1 | No TALs (`--no-rir-tals`); the ROA set was a SLURM (RFC 8416) `prefixAssertions` file, swapped for the change. |
| `stayrtr` | StayRTR 0.6.4 | A VRP JSON file written by `routinator vrps -f json`, swapped for the change. |
| `fort` | FORT 1.6.8 | Validated a local Krill 0.15.1 testbed trust anchor over RRDP; the change was a ROA update in Krill. |

rpki-client has no RTR server; its JSON output is in `internal/plugins/rpki/vrpjson/testdata`.
