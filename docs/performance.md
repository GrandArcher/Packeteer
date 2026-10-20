# Load and soak testing

Packeteer's resource budgets, how CI measures them, and how to run the same test yourself. Lab only: the router, the table, and the flows are synthetic, built from documentation prefixes (RFC 5737, RFC 3849) and documentation ASNs. Nothing here touches a real network, and Packeteer runs in `observe`.

## What runs

`lab/soak.sh IMAGE [PROFILE] [DURATION]` starts the stock image with a mounted config, the same `docker run --network host --cap-add NET_RAW --cap-add NET_ADMIN -v config.yaml:/etc/packeteer/config.yaml` an operator uses. The harness (`lab/soak`, Go) then:

1. **Plays the edge router.** A minimal BGP speaker on `127.0.0.1:11179` (iBGP, AS 64512, hold time 9s). Packeteer connects from `127.0.0.2` and gets a full-table dump: 1,250,000 prefixes on the `pr` and `soak` profiles, about a 2026 IPv4 plus IPv6 table. The first 1,533 are every prefix from /24 to /32 inside the three RFC 5737 blocks; the rest split `2001:db8::/32` into /53s (a 3,000,000-prefix table uses /54). Runs of 64 prefixes share a next hop (two IPv4 and two IPv6 providers) and a documentation-ASN AS path of one to four hops, so UPDATEs pack the way a real table does. The speaker encodes UPDATEs from the generator and keeps no table, so the memory measured is Packeteer's.
2. **Exports flows.** IPFIX at 20,000 records per second to Packeteer's `flow` source. Half the records go to 5,000 hot prefixes and half are spread over the whole table, so the busiest prefixes stay stable while nearly every other record is a prefix the window has not seen.
3. **Churns the table.** 6,000 prefixes a minute are withdrawn and announced again (100 a second).
4. **Probes many targets.** 1,000 static targets plus the flow source's top 2,000, through four providers, with the `fixed` prober (no packets leave the host). transit-b is faster, so about half the measured prefixes get a recommendation that observe never announces.
5. **Measures.** Every few seconds it reads the Packeteer process from the host (`/proc/<pid>/status` and `/stat`: RSS, peak RSS, threads, CPU time), `GET /metrics` and `GET /api/overview` (latency, `packeteer_ready`, `packeteer_bgp_session_up`, `packeteer_rib_prefixes`, `packeteer_probe_prefix_commits`, `packeteer_flow_prefixes_tracked`), and the host's UDP `RcvbufErrors` (the collector's socket is in the host network namespace, so a datagram Packeteer was too slow to read is counted there). Active prefixes per hour are the increase in `packeteer_probe_prefix_commits` after warmup, scaled to one hour (a prefix counts once per round that stored it). Passive prefixes are the last `packeteer_flow_prefixes_tracked`, a HyperLogLog estimate of distinct destinations in the flow window, including ones past the 20,000 exact cells.
6. **Stops Packeteer.** `docker stop -t 30` (SIGTERM). The process must exit 0 and the router must see the session close.

It fails, and CI goes red, when a figure is over its budget or an invariant breaks: the session or readiness drops during the soak, the RIB view is not whole once churn stops, observe sends the router a route, the process dies, or the stop is not clean.

## Budgets

The budgets live in [lab/soak/budgets.yaml](../lab/soak/budgets.yaml) and are set for a GitHub-hosted `ubuntu-latest` runner (4 vCPU, 16 GB). Learn time and the three RSS figures grow with the table, so the file states them per million prefixes (`learn_seconds_per_mprefix`, `rss_peak_mb_per_mprefix`, `rss_growth_mb_per_mprefix`, `rss_slope_mb_per_mprefix`, #217) and the harness multiplies by the profile's `prefixes`. The table below shows the result at 1,250,000 prefixes, the same limits the file held before it was scaled: nothing was raised. The other figures do not depend on the table and stay flat.

| Figure | What it is | `pr` (every PR, 10 min) | `soak` (weekly, 5h30m) |
|---|---|---|---|
| Full table learned | Session open to `packeteer_rib_prefixes` = the profile's prefixes (72 s per million) | <= 90 s | <= 90 s |
| Peak RSS | `VmHWM` of the process, learning included (4915.2 MiB per million on `pr`, 5324.8 on `soak`) | <= 6144 MiB | <= 6656 MiB |
| RSS growth | Median RSS over the second half of the post-warmup soak, minus the median RSS during warmup (3 min / 15 min). Warmup is the baseline, so a later dip and refill toward that level is not growth | <= 384 MiB | <= 512 MiB |
| RSS still rising | RSS climb at the end of the run (#112): the smaller of the Theil-Sen slope over the last third times that third, and the median of the last sixth minus the median of the middle third. Both must show a climb, so a step or a dip and refill is not read as a leak | <= 192 MiB | <= 192 MiB |
| Average CPU | CPU seconds over wall time in the soak phase | <= 2.0 cores | <= 2.0 cores |
| OS threads | Most seen | <= 64 | <= 64 |
| Flow datagrams dropped | Host UDP `RcvbufErrors` over datagrams received, soak phase | <= 5 % | <= 5 % |
| API p99 latency | `GET /metrics` and `GET /api/overview` while loaded | <= 1500 ms | <= 2000 ms |
| Reconverge | Last churned batch back to a whole RIB view | <= 30 s | <= 30 s |
| SIGTERM to exit | `docker stop` to process gone | <= 20 s | <= 20 s |
| Prefixes measured | `/api/overview` `counts.measured` at the end | >= 2500 | >= 2500 |
| Active prefixes per hour | Increase in `packeteer_probe_prefix_commits` after warmup, scaled to one hour (#125). A prefix counts once per round that stored it | >= 180000 | >= 180000 |
| Passive prefixes tracked | Last `packeteer_flow_prefixes_tracked` (#125). HyperLogLog of the flow window, including prefixes the 20,000 exact cells did not keep | >= 50000 | >= 50000 |

`rss_growth_mb_per_mprefix` is 307.2 on `pr` (384 MiB at 1.25M) and 409.6 on `soak` (512 MiB). #125 does not re-baseline it. The sketch is 4 KiB per flow bucket, about 120 KiB for the 5-minute window (30 buckets), which does not move that RSS figure. #112 stays open.

A run prints the table with the measured values, adds it to the GitHub job summary, and uploads the JSON result as an artifact (`load-result`, `soak-result`).

Measured on an 8-core development machine with the `pr` workload and a 4-minute soak: full table learned in 18 s (4.5 cores while learning), peak RSS 4530 MiB, RSS growth 0.3 MiB, 0.72 cores average, 14 threads, 1.8 % flow datagrams dropped, API p99 240 ms, reconverge 0.07 s, SIGTERM to exit 7.8 s, 3000 prefixes measured. Most of the memory is the learned table: about 1.7 KB of live heap per prefix (GoBGP's Adj-RIB-In plus the view), and the Go collector lets the heap grow to about twice that between collections.

On the nine `pr` runs on GitHub-hosted `ubuntu-latest` through 2026-10-01, end RSS stayed in a 4609-4818 MiB band and peak RSS stayed between 4869 and 5353 (all under 6144). Go returns unused pages with `MADV_DONTNEED`, so RSS falls after a collection and climbs back over the next minutes. The previous growth check compared medians of the first and last tenth after warmup, about 35 seconds each, which is shorter than that cycle. Actions run 36902639588 (the push of #96 to `main`) sat in a valley for that first tenth (baseline 4476 MiB) and on the refilled heap for the last (4818), and failed at 342 MiB.

Replaying each run's per-sample RSS log (printed to the nearest MiB) with the rule above gives 97 MiB on that run (warmup median 4619, second-half median 4716) and at most 146 MiB across the nine. On 2026-10-07 the same figure on green `main` runs was 0, 176, and 191 MiB (ends 4806-4863 MiB, peaks 4954-5100). Actions run 37698413398 measured 258 MiB (warmup median 4590, second-half median 4849, peak 4967). RSS on that run fell from 4966 to 4827 over the last three minutes and stayed there, and the absolute end matched the green runs, so the extra was where the scavenger cycle sat relative to warmup.

The `pr` budget is 384 MiB: above that sample, and still under the 400 MiB sustained rise the growth test rejects. Peak RSS is unchanged, the weekly soak budget stays 512, and the `load` job still runs this check.

#112 trims the heap where that was cheap and adds a leak check; it raises no budget. A single iBGP path is stored in the route entry, so a full table does not pay a map header per prefix (710 to 358 bytes per prefix on a 50k synthetic table, measured with `TestSinglePathAdjIsCompact`). `Lookup` skips prefix lengths that hold no selected route (0 allocs per call). Per-address probe semaphores are dropped when the host leaves the probe set, so they stay bounded by the current target list. The flow reader decodes in its socket buffer and reuses the observation slice and the window eviction scratch, and the fixed prober formats the target address only when a path matches on it. A soft memory limit (`GOMEMLIMIT` once the live heap stopped growing) was tried and dropped: on Actions run 38058605143 it traded the plateau for collector work, and CPU read 2.6 cores and flow datagrams dropped 13.5 %, both over budget. The growth budget stays 384 MiB. Actions run 38064717462 read 554 MiB of growth against 384 with the heap trimmed: warmup median 3756 MiB, second-half median 4310, peak 4785. The warmup baseline fell about 750 MiB from earlier runs while the plateau did not, because at the default `GOGC=100` a collection cycle takes minutes at this allocation rate (0.39 cores) and RSS swings between the live heap (about 2.3 GiB) and twice it; the 3 minute warmup sat in a trough. The controller now sets `GOGC=50` when the variable is unset (`DefaultGCPercent`, `cmd/controller/gc.go`), which halves that swing at a few CPU seconds per cycle. An explicit `GOGC` in the container environment is left alone. The budget is not raised.

The growth figure compares the warmup with the second half of the run, so it cannot say whether RSS has levelled off. The "RSS still rising" row reads the end of the run itself and fails when the heap is still climbing. It uses a pairwise-slope median, not a least-squares fit, because RSS moves in steps and one step at the last sample is not a trend, and it requires the end to sit above the middle third so a dip and refill to a level the run already had is not a climb. Replayed on the RSS logged by three green runs on 2026-10-10 (Actions 38060328414, 38059199721, 38058626210; kept in `lab/soak/testdata`) it reads 0, 0, and 103 MiB; the same runs with 12 MiB per sample added across the last third fail. The weekly soak value has not been measured on a soak run yet.

## Scaling model and sizing

The model is linear in table size, from the `pr` figures. Peak RSS on the nine green `pr` runs through 2026-10-01 was 4869 to 5353 MiB over 1.25M prefixes, 4.0 to 4.4 KiB per prefix. Those runs predate `GOGC=50` (#112), so the figures include the collector's default headroom. The budget is 5.0 KiB per prefix (4915.2 MiB per million), about 15% over the worst of those runs. Learn time and the growth and rising-RSS checks are budgeted as fixed shares of that: 72 s, 307.2 MiB, and 153.6 MiB per million prefixes. What does not scale with the table is the work around it: flow rate, churn, and the probe target set. CPU, threads, flow drops, API latency, and reconverge time keep one budget at every size.

The limits the harness applies, and the RAM to give a host (the peak limit plus a quarter, for the kernel and other processes):

| Table | Learn time | Peak RSS | RSS growth | Still rising | Host RAM |
|---|---|---|---|---|---|
| 1,000,000 | 72 s | 4.8 GiB | 307 MiB | 154 MiB | 6 GiB |
| 3,000,000 | 216 s | 14.4 GiB | 922 MiB | 461 MiB | 18 GiB |
| 5,000,000 | 360 s | 24.0 GiB | 1536 MiB | 768 MiB | 30 GiB |

These are limits derived from the 1.25M measurements, not measurements at 3M or 5M. CPU while learning is also linear: 4.5 cores for 18 s on the development machine is about 65 core-seconds per million prefixes, so 195 at 3M and 325 at 5M, spread over however many cores the host has. Steady-state CPU is 0.72 cores on the `pr` workload, set by the flow, churn, and probe load, so it is not scaled. Multiple paths per prefix (several sessions carrying the same prefixes) cost more than one path; the harness plays one session, so its "paths" are prefixes, and a table with several paths per prefix needs more than the per-prefix figure.

### Limits at large tables

Passive measurement keeps bounded tables. Each cap, its default at 5M paths, and what a larger table does to it:

| Cap | Default | Limit | Reviewed at 5M paths |
|---|---|---|---|
| flow and span `max_prefixes` | 20000 | 250000 | Exact cells per 10-second bucket (a 5-minute window has 30). A flow cell costs about 220 bytes (`BenchmarkCellBytes` in `internal/plugins/source/flow` reads 223 on a 200,000-cell bucket), so the default holds at most 127 MiB. It is per bucket of traffic, not per table prefix, and the busiest prefixes are what it keeps, so it stays 20000. Raise it when `packeteer_truncated_total{limit="max_prefixes"}` climbs while you need more probe targets (`top_n` and `max_targets` cannot exceed it). The limit holds at most 1.5 GiB. |
| flow and span `top_n`, `max_targets` | 100 | 100000 | Was 10000. Probe time still bounds it: every packet waits on `probe.rate_limit_pps`. |
| outage, vip `max_targets`, outage `min_prefixes` | 100, 3 | 100000 | Was 10000. `min_prefixes` is a count, not a percent of the table. |
| anomaly `max_keys` | 10000 | 1000000 | Was 100000. Keys come from the flow source's counters, which `max_prefixes` bounds. |
| span `max_flows` | 100000 | 10000000 | Already configurable. Past it, new connections are counted in `packeteer_truncated_total{limit="max_flows"}`. |
| `probe.prober_memory` | 100000 | 1000000 | Already configurable. The least recently probed hosts are dropped past it. |
| `max_improvements` | 50 | 10000 | Unchanged. It caps routes Packeteer announces, a safety limit rather than a size limit. |
| history `maxPending` | 200000 | none | Unchanged. It bounds unflushed rollups only while the store keeps failing, so it does not follow the table. |

`packeteer_truncated_total{limit}` counts cap events since start, not distinct prefixes: `max_prefixes` is cells a full flow or span window bucket refused (flow also counts the cells it evicts for a larger prefix; counter keys are not counted); `max_flows` is span connections not tracked. A reload that replaces a source restarts its count. A value that stays at 0 means the cap is not binding.

## Findings fixed with this test

The first full-table run dropped 78.8 % of flow datagrams at 20,000 records a second, where a 20,000-prefix table dropped none. Each window bucket of the `flow` source holds at most 20,000 prefixes. Once full, every new prefix rescanned all of them for the smallest, and with a full table nearly every record is a new prefix. A full bucket now frees a sixteenth of its smallest prefixes in one pass (never one larger than the newcomer), and the anomaly counters prune idle keys at most once a minute while at their cap. Drops fell to 1.8 % and soak CPU from 1.2 to 0.72 cores. Which prefixes are kept is unchanged: the busiest stay, and a smaller prefix never displaces a larger one. Merging those buckets for probe targets and commit volume keeps a destination list only for the busiest 20,000 prefixes, plus a problem prefix outside that set. The percent floor still uses every byte in the window. `rss_growth_mb` is unchanged.

## Run it yourself

Docker and Go on a Linux host; the full profile needs about 6 GB free.

```sh
docker build -t packeteer:local .
bash lab/soak.sh packeteer:local smoke           # 20k prefixes, 1 minute, report only
bash lab/soak.sh packeteer:local pr              # what CI runs (1,250,000 prefixes)
bash lab/soak.sh packeteer:local soak 24h        # a 24-hour soak
bash lab/soak.sh packeteer:local routes3m        # opt-in 3,000,000 prefixes; not CI
bash lab/soak.sh packeteer:local large           # about 5,000,000 paths; needs 32 GB of RAM; not CI
bash lab/soak.sh packeteer:local rate            # opt-in 100 pps, 20k prefixes; not CI
```

`routes3m` (#103) is the same observe workload as `pr` with a 3 million prefix table. Nothing selects it unless a human passes that name. It uses the `pr` per-million budgets (#217), 14.4 GiB of peak RSS at 3 million, so do not start it on a host with less than 18 GiB free. Those limits are a scale from the measured `pr` run, not a 3 million measurement.

`large` (#217) is the same workload over 5,000,000 prefixes, 20 minutes with a 6 minute warmup because a collection cycle takes longer on a heap this size. It uses the `pr` per-million budgets: 360 s to learn, 24 GiB of peak RSS, 1536 MiB of growth, 768 MiB still rising. The harness plays one iBGP session, so the table is one path per prefix. If 5 million paths cost more per prefix than 1.25 million did, the run fails and the figure it measured is the finding: do not raise a budget to make it pass.

`rate` (#125) is a 20,000-prefix table at `probe.rate_limit_pps` 100, the operator default. 375 pinned static targets is one 30-second round for two same-family providers and 4 packets (`100 * 30 / (2 * 4)`). Flow `top_n` shares that budget, so a round may store only the prefixes that finished. Its budgets are empty. CI does not run it. The `pr` and `soak` profiles are what check the active and passive floors, and they still generate `rate_limit_pps: 100000` so the fixed prober is not what bounds those runs.

The ports are on the host loopback (`11179` BGP, `12055` IPFIX, `18081` ops API); change them with the harness flags (`go run ./lab/soak run -h`) if they are taken. `go run ./lab/soak config -profile pr` prints the Packeteer config the test mounts.

## CI

- The `load` job in `ci.yml` runs the `pr` profile (1,250,000 prefixes, the budgets above) on every pull request and push to `main`. It does not run `routes3m` or `rate`.
- `load-large.yml` (#217) runs the `large` profile weekly (Wednesday 04:41 UTC) and on demand, on the runner named by the repository variable `LARGE_RUNNER` or the `runner` input. It needs at least 32 GB of RAM; GitHub-hosted `ubuntu-latest` has 16 GB. With neither set the job is skipped. It is not a pull request check.
- `soak.yml` runs the `soak` profile weekly (Sunday 03:17 UTC) and on demand. A GitHub-hosted job stops at 6 hours, so the scheduled soak phase is 5h30m. For 24 hours, start it by hand with `duration: 24h` and `runner:` set to a self-hosted runner label. That workflow does not run `routes3m` or `rate` either.
