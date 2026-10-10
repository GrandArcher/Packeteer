# Load and soak testing

Packeteer's resource budgets, how CI measures them, and how to run the same test yourself. Lab only: the router, the table, and the flows are synthetic, built from documentation prefixes (RFC 5737, RFC 3849) and documentation ASNs. Nothing here touches a real network, and Packeteer runs in `observe`.

## What runs

`lab/soak.sh IMAGE [PROFILE] [DURATION]` starts the stock image with a mounted config, the same `docker run --network host --cap-add NET_RAW --cap-add NET_ADMIN -v config.yaml:/etc/packeteer/config.yaml` an operator uses. The harness (`lab/soak`, Go) then:

1. **Plays the edge router.** A minimal BGP speaker on `127.0.0.1:11179` (iBGP, AS 64512, hold time 9s). Packeteer connects from `127.0.0.2` and gets a full-table dump: 1,250,000 prefixes on the `pr` and `soak` profiles, about a 2026 IPv4 plus IPv6 table. The first 1,533 are every prefix from /24 to /32 inside the three RFC 5737 blocks; the rest split `2001:db8::/32` into /53s (a 3,000,000-prefix table uses /54). Runs of 64 prefixes share a next hop (two IPv4 and two IPv6 providers) and a documentation-ASN AS path of one to four hops, so UPDATEs pack the way a real table does. The speaker encodes UPDATEs from the generator and keeps no table, so the memory measured is Packeteer's.
2. **Exports flows.** IPFIX at 20,000 records per second to Packeteer's `flow` source. Half the records go to 5,000 hot prefixes and half are spread over the whole table, so the busiest prefixes stay stable while nearly every other record is a prefix the window has not seen.
3. **Churns the table.** 6,000 prefixes a minute are withdrawn and announced again (100 a second).
4. **Probes many targets.** 1,000 static targets plus the flow source's top 2,000, through four providers, with the `fixed` prober (no packets leave the host). transit-b is faster, so about half the measured prefixes get a recommendation that observe never announces.
5. **Measures.** Every few seconds it reads the Packeteer process from the host (`/proc/<pid>/status` and `/stat`: RSS, peak RSS, threads, CPU time), `GET /metrics` and `GET /api/overview` (latency, `packeteer_ready`, `packeteer_bgp_session_up`, `packeteer_rib_prefixes`), and the host's UDP `RcvbufErrors` (the collector's socket is in the host network namespace, so a datagram Packeteer was too slow to read is counted there).
6. **Stops Packeteer.** `docker stop -t 30` (SIGTERM). The process must exit 0 and the router must see the session close.

It fails, and CI goes red, when a figure is over its budget or an invariant breaks: the session or readiness drops during the soak, the RIB view is not whole once churn stops, observe sends the router a route, the process dies, or the stop is not clean.

## Budgets

The budgets live in [lab/soak/budgets.yaml](../lab/soak/budgets.yaml) and are set for a GitHub-hosted `ubuntu-latest` runner (4 vCPU, 16 GB).

| Figure | What it is | `pr` (every PR, 10 min) | `soak` (weekly, 5h30m) |
|---|---|---|---|
| Full table learned | Session open to `packeteer_rib_prefixes` = 1,250,000 | ≤ 90 s | ≤ 90 s |
| Peak RSS | `VmHWM` of the process, learning included | ≤ 6144 MiB | ≤ 6656 MiB |
| RSS growth | Median RSS over the second half of the post-warmup soak, minus the median RSS during warmup (3 min / 15 min). Warmup is the baseline, so a later dip and refill toward that level is not growth | ≤ 384 MiB | ≤ 512 MiB |
| RSS still rising | RSS climb at the end of the run (#112): the smaller of the Theil-Sen slope over the last third times that third, and the median of the last sixth minus the median of the middle third. Both must show a climb, so a step or a dip and refill is not read as a leak | ≤ 192 MiB | ≤ 192 MiB |
| Average CPU | CPU seconds over wall time in the soak phase | ≤ 2.0 cores | ≤ 2.0 cores |
| OS threads | Most seen | ≤ 64 | ≤ 64 |
| Flow datagrams dropped | Host UDP `RcvbufErrors` over datagrams received, soak phase | ≤ 5 % | ≤ 5 % |
| API p99 latency | `GET /metrics` and `GET /api/overview` while loaded | ≤ 1500 ms | ≤ 2000 ms |
| Reconverge | Last churned batch back to a whole RIB view | ≤ 30 s | ≤ 30 s |
| SIGTERM to exit | `docker stop` to process gone | ≤ 20 s | ≤ 20 s |
| Prefixes measured | `/api/overview` `counts.measured` at the end | ≥ 2500 | ≥ 2500 |

A run prints the table with the measured values, adds it to the GitHub job summary, and uploads the JSON result as an artifact (`load-result`, `soak-result`).

Measured on an 8-core development machine with the `pr` workload and a 4-minute soak: full table learned in 18 s (4.5 cores while learning), peak RSS 4530 MiB, RSS growth 0.3 MiB, 0.72 cores average, 14 threads, 1.8 % flow datagrams dropped, API p99 240 ms, reconverge 0.07 s, SIGTERM to exit 7.8 s, 3000 prefixes measured. Most of the memory is the learned table: about 1.7 KB of live heap per prefix (GoBGP's Adj-RIB-In plus the view), and the Go collector lets the heap grow to about twice that between collections.

On the nine `pr` runs on GitHub-hosted `ubuntu-latest` through 2026-10-01, end RSS stayed in a 4609–4818 MiB band and peak RSS stayed between 4869 and 5353 (all under 6144). Go returns unused pages with `MADV_DONTNEED`, so RSS falls after a collection and climbs back over the next minutes. The previous growth check compared medians of the first and last tenth after warmup, about 35 seconds each, which is shorter than that cycle. Actions run 36902639588 (the push of #96 to `main`) sat in a valley for that first tenth (baseline 4476 MiB) and on the refilled heap for the last (4818), and failed at 342 MiB. Replaying each run's per-sample RSS log (printed to the nearest MiB) with the rule above gives 97 MiB on that run (warmup median 4619, second-half median 4716) and at most 146 MiB across the nine. On 2026-10-07 the same figure on green `main` runs was 0, 176, and 191 MiB (ends 4806–4863 MiB, peaks 4954–5100). Actions run 37698413398 measured 258 MiB (warmup median 4590, second-half median 4849, peak 4967). RSS on that run fell from 4966 to 4827 over the last three minutes and stayed there, and the absolute end matched the green runs, so the extra was where the scavenger cycle sat relative to warmup. The `pr` budget is 384 MiB: above that sample, and still under the 400 MiB sustained rise the growth test rejects. Peak RSS is unchanged, the weekly soak budget stays 512, and the `load` job still runs this check.

#112 trims the heap where that was cheap and adds a leak check; it raises no budget. A single iBGP path is stored in the route entry, so a full table does not pay a map header per prefix (710 to 358 bytes per prefix on a 50k synthetic table, measured with `TestSinglePathAdjIsCompact`). `Lookup` skips prefix lengths that hold no selected route (0 allocs per call). Per-address probe semaphores are dropped when the host leaves the probe set, so they stay bounded by the current target list. The flow reader decodes in its socket buffer and reuses the observation slice and the window eviction scratch, and the fixed prober formats the target address only when a path matches on it. A soft memory limit (`GOMEMLIMIT` once the live heap stopped growing) was tried and dropped: on Actions run 38058605143 it traded the plateau for collector work, and CPU read 2.6 cores and flow datagrams dropped 13.5 %, both over budget. The growth budget stays 384 MiB.

The growth figure compares the warmup with the second half of the run, so it cannot say whether RSS has levelled off. The "RSS still rising" row reads the end of the run itself and fails when the heap is still climbing. It uses a pairwise-slope median, not a least-squares fit, because RSS moves in steps and one step at the last sample is not a trend, and it requires the end to sit above the middle third so a dip and refill to a level the run already had is not a climb. Replayed on the RSS logged by three green runs on 2026-10-10 (Actions 38060328414, 38059199721, 38058626210; kept in `lab/soak/testdata`) it reads 0, 0, and 103 MiB; the same runs with 12 MiB per sample added across the last third fail. The weekly soak value has not been measured on a soak run yet.

## Findings fixed with this test

The first full-table run dropped 78.8 % of flow datagrams at 20,000 records a second, where a 20,000-prefix table dropped none. Each window bucket of the `flow` source holds at most 20,000 prefixes. Once full, every new prefix rescanned all of them for the smallest, and with a full table nearly every record is a new prefix. A full bucket now frees a sixteenth of its smallest prefixes in one pass (never one larger than the newcomer), and the anomaly counters prune idle keys at most once a minute while at their cap. Drops fell to 1.8 % and soak CPU from 1.2 to 0.72 cores. Which prefixes are kept is unchanged: the busiest stay, and a smaller prefix never displaces a larger one.

## Run it yourself

Docker and Go on a Linux host; the full profile needs about 6 GB free.

```sh
docker build -t packeteer:local .
bash lab/soak.sh packeteer:local smoke           # 20k prefixes, 1 minute, report only
bash lab/soak.sh packeteer:local pr              # what CI runs (1,250,000 prefixes)
bash lab/soak.sh packeteer:local soak 24h        # a 24-hour soak
bash lab/soak.sh packeteer:local routes3m        # opt-in 3,000,000 prefixes; not CI
```

`routes3m` (#103) is the same observe workload as `pr` with a 3 million prefix table. Nothing selects it unless a human passes that name. Its budgets are empty, so the run records learn time, RSS, and API latency and does not fail a number. The 1.25 million table measured about 4.5 GiB RSS (about 1.7 KB of live heap per prefix, and the collector lets the heap grow to about twice that). Three million prefixes is 2.4 times that table, on the order of 11 GiB before that headroom, so do not start `routes3m` on a host with only a few gigabytes free. Those figures are a scale from the measured `pr` run, not a 3 million measurement. With no `learn_seconds` budget the harness waits up to 30 minutes for the table.

The ports are on the host loopback (`11179` BGP, `12055` IPFIX, `18081` ops API); change them with the harness flags (`go run ./lab/soak run -h`) if they are taken. `go run ./lab/soak config -profile pr` prints the Packeteer config the test mounts.

## CI

- The `load` job in `ci.yml` runs the `pr` profile (1,250,000 prefixes, the budgets above) on every pull request and push to `main`. It does not run `routes3m`.
- `soak.yml` runs the `soak` profile weekly (Sunday 03:17 UTC) and on demand. A GitHub-hosted job stops at 6 hours, so the scheduled soak phase is 5h30m. For 24 hours, start it by hand with `duration: 24h` and `runner:` set to a self-hosted runner label. That workflow does not run `routes3m` either.
