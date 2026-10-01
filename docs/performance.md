# Load and soak testing

Packeteer's resource budgets, how CI measures them, and how to run the same test yourself. Lab only: the router, the table, and the flows are synthetic, built from documentation prefixes (RFC 5737, RFC 3849) and documentation ASNs. Nothing here touches a real network, and Packeteer runs in `observe`.

## What runs

`lab/soak.sh IMAGE [PROFILE] [DURATION]` starts the stock image with a mounted config, the same `docker run --network host --cap-add NET_RAW --cap-add NET_ADMIN -v config.yaml:/etc/packeteer/config.yaml` an operator uses. The harness (`lab/soak`, Go) then:

1. **Plays the edge router.** A minimal BGP speaker on `127.0.0.1:11179` (iBGP, AS 64512, hold time 9s). Packeteer connects from `127.0.0.2` and gets a full-table dump: 1,250,000 prefixes, about a 2026 IPv4 plus IPv6 table. The first 1,533 are every prefix from /24 to /32 inside the three RFC 5737 blocks; the rest split `2001:db8::/32` into /53s. Runs of 64 prefixes share a next hop (two IPv4 and two IPv6 providers) and a documentation-ASN AS path of one to four hops, so UPDATEs pack the way a real table does. The speaker encodes UPDATEs from the generator and keeps no table, so the memory measured is Packeteer's.
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
| RSS growth | Median RSS over the second half of the post-warmup soak, minus the median RSS during warmup (3 min / 15 min). Warmup is the baseline, so a later dip and refill toward that level is not growth | ≤ 256 MiB | ≤ 512 MiB |
| Average CPU | CPU seconds over wall time in the soak phase | ≤ 2.0 cores | ≤ 2.0 cores |
| OS threads | Most seen | ≤ 64 | ≤ 64 |
| Flow datagrams dropped | Host UDP `RcvbufErrors` over datagrams received, soak phase | ≤ 5 % | ≤ 5 % |
| API p99 latency | `GET /metrics` and `GET /api/overview` while loaded | ≤ 1500 ms | ≤ 2000 ms |
| Reconverge | Last churned batch back to a whole RIB view | ≤ 30 s | ≤ 30 s |
| SIGTERM to exit | `docker stop` to process gone | ≤ 20 s | ≤ 20 s |
| Prefixes measured | `/api/overview` `counts.measured` at the end | ≥ 2500 | ≥ 2500 |

A run prints the table with the measured values, adds it to the GitHub job summary, and uploads the JSON result as an artifact (`load-result`, `soak-result`).

Measured on an 8-core development machine with the `pr` workload and a 4-minute soak: full table learned in 18 s (4.5 cores while learning), peak RSS 4530 MiB, RSS growth 0.3 MiB, 0.72 cores average, 14 threads, 1.8 % flow datagrams dropped, API p99 240 ms, reconverge 0.07 s, SIGTERM to exit 7.8 s, 3000 prefixes measured. Most of the memory is the learned table: about 1.7 KB of live heap per prefix (GoBGP's Adj-RIB-In plus the view), and the Go collector lets the heap grow to about twice that between collections.

On the nine `pr` runs on GitHub-hosted `ubuntu-latest` through 2026-10-01, end RSS stayed in a 4609–4818 MiB band and peak RSS stayed between 4869 and 5353 (all under 6144). Go returns unused pages with `MADV_DONTNEED`, so RSS falls after a collection and climbs back over the next minutes. The previous growth check compared medians of the first and last tenth after warmup, about 35 seconds each, which is shorter than that cycle. Actions run 36902639588 (the push of #96 to `main`) sat in a valley for that first tenth (baseline 4476 MiB) and on the refilled heap for the last (4818), and failed at 342 MiB. Replaying each run's per-sample RSS log (printed to the nearest MiB) with the rule above gives 97 MiB on that run (warmup median 4619, second-half median 4716) and at most 146 MiB across the nine. The 256 MiB budget is that measurement plus headroom. Peak RSS is unchanged, and the `load` job still runs this check.

## Findings fixed with this test

The first full-table run dropped 78.8 % of flow datagrams at 20,000 records a second, where a 20,000-prefix table dropped none. Each window bucket of the `flow` source holds at most 20,000 prefixes. Once full, every new prefix rescanned all of them for the smallest, and with a full table nearly every record is a new prefix. A full bucket now frees a sixteenth of its smallest prefixes in one pass (never one larger than the newcomer), and the anomaly counters prune idle keys at most once a minute while at their cap. Drops fell to 1.8 % and soak CPU from 1.2 to 0.72 cores. Which prefixes are kept is unchanged: the busiest stay, and a smaller prefix never displaces a larger one.

## Run it yourself

Docker and Go on a Linux host; the full profile needs about 6 GB free.

```sh
docker build -t packeteer:local .
bash lab/soak.sh packeteer:local smoke           # 20k prefixes, 1 minute, report only
bash lab/soak.sh packeteer:local pr              # what CI runs
bash lab/soak.sh packeteer:local soak 24h        # a 24-hour soak
```

The ports are on the host loopback (`11179` BGP, `12055` IPFIX, `18081` ops API); change them with the harness flags (`go run ./lab/soak run -h`) if they are taken. `go run ./lab/soak config -profile pr` prints the Packeteer config the test mounts.

## CI

- The `load` job in `ci.yml` runs the `pr` profile on every pull request and push to `main`.
- `soak.yml` runs the `soak` profile weekly (Sunday 03:17 UTC) and on demand. A GitHub-hosted job stops at 6 hours, so the scheduled soak phase is 5h30m. For 24 hours, start it by hand with `duration: 24h` and `runner:` set to a self-hosted runner label.
