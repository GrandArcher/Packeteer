# ROI worksheet

A way to estimate what Packeteer returns on your edge, using numbers you already have and numbers Packeteer measures in observe. Nothing here needs injection: observe records recommendations, and every figure below is an estimate until a move is really made. Use it with [adopting.md](adopting.md).

Use one currency and one billing month throughout. The figures below are made up and use documentation names.

## 1. Inputs you bring

| Input | Where it comes from |
|---|---|
| Price per Mbps per month for each transit | Your contract. Put it in `providers[].cost`. |
| Commit per transit (Mbps) | Your contract. Put it in the SNMP binding as `commit_mbps`. |
| Overage rate per Mbps above the commit | Your contract. Packeteer does not store it. |
| Running cost of Packeteer | A small host or VM, plus operator time. The software is Apache-2.0 ([LICENSE](../LICENSE)) and has no license fee. |

## 2. Inputs Packeteer measures

Set `cost` on at least two providers, add a `flow` source (or `mbps` on static targets) so prefixes carry a volume, add `telemetry` for the 95th percentile, and set `storage: {type: sqlite}` to keep history. Then read:

| Figure | Where |
|---|---|
| `est_savings`: the price difference times the prefix volume, per month, for a recommended move between two priced providers | `GET /api/improvements`, and the `savings` and `improvements` reports |
| Accrued savings: `est_savings` times the hours the move was active in the range, divided by 730 | `savings` report (`accrued`), `summary` report (`est_savings_accrued`) |
| Billable 95th against the commit, per provider | `/commit.html`, `GET /api/commit` |
| Loss and latency before and after each move | `summary` report (`before_loss_pct`, `after_loss_pct`, `before_rtt_ms`, `after_rtt_ms`) |

Two limits to keep in mind:

- In observe and suggest these are recommendations. Nothing moved, so the figures are what Packeteer would have saved, not what you saved.
- `est_savings` multiplies by volume only when a source reports one. Without a volume the figure is the price difference per Mbps alone, and you multiply by the traffic yourself.

## 3. The three lines

### A. Transit cost

For each recommended cost move:

```
cost saving per month = (native price - steered price) x Mbps moved
```

This is what Packeteer reports as `est_savings`. The `cost` scorer moves a prefix only onto a cheaper provider whose path is inside its performance floor. Total A is the sum over the moves that stay active. A performance move onto a dearer provider shows as a negative value, which is extra spend. Include it.

Example: 400 Mbps of `198.51.100.0/24` and its neighbors move from transit-a (2.00 per Mbps) to transit-b (1.20 per Mbps). A = (2.00 - 1.20) x 400 = 320 per month. If the moves were active for 360 hours of the range, the accrued figure for that range is 320 x 360 / 730 = 157.81.

### B. Commit relief

Packeteer reports the 95th and plans commit moves, but it does not compute commit dollars. Work it out from the commit report:

```
overage now      = max(0, billable 95th - commit) x overage rate
overage after    = max(0, 95th after the move - commit) x overage rate
destination cost = Mbps added above the destination's own commit x its rate
commit relief    = overage now - overage after - destination cost
```

Move only traffic the `commit` scorer could really move: a prefix needs a volume, a destination needs room under its own commit, and a `cc_disable` provider is left out. A move that is active only some of the time lowers the 95th only if it covers the busiest 5 percent of samples, so read the running 95th on `/commit.html` rather than the average.

Example: transit-a has a commit of 1000 Mbps and a billable 95th of 1150 Mbps. The overage rate is 2.00 per Mbps, so overage now is 150 x 2.00 = 300. The `commit` scorer recommends moving 150 Mbps to transit-b, which has 400 Mbps free under its commit. Overage after is 0 and destination cost is 0, so B = 300 per month.

### C. Measured gain

Loss and latency gains have no price in Packeteer. Take the before and after figures from the `summary` report for performance moves and put your own value on them. Two ways that stay close to the data:

- Capacity you did not buy. If the alternative to fixing a congested path was more commit on one transit, C = Mbps you would have bought x its price per Mbps.
- Loss you would otherwise have to credit or explain. Take the prefixes whose loss fell after a move (the `improvements` report lists loss before and after per prefix) and value each at what that loss costs you, for example support time or service credits.

Leave C at 0 if you cannot support a number. The worksheet is still useful with A and B alone.

## 4. Net

```
monthly return = A + B + C - running cost
payback        = one-time setup cost / monthly return
```

Example: A = 320, B = 300, C = 0, running cost 80 (host and an hour of operator time). Monthly return = 540. With a one-time setup cost of 1,000, payback is under two months.

## 5. Checks before you trust the number

- Run for at least one billing period. A week hides the 95th.
- Compare against the recommendations you would accept. `/api/improvements` gives a reason sentence for each; a saving built on moves you would not make does not count.
- Confirm prices and commits against the contract, not the config. A stale `cost` makes every figure wrong.
- If the native path is already the cheapest inside the floor, there is nothing to move and A is 0.
- Re-run after you turn on inject. The `improvements` report has a `mode` column, so you can separate recommended moves from announced ones and replace the estimate with what was announced.
