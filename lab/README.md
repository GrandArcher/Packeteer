# FRR lab

A simulated edge router (FRR) peered over iBGP with Packeteer. Addresses are documentation prefixes (RFC 5737) and the ASN is the private-use value 64512. Nothing here touches a real network.

`lab/e2e.sh` builds the Packeteer image from the repo Dockerfile, starts FRR, and checks `vtysh -c 'show bgp ipv4 unicast json'`:

1. `198.51.100.0/24` appears with next hop `192.0.2.2` (transit-b), local preference 250, community `64512:666`, and `no-export`.
2. Rewriting the fixed-prober file so transit-a is faster withdraws that route (flip-back, after `hold_time`).
3. Restoring the original results announces it again. The route then has to stay up while FRR is still advertising the native path (the network statement's weight keeps it best).
4. Removing FRR's `network 198.51.100.0/24` withdraws Packeteer's route within seconds, while Packeteer is still running. That is a real leave: FRR had kept sending the prefix.
5. The network statement is put back and Packeteer's import weight is raised to match, so local preference wins the way a real eBGP path loses. FRR stops advertising the prefix to Packeteer. Packeteer's route has to stay; withdrawing it would flap.
6. Stopping Packeteer with SIGTERM withdraws it (`WithdrawAll` while the session is still up).
7. Packeteer is started again and the route comes back. `docker kill -s KILL` stops it with no withdraw. FRR's negotiated hold time is the configured 9 seconds. The injected route must be gone once the session is no longer Established, and no later than that hold time plus a few seconds. A withdraw while the session is still Established fails this step. Graceful restart is off on both sides.

The fixed prober (`type: fixed`) returns configured RTTs and sends no packets. It is for this lab and for tests. A real deployment uses `icmp` and `tcp`.

`lab/e2e-commit.sh` is the commit-cause path on the same FRR edge. Probe RTTs stay inside the latency threshold. A static target declares 80 Mbps and the `fixed` telemetry plugin reports transit-a over its commit, so the injected route is a commit steer (`cause=commit` in the log). Rewriting the usage file so transit-a can take the prefix back withdraws it. The script then restores the over-commit file, stops Packeteer with SIGTERM, and SIGKILLs it. The route is gone once the session drops, and no later than the BGP hold timer. `fixed` telemetry is for this lab. A real edge uses `snmp` and flow volume.

`lab/e2e-cost.sh` is the cost-cause path on the same FRR edge (`lab/packeteer-cost.yaml`). transit-a costs 10 per Mbps and transit-b costs 5. transit-b is 10 ms slower, inside the 20 ms cost floor and the 15 ms performance threshold, so the injected route is a cost steer (`cause=cost` in the log). Rewriting the probe file so transit-b is 40 ms slower moves it outside the floor and withdraws the route. The script then restores the in-floor file, stops Packeteer with SIGTERM, and SIGKILLs it, with the same checks as the commit job.

`lab/e2e-inbound.sh` is inbound optimization (#25) on its own topology (`lab/docker-compose-inbound.yml`): the FRR edge (`lab/frr-inbound`) peers with Packeteer and with two simulated eBGP transits, transit-a (AS 64496, `192.0.2.21`) and transit-b (AS 64497, `192.0.2.22`). The edge originates `203.0.113.0/24`. The `fixed` telemetry file puts transit-a's inbound 95th over commit, so Packeteer re-announces the prefix with its marker and transit-a's catalog communities. The script checks the transits' own tables with `lab/checkpath`: transit-a must see `64512 64512 64512` and `64496:3`, transit-b the plain `64512`, and no Packeteer community may leave the edge. It releases the steer by rewriting the usage file, steers again inside the flap window (damped: doubled hold and learned inertia) and checks that flipping usage under does not release it, then stops Packeteer with SIGTERM. After a restart it rewrites the `fixed` prober file: transit-a slowest gives a performance steer, equal probes release it, transit-b slowest withholds the prefix from transit-b (`checkpath -absent`, selective announcement), and finally it SIGKILLs Packeteer with transit-a steered. Each stop must return both transits to the plain path, the SIGKILL case within the 9s hold timer.

`lab/e2e-bmp.sh` is the BMP monitoring station (#26) on its own topology (`lab/docker-compose-bmp.yml`). The FRR edge (`lab/frr-bmp`, bgpd with `-M bmp`) peers with Packeteer over iBGP and with two simulated eBGP transits (`lab/frr-bmp-transit-a`, `lab/frr-bmp-transit-b`). It streams post-policy Adj-RIB-In and Loc-RIB to Packeteer's station on `192.0.2.10:11019` (`lab/packeteer-bmp.yaml`). Both transits send `198.51.100.0/24`. transit-b prepends, so its path is inactive on the edge and never reaches Packeteer over iBGP. Only BMP shows it. transit-b (`bmp: only`) is the faster probed path. The script checks: (1) Packeteer steers onto transit-b's inactive path. (2) transit-b withdraws the prefix: the route check retires the improvement within seconds, inside the 5m `hold_time`, even though the edge still has Packeteer's own route as best and reports it back over BMP. Packeteer does not re-inject while transit-b has no path. (3) transit-b re-announces and the steer comes back. (4) The edge removes its BMP target: the improvement retires, and nothing is injected onto the `only` provider without a feed. (5) BMP returns and the steer comes back; SIGTERM withdraws it.

GitHub Actions runs all five scripts as the `e2e` job. Docker and Go are required (the scripts build `lab/checkroute` and `lab/checkpath`); they do not run in the unit-test job. `go test ./lab/checkroute ./lab/checkpath` covers the checks themselves.

```sh
bash lab/e2e.sh
bash lab/e2e-commit.sh
bash lab/e2e-cost.sh
bash lab/e2e-inbound.sh
bash lab/e2e-bmp.sh
```
