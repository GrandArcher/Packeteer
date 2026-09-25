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

GitHub Actions runs all three scripts as the `e2e` job. Docker and Go are required (the script builds `lab/checkroute`); it does not run in the unit-test job. `go test ./lab/checkroute` covers the route check itself.

```sh
bash lab/e2e.sh
bash lab/e2e-commit.sh
bash lab/e2e-cost.sh
```
