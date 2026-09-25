# FRR lab

A simulated edge router (FRR) peered over iBGP with Packeteer. Addresses are documentation prefixes (RFC 5737) and the ASN is the private-use value 64512. Nothing here touches a real network.

`lab/e2e.sh` builds the Packeteer image from the repo Dockerfile, starts FRR, and checks `vtysh -c 'show bgp ipv4 unicast json'`:

1. `198.51.100.0/24` appears with next hop `192.0.2.2` (transit-b), local preference 250, community `64512:666`, and `no-export`.
2. Rewriting the fixed-prober file so transit-a is faster withdraws that route (flip-back, after `hold_time`).
3. Restoring the original results announces it again.
4. Removing FRR's `network 198.51.100.0/24` withdraws Packeteer's route within seconds, while Packeteer is still running.
5. Stopping Packeteer withdraws it. Graceful restart is off on both sides.

The fixed prober (`type: fixed`) returns configured RTTs and sends no packets. It is for this lab and for tests. A real deployment uses `icmp` and `tcp`.

GitHub Actions runs this as the `e2e` job. Docker is required; the script does not run in the unit-test job.

```sh
bash lab/e2e.sh
```
