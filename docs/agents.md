# Distributed probe agents (#230)

Tested in process over mutual TLS only (no container lab job yet); not proven on a public edge. Default mode stays `observe`.

A probe agent is a small process you run inside your own network (another POP, a site behind an edge router, a data center). It measures a provider from where that provider's traffic leaves and reports to one central controller. It is not the herd ([herd.md](herd.md)), which shares measurements between different networks.

The agent has no BGP, no injection, and no UI, and it listens on no port. It calls the controller over mutual TLS, so a remote site needs no inbound rule. It is a `prober` plugin on the controller side (`agent`), so every decision, cap, allowlist, and withdraw rule works as before.

## How it works

1. A provider with `site: dc-b` is measured only by agents that declare site `dc-b` and the provider's name. The controller's own probers skip it (it has no `source_ip`), and the `agent` prober serves only providers with a site.
2. The agent declares its site and, per provider, the `source_ip`, `fwmark`, and `dscp` it probes from. A task from the controller names only the provider, target, packet count, and timeout, so the controller cannot make an agent send from another address. The agent refuses a provider it did not declare, more than 100 packets, and a timeout over 30 s.
3. Each probe goes to one usable agent at the site: the one with the earliest free slot under its rate limit, then the one with the least work queued, then the one that served the fewest. Several agents at one site share the load.
4. The result is the raw replies. The controller computes loss, RTT, and jitter as for any prober, and the result carries `site` and `agent` (`/api/prefixes` probe rows, `/api/providers` `site`).

## Safety

- An agent not listed in `agents`, a certificate from another CA, and a certificate on the CRL are refused (403, or no TLS session). The check runs on every request, so a revoked agent is refused on an open connection, and the CRL file is re-read within a second of a change.
- An agent is usable only while it has called within `max_age` and its certificate is not revoked. A hung-up poll makes it unusable at once. Probes waiting on a stale agent fail.
- When no agent at a provider's site is usable, the provider fails closed like a probe source that cannot be bound: it is marked down, a decision never uses it, and an improvement steering to it is retired and withdrawn. Its earlier results age out as stale. Other sites are not affected.
- An agent that reports it cannot use its declared source address (`source_unavailable`) fails the provider closed too.
- An agent answers only its own tasks, and a reply is checked against the task: no more packets than asked, no RTT past the timeout.
- An agent that loses the controller only retries its poll, with a pause growing to 15 s. It runs nothing without a task and keeps no queue, so nothing it holds can reach routing. Routes are announced only by the controller.
- `max_pps` caps the packets per second sent to one agent (default 100). A probe that would wait past its deadline for a slot is dropped; that keeps the provider's previous result, which goes stale on its own.

## Controller config

```yaml
providers:
  - name: carrier-a
    site: dc-a              # no source_ip, fwmark, or dscp: the agent declares them
    next_hop: 192.0.2.1
  - name: carrier-b
    site: dc-b
    next_hop: 192.0.2.2
probers:
  - type: agent
    config:
      listen: 0.0.0.0:9444
      cert_file: /etc/packeteer/certs/controller.crt
      key_file: /etc/packeteer/certs/controller.key
      ca_file: /etc/packeteer/certs/ca.crt
      crl_file: /etc/packeteer/certs/agents.crl   # optional
      agents:
        - name: agent-a        # certificate CN or DNS SAN
          max_pps: 100
        - name: agent-b
```

Keys are in [CONFIG.md](CONFIG.md#prober-agent). A provider with a `site` needs a `probers` entry of type `agent`, and the agent prober is used only for such providers; list the usual probers too for providers without a site. A site provider is probed toward targets of its `next_hop` address family, so the agent's `source_ip` for it must be that family (use one provider per family for dual stack). `path_check`, `probe.reorder`, and `probe.indirect` do not apply to a provider with a site, because they start from the controller host.

## Agent config

`/etc/packeteer/agent.yaml` (or `PACKETEER_AGENT_CONFIG`):

```yaml
controller_url: https://192.0.2.10:9444
server_name: controller        # only when the certificate name differs from the URL host
cert_file: /etc/packeteer/certs/agent-a.crt
key_file: /etc/packeteer/certs/agent-a.key
ca_file: /etc/packeteer/certs/ca.crt
site: dc-a
prober:
  type: icmp                   # icmp (default), tcp, or udp, with that prober's config
providers:
  - name: carrier-a            # a provider name from the controller config
    source_ip: 192.0.2.11      # on this host, and routed out through that provider
    fwmark: 0
    dscp: 0
max_concurrent: 8
```

`packeteer-agent -check` validates the file and exits. Providers the controller does not know are ignored.

## Certificates

One CA signs the controller's certificate (server and client use; its names or IP addresses must match `controller_url`) and each agent's certificate (client use; the CN or a DNS SAN is the agent's name). Use one certificate per agent. TLS 1.3 only.

Revoke an agent by adding its certificate to the CRL (PEM, signed by a CA in `ca_file`) that `crl_file` names, or by removing it from `agents` and restarting. A CRL that is not signed by the CA is refused; if a later reload fails, the previous list stays.

## Docker

The image ships `packeteer-agent`. Run it on the remote host with the same image:

```sh
docker run --network host --cap-add NET_RAW --cap-add NET_ADMIN \
  --entrypoint packeteer-agent \
  -v "$PWD/agent.yaml:/etc/packeteer/agent.yaml" \
  -v "$PWD/certs:/etc/packeteer/certs:ro" \
  ghcr.io/grandarcher/packeteer
```

`--network host` is needed so the agent can use the host's addresses and policy routing. On the controller, publish the `listen` port (or use host networking) and mount the certificates.

## Testing

`go test ./internal/plugins/prober/agent` starts a controller and agents over real mutual TLS on loopback and checks the split across agents and sites, the per-site attribution, a killed agent failing its provider closed, revocation at start and while running, unlisted and foreign certificates, rate limits, and forged answers. There is no container lab job for it yet.

Rollback: remove the `agent` prober and the `site` keys and restart; stop the agents.
