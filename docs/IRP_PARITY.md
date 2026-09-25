# Noction IRP feature parity

Feature parity with [Noction IRP](https://www.noction.com/docs/irp-features) is Packeteer's top roadmap priority. This matrix lists IRP's capabilities, taken from the public IRP technical documentation (section numbers refer to it), with Packeteer's status, target milestone, the plugin kind that implements each one, and the tracking issue.

Every parity feature ships as a plugin behind the interfaces in `pkg/plugin` wherever one fits (see [PLUGINS.md](PLUGINS.md)), and it must work in the stock Docker image. Packeteer's safety rules (observe by default, allowlist, community tagging, improvement cap, withdraw on failure, no graceful restart) apply to every feature, even where IRP behaves differently.

Statuses: **done** (merged to `main`), **in progress** (open PR or active branch), **planned** (issue exists), **won't do** (reason given).

Milestones:
- **v0.1**: installable core outbound performance loop: probing, targets from static lists and flows, RIB via iBGP, scoring with hysteresis, injection via GoBGP, web UI + API + metrics, Docker, e2e lab.
- **v0.2**: cost and commit control, SNMP, VIP and AS-pattern detection, policies (prefix/ASN/country), alerts, reports.
- **v0.3**: inbound optimization, BMP, multiple routers and IX, FlowSpec/RTBH, transit optimization.
- **v0.4**: multi-POP, HA, RBAC, anomaly detection, remaining parity.

## Summary

| Milestone | Capabilities |
|---|---|
| v0.1 | 24 |
| v0.2 | 26 |
| v0.3 | 16 |
| v0.4 | 12 |
| won't do | 3 |
| **total** | 81 |

| Status | Count |
|---|---|
| done | 20 |
| in progress | 0 |
| planned | 58 |
| won't do | 3 |

## Performance optimization

| Capability | IRP doc ref | Status | Milestone | Plugin kind | Issue |
|---|---|---|---|---|---|
| Active probing per provider: ICMP | 1.3.1, Explorer | done | v0.1 | prober (`icmp`) | #2 |
| Active probing per provider: TCP | 1.3.1, Explorer | done | v0.1 | prober (`tcp`) | #2 |
| Active probing per provider: UDP | Explorer | planned | v0.2 | prober (`udp`) | #15 |
| Traceroute-based probe target discovery | Explorer | planned | v0.2 | source (`traceroute`) | #15 |
| Loss / latency / jitter measurement and scoring | 1.3.1 | done | v0.1 | prober + scorer (`weighted`) | #2, #7 |
| Throughput-aware scoring (prefix volume weighting) | 1.2.13 Improvements weight | planned | v0.2 | scorer | #23, #18 |
| Probe sources per provider (IRP uses PBR; we use source-IP policy routing) | 2.8 Explorer, 2.8.1 PBR | done | v0.1 | core + docs | #2 |
| Static probe target lists | - | done | v0.1 | source (`static`) | #2 |
| Flow-based target discovery (NetFlow v5/v9, IPFIX, sFlow) | 2.7.1 Irpflowd | done | v0.1 | source (`flow`) | #5 |
| Passive problem detection from flows | 2.7 Collector | planned | v0.2 | source | #21 |
| SPAN / mirrored-traffic collector | 2.7.2 Irpspand | planned | v0.2 | source (`span`) | #21 |
| AS-pattern outage/congestion detection (re-probe prefixes crossing a sick ASN) | 1.2.6 Outage Detection | planned | v0.2 | source (detector) | #16 |
| Circuit issues detection | 1.2.23 | planned | v0.2 | source (detector) | #16 |
| VIP (critical) prefixes/ASNs with more frequent probing | 1.2.7 VIP Improvements | planned | v0.2 | source / policy | #15 |
| Retry / aggressive probing | 1.2.8 Retry Probing | planned | v0.2 | core (probe engine) | #15 |
| Hysteresis, thresholds, hold time before flip | 1.3.1 | done | v0.1 | scorer | #7 |
| Max improvements cap | 4.8 Core settings | done | v0.1 | core | #7 |
| Improvement retirement / periodic re-probe of improvements | 4.8 Core settings | done | v0.1 | core | #7 |

## Cost / commit

| Capability | IRP doc ref | Status | Milestone | Plugin kind | Issue |
|---|---|---|---|---|---|
| SNMP interface bandwidth collection | 3.13.9 SNMP hosts | planned | v0.2 | telemetry (`snmp`, new kind) | #17 |
| 95th percentile tracking (separate / greater-of modes, billing day) | 1.3.3, 4.15 | planned | v0.2 | telemetry | #17 |
| Outbound commit control (keep providers under commit) | 1.3.3 Commit Control | planned | v0.2 | scorer (`commit`) | #18 |
| Provider groups and load balancing in group | 4.15 group_loadbalance | planned | v0.2 | scorer | #18 |
| Provider precedence / last-resort provider | 4.15 precedence | planned | v0.2 | scorer | #18 |
| Cost optimization mode (cheapest provider meeting a performance floor) | 1.3.2 Cost optimization | planned | v0.2 | scorer (`cost`) | #19 |
| Precedence rules performance vs cost | 1.3.2 | planned | v0.2 | scorer | #19 |
| Global commit across POPs | 3.12 Global Commit | planned | v0.4 | core (multi-instance) | #30 |

## Inbound

| Capability | IRP doc ref | Status | Milestone | Plugin kind | Issue |
|---|---|---|---|---|---|
| Inbound commit control (bandwidth) | 1.2.17, 3.6.1 | planned | v0.3 | announcer (inbound) | #25 |
| Inbound performance optimization (prepends, provider TE communities, selective announcements) | 1.2.18, 3.6.2 | planned | v0.3 | announcer (inbound) | #25 |
| Inertia damping, automated vs moderated inbound improvements | 1.2.18 | planned | v0.3 | announcer (inbound) + suggest mode | #25 |

## Transit

| Capability | IRP doc ref | Status | Milestone | Plugin kind | Issue |
|---|---|---|---|---|---|
| Optimization of transiting traffic | 1.2.22 | planned | v0.3 | source + scorer | #29 |

## Policies

| Capability | IRP doc ref | Status | Milestone | Plugin kind | Issue |
|---|---|---|---|---|---|
| Operating modes: non-intrusive / intrusive (observe / suggest / inject) | 1.2.4 Operating modes | done | v0.1 | core (config) | #1 |
| Allow / deny / static provider / VIP policies by prefix | 1.2.9, 3.7 Routing Policies | planned | v0.2 | scorer (policy filter) | #20 |
| Policies by ASN | 3.7 | planned | v0.2 | scorer (policy filter) | #20 |
| Policies by country (GeoIP) | 3.7 | planned | v0.2 | scorer (policy filter) | #20 |
| Provider exclusions | 4.15 cc_disable, 3.7 | done | v0.1 | scorer | #7 |
| Maintenance windows | 1.2.21, 3.19 | planned | v0.2 | scorer (policy filter) | #20 |
| Inject allowlist (Packeteer safety addition) | - | done | v0.1 | core + announcer | #7, #8 |

## BGP

| Capability | IRP doc ref | Status | Milestone | Plugin kind | Issue |
|---|---|---|---|---|---|
| iBGP injection with local-pref, communities, next-hop | 1.2.2 Bgpd | done | v0.1 | announcer (`gobgp`) | #8 |
| More-specific injection | 2.9 Bgpd | done | v0.1 | announcer (`gobgp`) | #8 |
| RIB view from iBGP (learn current best exits) | 2.9 Bgpd | done | v0.1 | core (`internal/rib`) | #6 |
| BGP session health and automatic withdraw (no stale intent) | 2.9 | done | v0.1 | announcer | #8 |
| AS-path behavior options | 2.9.1 | planned | v0.3 | announcer | #27 |
| BGP additional paths (add-path) | 2.9.3 | planned | v0.3 | RIB source | #26 |
| BMP monitoring (incl. inactive IX paths) | 1.2.5, 2.10 | planned | v0.3 | RIB source (`bmp`) | #26 |
| Multiple edge routers | 1.2.2 | planned | v0.3 | announcer | #27 |
| Centralized route reflector support | 1.2.10 | planned | v0.3 | announcer | #27 |
| Internet exchanges / many peers with per-peer next-hop | 1.2.11, 3.4.6 | planned | v0.3 | announcer + RIB | #27 |
| Bgpd online reconfiguration | 2.9.2 | planned | v0.3 | announcer | #27 |

## Multi-POP

| Capability | IRP doc ref | Status | Milestone | Plugin kind | Issue |
|---|---|---|---|---|---|
| Multiple routing domains with inter-DC RTT | 1.2.12, 4.21 | planned | v0.4 | core | #30 |
| Central management of many instances (GMI) | 1.4 | planned | v0.4 | core + UI | #30 |

## Security

| Capability | IRP doc ref | Status | Milestone | Plugin kind | Issue |
|---|---|---|---|---|---|
| RTBH (BGP blackholing) | 2.11.1 | planned | v0.3 | announcer (mitigation) | #28 |
| BGP redirect | 2.11.2 | planned | v0.3 | announcer (mitigation) | #28 |
| FlowSpec drop / rate-limit (throttle) / redirect | 1.2.19, 1.2.20, 2.11.3-4 | planned | v0.3 | announcer (flowspec) | #28 |
| FlowSpec policies by country | 3.8.1 | planned | v0.3 | announcer (flowspec) + GeoIP | #28 |
| Threat mitigation monitor, rules, feed, history | 1.2.24, 3.10 | planned | v0.3 | announcer (mitigation) + UI | #28 |
| Automatic traffic anomaly (DDoS) detection | 1.2.25, 2.12, 3.11 | planned | v0.4 | source (detector) | #33 |

## Ops

| Capability | IRP doc ref | Status | Milestone | Plugin kind | Issue |
|---|---|---|---|---|---|
| Web UI dashboard (providers, per-prefix metrics, current vs recommended, improvements) | 3.3 Dashboards | planned | v0.1 | core (`internal/httpapi`) | #9 |
| Custom dashboards / widgets | 3.3.1-3.3.3 | planned | v0.4 | UI | #34 |
| REST API | 1.2.15, 4.3 | planned | v0.1 | core | #9 |
| Prometheus metrics | - | planned | v0.1 | core (exporter later) | #9 |
| Reports: improvements, before/after latency/loss, provider efficiency, top prefixes/ASNs, country stats, cost savings | 3.4, 3.5 | planned | v0.2 | storage/exporter | #23 |
| Historical records / storage | 3.4.7 | planned | v0.2 | storage/exporter | #23 |
| Looking glass, traceroute, whois, manual prefix probe | 3.9 | planned | v0.2 | core + prober | #24 |
| Alerts: email | 3.14.5 Senders, 3.17 | planned | v0.2 | notifier (`smtp`) | #22 |
| Alerts: webhook (Slack/Teams/SMS gateways) | 3.17.3 | done | v0.1 | notifier (`webhook`) | #13 |
| Alerts: SNMP traps | 3.17.2 | planned | v0.2 | notifier (`snmptrap`) | #22 |
| Event catalog and notification rules | 1.2.14, 3.16, 3.17.1 | planned | v0.2 | notifier | #22 |
| Email report subscriptions | 3.15 | planned | v0.4 | notifier + storage | #34 |
| User accounts, RBAC, access restriction | 3.14.2, 3.14.3 | planned | v0.4 | core (HTTP auth) | #32 |
| Audit log | - | planned | v0.4 | core + notifier | #32 |
| Failover / HA (active-standby) | 1.2.16, 2.14 | planned | v0.4 | core | #31 |
| Config backup / restore | 2.14 | planned | v0.4 | core | #31 |
| Configuration editor and setup wizards | 3.13, 3.2 | planned | v0.4 | UI | #34 |
| Improvement weights | 1.2.13 | planned | v0.4 | scorer | #34 |
| Structured logging | - | planned | v0.1 | core | #9 |

## Deployment

| Capability | IRP doc ref | Status | Milestone | Plugin kind | Issue |
|---|---|---|---|---|---|
| Single-container install (Docker, multi-arch GHCR image) | 1.2.3 Technical requirements | done | v0.1 | - | #4 |
| Plugin system (in-process + exec + webhook) | - | done | v0.1 | all kinds | #13 |
| Simulated-router e2e lab | - | done | v0.1 | - | #10 |
| Software management / upgrades via package manager | 2.1 | won't do (Replaced by container images and tags; upgrade = pull a new tag.) | - | - | - |
| IRP Lite (feature-restricted free edition) | - | won't do (Packeteer is fully open source; there are no editions.) | - | - | - |
| NOC-as-a-service, Tier 1 reports, training | - | won't do (Commercial services, not software features.) | - | - | - |

## Maintaining this file

Update the status in the same PR that changes it. New IRP capabilities discovered later get a row and an issue in the right milestone.
