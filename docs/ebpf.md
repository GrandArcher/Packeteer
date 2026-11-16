# eBPF data path

Optional, off by default (#229, #631). Small tc programs, loaded by the controller itself with a pure Go loader (cilium/ebpf). There is no C source, no compiler at run time, and no BTF or CO-RE relocation: the programs are assembled in `internal/ebpfpath` and read only `__sk_buff`, whose layout is stable kernel UAPI. They never drop, edit, or redirect a packet and return `TCX_NEXT`. Nothing here announces a route.

| Where | Turn on | What the kernel does |
|---|---|---|
| `span` source | `ebpf: true` | Copies the first 128 bytes of every TCP frame, both directions, into a 4 MiB ring buffer. The source reads that instead of an AF_PACKET socket, and the same tracker scores retransmissions, resets, timeouts, and handshake RTT. Other traffic never leaves the kernel. |
| `span` source, kernel tracker | `ebpf: true` and `ebpf_track: true` | Follows every TCP connection in the kernel instead of copying frames (#631). See below. |
| `flow` source | `ebpf: {interface: eth0}` | Counts bytes and packets of every IP packet leaving the interface, per source, destination, and protocol, in an LRU per-CPU hash map. Nothing is sampled. The source reads the map once a second and counts the growth in the same window as NetFlow, IPFIX, and sFlow. Bytes are IP bytes, as in NetFlow. |

## Kernel-side tracking (`ebpf_track`)

With `ebpf_track: true` (it needs `ebpf: true`) a tc program does what the userspace span tracker does with frame heads, and the frame-copying capture program is not loaded. It parses Ethernet, IPv4, and IPv6 headers, tells the local end of a connection with an LPM trie of the `local` prefixes, and keeps one entry per connection in a hash map capped by `max_flows`: the next expected sequence number, the pending SYN or SYN-ACK, and running counts of outbound data segments, retransmissions, remote resets, and handshake RTT. Retransmissions and sequence wrap follow the userspace rules, including the one-byte keepalive exception. A handshake RTT is taken only when the handshake was not retransmitted and was answered inside `syn_timeout`.

The kernel hands a connection's counts to userspace through a 1 MiB ring buffer record of 96 bytes: when a connection is first seen, on a retransmission, a handshake RTT, a RST, a FIN, and at most once a second while it keeps sending. The counts only grow, so the source scores the difference from the last counts it saw, from the ring and from a read of the connection table. The source keeps one small entry per connection for that. The source still does the parts that need the RIB view or a timer: the remote filter and prefix mapping (the same as without `ebpf_track`), counting handshake timeouts (each pending SYN or SYN-ACK once, when the table is read at the start of a probe round), and removing connections idle for `flow_idle` from the table after scoring their last counts. The scorer is unchanged.

Differences from the userspace tracker: IPv6 packets with extension headers and VLAN-tagged frames are not tracked (the userspace tracker parses both); packets of one connection on different CPUs are not ordered, so a race can misjudge one segment; a connection past `max_flows` is counted in `packeteer_truncated_total{limit="max_flows"}` as before.

If the program cannot load (kernel older than 6.6, missing `BPF` or `NET_ADMIN`, a tun device, a blocked `bpf(2)`), the source logs `span eBPF tracker unavailable, tracking in userspace` and continues with the ring buffer capture and the userspace tracker, then AF_PACKET if that fails too. With `ebpf_track` off, nothing in this section loads.

## Flow collector

The flow collector sees traffic of the host it runs on. Where a router samples 1 packet in 1000, a burst of 40 packets may produce no sample at all; the collector counts all 40. Use it beside router exports, or in place of them on a Linux edge host.

## Requirements and fallback

- Linux 6.6 or newer (TCX attach), `CAP_BPF` and `CAP_NET_ADMIN`, plus `CAP_PERFMON` where the kernel asks for it, and `CAP_NET_RAW` when `span` uses promiscuous mode (the program holds an AF_PACKET membership that the kernel drops when the process dies). Example: `--cap-add BPF --cap-add NET_ADMIN --cap-add PERFMON --cap-add NET_RAW`. A container runtime whose seccomp profile blocks `bpf(2)` makes loading fail.
- An Ethernet interface (or `lo`). A tun device has no Ethernet header and is refused. Frames with an in-band VLAN tag are not parsed; use the VLAN sub-interface or a NIC that strips the tag.
- `span`: if the program cannot load, it logs `span eBPF path unavailable, using AF_PACKET` and opens the AF_PACKET socket as before. Startup fails only if that also fails.
- `flow`: if it cannot load, it logs `flow eBPF collector unavailable` and keeps its `listen` collectors. With no `listen`, the source has no input until the cause is fixed.
- The kernel detaches the programs when the process exits, however it exits. GRO or LRO on the interface merge segments before tc sees them; the AF_PACKET path sees the same merged frames.
- Ring buffer overflows are counted in `packeteer_truncated_total{limit="ebpf_ring_full"}`. The flow table is capped by `max_entries`; the kernel evicts the least recently used flow.

Not done: probe capture and reply matching still use the probers' own raw sockets; the eBPF path does not replace them. Without `ebpf_track` the programs do not track TCP state; the userspace span tracker does that from the frame heads.

## Lab tests and CPU per Gbit

CI runs these as root on a veth pair (`.github/workflows/ci.yml`, step "eBPF data path"): the same frames give the same `span` counts on both paths, a tun device falls back, and a 40-packet burst that a 1:1000 sampler model never exports to the `listen` collector is counted exactly by the eBPF collector of the same source. Run them yourself on a Linux 6.6 host:

```
go test -c -o span.test ./internal/plugins/source/span/
sudo ./span.test -test.run EBPF -test.v
```

`TestEBPFCPUPerGbit` sends 200,000 frames of 1,502 bytes through each capture path and logs the process CPU above a no-capture baseline, per Gbit. The numbers depend on the machine; read them from the CI log or your own run.

The kernel tracker has its own tests (`TestEBPFTrack*`). On a veth pair the same paced traffic goes to a userspace-tracking source and a kernel-tracking source: the pcap fixture's IPv4 and IPv6 connections with retransmissions, unanswered SYNs and SYN-ACKs, resets, and ignored noise. Connections, segments, retransmissions, resets, handshake timeouts, and RTT samples must be equal. The handshake RTT average may differ by up to 10 ms; on the lab machine it differed by under 0.1 ms. Other tests cover sequence wrap, `max_flows`, idle expiry, and the fallback. `TestEBPFTrackCPUPerGbit` sends one busy connection (202,000 data segments, 2.4 Gbit) through AF_PACKET with the userspace tracker, the ring buffer with the userspace tracker, and the kernel tracker, and logs CPU per Gbit above sending alone. On an 8-core lab machine in three runs, the process spent about 0.14 to 0.30, 0.22, and 0.02 to 0.04 CPU-seconds per Gbit.
