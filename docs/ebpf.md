# eBPF data path

Optional, off by default (#229). Two small tc programs, loaded by the controller itself with a pure Go loader (cilium/ebpf). There is no C source, no compiler at run time, and no BTF or CO-RE relocation: the programs are assembled in `internal/ebpfpath` and read only `__sk_buff`, whose layout is stable kernel UAPI. They never drop, edit, or redirect a packet and return `TCX_NEXT`. Nothing here announces a route.

| Where | Turn on | What the kernel does |
|---|---|---|
| `span` source | `ebpf: true` | Copies the first 128 bytes of every TCP frame, both directions, into a 4 MiB ring buffer. The source reads that instead of an AF_PACKET socket, and the same tracker scores retransmissions, resets, timeouts, and handshake RTT. Other traffic never leaves the kernel. |
| `flow` source | `ebpf: {interface: eth0}` | Counts bytes and packets of every IP packet leaving the interface, per source, destination, and protocol, in an LRU per-CPU hash map. Nothing is sampled. The source reads the map once a second and counts the growth in the same window as NetFlow, IPFIX, and sFlow. Bytes are IP bytes, as in NetFlow. |

The flow collector sees traffic of the host it runs on. Where a router samples 1 packet in 1000, a burst of 40 packets may produce no sample at all; the collector counts all 40. Use it beside router exports, or in place of them on a Linux edge host.

## Requirements and fallback

- Linux 6.6 or newer (TCX attach), `CAP_BPF` and `CAP_NET_ADMIN`, plus `CAP_PERFMON` where the kernel asks for it, and `CAP_NET_RAW` when `span` uses promiscuous mode (the program holds an AF_PACKET membership that the kernel drops when the process dies). Example: `--cap-add BPF --cap-add NET_ADMIN --cap-add PERFMON --cap-add NET_RAW`. A container runtime whose seccomp profile blocks `bpf(2)` makes loading fail.
- An Ethernet interface (or `lo`). A tun device has no Ethernet header and is refused. Frames with an in-band VLAN tag are not parsed; use the VLAN sub-interface or a NIC that strips the tag.
- `span`: if the program cannot load, it logs `span eBPF path unavailable, using AF_PACKET` and opens the AF_PACKET socket as before. Startup fails only if that also fails.
- `flow`: if it cannot load, it logs `flow eBPF collector unavailable` and keeps its `listen` collectors. With no `listen`, the source has no input until the cause is fixed.
- The kernel detaches the programs when the process exits, however it exits. GRO or LRO on the interface merge segments before tc sees them; the AF_PACKET path sees the same merged frames.
- Ring buffer overflows are counted in `packeteer_truncated_total{limit="ebpf_ring_full"}`. The flow table is capped by `max_entries`; the kernel evicts the least recently used flow.

Not done: the programs do not track TCP state or RTT in the kernel, and they do not match probe replies. The userspace tracker does both from the frame heads, so `span` results are those of the raw-socket path.

## Lab tests and CPU per Gbit

CI runs these as root on a veth pair (`.github/workflows/ci.yml`, step "eBPF data path"): the same frames give the same `span` counts on both paths, a tun device falls back, and a 40-packet burst that a 1:1000 sampler cannot export is counted exactly by the flow collector. Run them yourself on a Linux 6.6 host:

```
go test -c -o span.test ./internal/plugins/source/span/
sudo ./span.test -test.run EBPF -test.v
```

`TestEBPFCPUPerGbit` sends 200,000 frames of 1,514 bytes through each path and logs the process CPU above a no-capture baseline, per Gbit. The numbers depend on the machine; read them from the CI log or your own run.
