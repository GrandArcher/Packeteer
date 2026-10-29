package main

import (
	"errors"
	"fmt"
	"os"
	"slices"
	"strconv"
	"strings"

	"github.com/osrg/gobgp/v3/pkg/packet/bgp"
)

// A simulated real-table run (#103) learns the real table and gives it
// probe results from Packeteer's sim prober: no packet is sent. The routes
// below are the model, one per provider next hop. Rtt is the round trip a
// destination at the middle of the spread sees, in milliseconds; spread is
// how far each destination's RTT moves from it, in percent; jitter is the
// per-reply move in milliseconds; loss is the per-packet loss in percent.
// Every probe figure the run reports is simulated, and the report says so.
type simRoute struct {
	name, kind string
	asn        uint32
	cost       float64 // per Mbps, one currency for all
	commitMbps float64 // 0: no commit
	usageMbps  float64
	rtt        float64
	spread     float64
	jitter     float64
	loss       float64
}

var simRoutes = [maxViews]simRoute{
	{name: "transit-a", kind: "transit", asn: 64496, cost: 4, commitMbps: 2000, usageMbps: 900, rtt: 38, spread: 60, jitter: 2, loss: 0.4},
	{name: "transit-b", kind: "transit", asn: 64497, cost: 6, commitMbps: 1000, usageMbps: 400, rtt: 30, spread: 60, jitter: 2, loss: 0.8},
	{name: "ix-peer", kind: "peer", asn: 64498, cost: 0.5, rtt: 22, spread: 70, jitter: 3, loss: 1.5},
}

// simSeed fixes every simulated answer, so two runs of a profile agree.
const simSeed = 103

// simProber is the probers block: the sim prober with each route's model
// on both families' providers.
func simProber() string {
	var b strings.Builder
	fmt.Fprintf(&b, "probers:\n  - type: sim\n    config:\n      seed: %d\n      routes:\n", simSeed)
	for _, r := range simRoutes {
		for _, name := range []string{r.name, r.name + "6"} {
			fmt.Fprintf(&b, "        - {provider: %s, rtt_ms: %v, spread_pct: %v, jitter_ms: %v, loss_pct: %v}\n", name, r.rtt, r.spread, r.jitter, r.loss)
		}
	}
	return b.String()
}

// simTelemetry fills the commit field of the providers that have one, so
// the Providers and Commit pages have values to show. The usage is a lab
// figure and not a measurement either.
func simTelemetry() string {
	var b strings.Builder
	b.WriteString("telemetry:\n  - type: fixed\n    config:\n      providers:\n")
	for _, r := range simRoutes {
		if r.commitMbps > 0 {
			fmt.Fprintf(&b, "        - {name: %s, commit_mbps: %v, usage_mbps: %v}\n", r.name, r.commitMbps, r.usageMbps)
		}
	}
	return b.String()
}

// maxVIPASNs bounds the vip source's asns list in the generated config.
const maxVIPASNs = 4000

// vipASNs picks the origin ASNs for the vip source: the ones with the most
// routes in the first view, leaving out any that alone holds more than a
// quarter of want, until they cover one and a half times want routes. The
// source stops at max_targets, so a few ASNs would do, but a wide list
// spreads the probed prefixes over many origins. The list goes only into
// the generated config in the run's temporary directory.
func vipASNs(t *realSet, want int) ([]uint32, error) {
	v := t.views[0]
	origin := make([]uint32, len(v.sets))
	for i, set := range v.sets {
		origin[i] = originAS(set)
	}
	count := map[uint32]int{}
	for _, e := range v.entries {
		if as := origin[e.set]; as != 0 {
			count[as]++
		}
	}
	asns := make([]uint32, 0, len(count))
	for as, n := range count {
		if n <= want/4 {
			asns = append(asns, as)
		}
	}
	slices.SortFunc(asns, func(a, b uint32) int {
		if count[a] != count[b] {
			return count[b] - count[a]
		}
		return int(a) - int(b)
	})
	var out []uint32
	for covered, i := 0, 0; i < len(asns) && covered < want*3/2 && len(out) < maxVIPASNs; i++ {
		out = append(out, asns[i])
		covered += count[asns[i]]
	}
	if len(out) == 0 {
		return nil, errors.New("no origin AS small enough to name in the vip source")
	}
	slices.Sort(out)
	return out, nil
}

// originAS is the last AS of a set's AS_PATH when that path ends in an
// AS_SEQUENCE, else 0.
func originAS(set []bgp.PathAttributeInterface) uint32 {
	for _, a := range set {
		p, ok := a.(*bgp.PathAttributeAsPath)
		if !ok || len(p.Value) == 0 {
			continue
		}
		last, ok := p.Value[len(p.Value)-1].(*bgp.As4PathParam)
		if !ok || last.Type != bgp.BGP_ASPATH_ATTR_TYPE_SEQ || len(last.AS) == 0 {
			continue
		}
		return last.AS[len(last.AS)-1]
	}
	return 0
}

// echoesSent is how many ICMP echo requests the host has sent, IPv4 and
// IPv6, from procfs. A simulated run sends none, so the count must not
// move; any host traffic that pings would show here too, which is why the
// run is for an otherwise idle lab host. IPv6 counters are optional (a host
// with IPv6 off has no snmp6 file).
func echoesSent(procRoot string) (uint64, error) {
	b, err := os.ReadFile(procRoot + "/net/snmp")
	if err != nil {
		return 0, err
	}
	n, err := snmpCounter(string(b), "Icmp:", "OutEchos")
	if err != nil {
		return 0, err
	}
	if b6, err := os.ReadFile(procRoot + "/net/snmp6"); err == nil {
		for line := range strings.Lines(string(b6)) {
			if f := strings.Fields(line); len(f) == 2 && f[0] == "Icmp6OutEchos" {
				v, err := strconv.ParseUint(f[1], 10, 64)
				if err != nil {
					return 0, err
				}
				n += v
			}
		}
	}
	return n, nil
}

// echoFault says what is wrong when the host's echo counter is not before,
// or "".
func echoFault(procRoot string, before uint64) string {
	now, err := echoesSent(procRoot)
	switch {
	case err != nil:
		return fmt.Sprintf("cannot read the ICMP echo counter after a simulated run: %v", err)
	case now != before:
		return fmt.Sprintf("ICMP echo requests sent by the host moved from %d to %d during a simulated run: no probe may leave the lab", before, now)
	}
	return ""
}

// snmpCounter reads one column of /proc/net/snmp: a header line names the
// columns of the line after it.
func snmpCounter(s, proto, name string) (uint64, error) {
	var names []string
	for line := range strings.Lines(s) {
		f := strings.Fields(line)
		if len(f) == 0 || f[0] != proto {
			continue
		}
		if names == nil {
			names = f[1:]
			continue
		}
		for j, n := range names {
			if n == name && j+1 < len(f) {
				return strconv.ParseUint(f[j+1], 10, 64)
			}
		}
		break
	}
	return 0, fmt.Errorf("snmp: %s %s missing", proto, name)
}
