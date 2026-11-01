package config

import (
	"net/netip"
	"strings"
	"time"

	"github.com/GrandArcher/Packeteer/internal/probe"
	"github.com/GrandArcher/Packeteer/internal/twamp"
)

// Reordering measurement defaults and bounds (#224).
const (
	DefaultReorderPackets = 20
	MaxReorderPackets     = 200
	DefaultReorderSpacing = 20 * time.Millisecond
	MinReorderSpacing     = time.Millisecond
	MaxReorderSpacing     = time.Second
	MaxReorderTimeout     = 30 * time.Second
	MinReorderInterval    = time.Second
	DefaultReorderFlows   = 4
	MaxReorderFlows       = 16
	MaxReorderResponders  = 64
)

// ProbeReorder measures packet reordering per provider path (RFC 4737)
// with trains of sequence-numbered packets toward responders the operator
// names. Omitted leaves it off. Measurement only: a reading enters the
// score only through a scorer's reorder_weight, and an icmp estimate
// never does.
type ProbeReorder struct {
	// Packets is the train length and Spacing the gap between its
	// packets. Reordering closer than Spacing is not visible.
	Packets int           `yaml:"packets"`
	Spacing time.Duration `yaml:"spacing"`
	// Timeout is how long the last packet's reply is waited for. Zero
	// uses probe.timeout.
	Timeout time.Duration `yaml:"timeout"`
	// Interval is the time between measurements. Zero uses
	// probe.interval. The longest gap between two readings of one
	// provider and responder (see reorderCycle) must fit in three times
	// probe.interval, inside the window after which a reading is stale.
	Interval time.Duration `yaml:"interval"`
	// Flows is how many trains, each from its own source port, go to a
	// twamp responder per measurement, so an ECMP bundle's members are
	// sampled. A train never changes its 5-tuple.
	Flows      int                `yaml:"flows"`
	Responders []ReorderResponder `yaml:"responders"`
}

// ReorderResponder is one host the trains are sent to from every
// provider. Type twamp (the default) is a TWAMP-Light reflector (RFC 5357)
// on Port; icmp is any host that answers echo, whose reading is an
// estimate.
type ReorderResponder struct {
	Address string `yaml:"address"`
	Port    int    `yaml:"port"`
	Type    string `yaml:"type"`
}

func (c *Config) defaultReorder() {
	r := c.Probe.Reorder
	if r == nil {
		return
	}
	if r.Packets == 0 {
		r.Packets = DefaultReorderPackets
	}
	if r.Spacing == 0 {
		r.Spacing = DefaultReorderSpacing
	}
	if r.Timeout == 0 {
		r.Timeout = c.Probe.Timeout
	}
	if r.Interval == 0 {
		r.Interval = c.Probe.Interval
	}
	if r.Flows == 0 {
		r.Flows = DefaultReorderFlows
	}
	for i := range r.Responders {
		rr := &r.Responders[i]
		rr.Type = strings.ToLower(strings.TrimSpace(rr.Type))
		if rr.Type == "" {
			rr.Type = probe.ResponderTWAMP
		}
		if rr.Type == probe.ResponderTWAMP && rr.Port == 0 {
			rr.Port = twamp.DefaultPort
		}
	}
}

func (c *Config) validateReorder(add func(string, ...any)) {
	r := c.Probe.Reorder
	if r == nil {
		return
	}
	if r.Packets < 2 || r.Packets > MaxReorderPackets {
		add("probe.reorder.packets %d must be between 2 and %d", r.Packets, MaxReorderPackets)
	}
	if r.Spacing < MinReorderSpacing || r.Spacing > MaxReorderSpacing {
		add("probe.reorder.spacing %s must be between %s and %s", r.Spacing, MinReorderSpacing, MaxReorderSpacing)
	}
	if r.Timeout < time.Millisecond || r.Timeout > MaxReorderTimeout {
		add("probe.reorder.timeout %s must be between 1ms and %s", r.Timeout, MaxReorderTimeout)
	}
	if window := 3 * c.Probe.Interval; r.Interval < MinReorderInterval || (window > 0 && r.Interval > window) {
		add("probe.reorder.interval %s must be between %s and three times probe.interval (%s)", r.Interval, MinReorderInterval, window)
	}
	if r.Flows < 1 || r.Flows > MaxReorderFlows {
		add("probe.reorder.flows %d must be between 1 and %d", r.Flows, MaxReorderFlows)
	}
	// A measurement starts every interval, or when the last one ends if
	// that is later, and a reading may come early in one and late in the
	// next.
	if window, cycle := 3*c.Probe.Interval, c.reorderCycle(); window > 0 && max(r.Interval, cycle)+cycle > window {
		add("probe.reorder: one measurement of every provider and responder can take %s, so a reading can wait %s to be replaced, more than three times probe.interval (%s); lower flows, packets, timeout, or responders, or raise probe.interval",
			cycle, max(r.Interval, cycle)+cycle, window)
	}
	if len(r.Responders) == 0 {
		add("probe.reorder.responders must list at least one responder")
	}
	if len(r.Responders) > MaxReorderResponders {
		add("probe.reorder.responders lists %d responders, at most %d", len(r.Responders), MaxReorderResponders)
	}
	excluded := c.Probe.Exclude.PrefixList()
	seen := map[ReorderResponder]bool{}
	for i, rr := range r.Responders {
		key := func(format string, a ...any) {
			add("probe.reorder.responders[%d]: "+format, append([]any{i}, a...)...)
		}
		addr, err := netip.ParseAddr(rr.Address)
		if err != nil || addr.Zone() != "" {
			key("address %q is not a valid IP address", rr.Address)
			continue
		}
		switch rr.Type {
		case probe.ResponderTWAMP:
			if rr.Port < 1 || rr.Port > 65535 {
				key("port %d must be between 1 and 65535", rr.Port)
			}
		case probe.ResponderICMP:
			if rr.Port != 0 {
				key("port is not used by an icmp responder")
			}
		default:
			key("type %q is invalid (want twamp or icmp)", rr.Type)
		}
		for _, p := range excluded {
			if p.Contains(addr) {
				key("address %s is inside probe.exclude prefix %s", addr, p)
				break
			}
		}
		if seen[rr] {
			key("duplicate of an earlier responder")
		}
		seen[rr] = true
	}
}

// reorderCycle is the longest one measurement of every local provider and
// responder takes when no reply comes back: the trains run one after
// another, each packets*spacing plus timeout, and their packets wait on
// rate_limit_pps, or on per_asn_pps when set (at most rate_limit_pps; as
// if every responder had one origin ASN). Probe engine packets on the same
// budget can still delay it.
func (c *Config) reorderCycle() time.Duration {
	r := c.Probe.Reorder
	perProvider := 0
	for _, rr := range r.Responders {
		if rr.Type == probe.ResponderICMP {
			perProvider++
		} else {
			perProvider += r.Flows
		}
	}
	trains := 0
	for _, p := range c.Providers {
		if c.LocalProbe(p) {
			trains += perProvider
		}
	}
	cycle := time.Duration(trains) * (time.Duration(r.Packets)*r.Spacing + r.Timeout)
	pps := c.Probe.RateLimitPPS
	if c.Probe.PerASNPPS > 0 {
		pps = c.Probe.PerASNPPS
	}
	if pps > 0 {
		cycle += time.Duration(trains*r.Packets) * time.Second / time.Duration(pps)
	}
	return cycle
}
