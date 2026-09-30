package flow

import (
	"net/netip"
	"sync"
	"time"

	"github.com/GrandArcher/Packeteer/pkg/plugin"
)

// counterIdle is how long a key may see no traffic before it is forgotten.
// A reader sees its counter start again from zero.
const counterIdle = time.Hour

type counterKey struct {
	prefix netip.Prefix
	proto  uint8
}

type counter struct {
	bytes uint64
	seen  time.Time
}

// counters sums bytes per destination prefix and IP protocol for the
// anomaly detector (#33). At most max keys are held, so a scan of unique
// destinations cannot grow memory without bound; traffic toward a new key
// past the cap is not counted until idle keys are forgotten.
type counters struct {
	mu   sync.Mutex
	max  int
	keys map[counterKey]*counter
}

func newCounters(max int) *counters {
	return &counters{max: max, keys: map[counterKey]*counter{}}
}

func (c *counters) add(at time.Time, p netip.Prefix, proto uint8, n uint64) {
	if n == 0 || !p.IsValid() {
		return
	}
	k := counterKey{prefix: p.Masked(), proto: proto}
	c.mu.Lock()
	defer c.mu.Unlock()
	e := c.keys[k]
	if e == nil {
		if len(c.keys) >= c.max {
			c.pruneLocked(at)
			if len(c.keys) >= c.max {
				return
			}
		}
		e = &counter{}
		c.keys[k] = e
	}
	e.bytes += n
	if at.After(e.seen) {
		e.seen = at
	}
}

func (c *counters) pruneLocked(now time.Time) {
	for k, e := range c.keys {
		if now.Sub(e.seen) > counterIdle {
			delete(c.keys, k)
		}
	}
}

func (c *counters) snapshot(now time.Time) []plugin.FlowCounter {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.pruneLocked(now)
	out := make([]plugin.FlowCounter, 0, len(c.keys))
	for k, e := range c.keys {
		out = append(out, plugin.FlowCounter{Prefix: k.prefix, Protocol: plugin.IPProtocol(k.proto), Bytes: e.bytes})
	}
	return out
}
