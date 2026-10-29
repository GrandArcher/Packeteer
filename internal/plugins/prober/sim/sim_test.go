package sim

import (
	"context"
	"go/parser"
	"go/token"
	"net/netip"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/GrandArcher/Packeteer/pkg/plugin"
)

const threeRoutes = `
seed: 7
routes:
  - {provider: transit-a, rtt_ms: 40, spread_pct: 50, jitter_ms: 2, loss_pct: 0.5}
  - {provider: transit-b, rtt_ms: 20, spread_pct: 50, jitter_ms: 2, loss_pct: 2}
  - {provider: transit-c, rtt_ms: 80, spread_pct: 10, loss_pct: 25}
`

func newProber(t *testing.T, y string) plugin.Prober {
	t.Helper()
	c, err := plugin.ConfigFromYAML(y)
	if err != nil {
		t.Fatal(err)
	}
	p, err := New(c, plugin.Env{})
	if err != nil {
		t.Fatal(err)
	}
	return p
}

func probe(t *testing.T, p plugin.Prober, provider string, dst netip.Addr, count int) plugin.ProbeResult {
	t.Helper()
	r, err := p.Probe(context.Background(), plugin.ProbeRequest{Provider: provider, Target: dst, Count: count, Timeout: time.Second})
	if err != nil {
		t.Fatal(err)
	}
	return r
}

func addr(i int) netip.Addr {
	return netip.AddrFrom4([4]byte{198, 51, byte(i >> 8), byte(i)})
}

func TestAnswersAreRepeatable(t *testing.T) {
	a, b := newProber(t, threeRoutes), newProber(t, threeRoutes)
	other := newProber(t, strings.Replace(threeRoutes, "seed: 7", "seed: 8", 1))
	moved := false
	for i := range 200 {
		x := probe(t, a, "transit-a", addr(i), 4)
		y := probe(t, b, "transit-a", addr(i), 4)
		if x.Sent != y.Sent || !slices.Equal(x.RTTs, y.RTTs) {
			t.Fatalf("same seed differs for %v: %v vs %v", addr(i), x, y)
		}
		if z := probe(t, other, "transit-a", addr(i), 4); !slices.Equal(x.RTTs, z.RTTs) {
			moved = true
		}
	}
	if !moved {
		t.Fatal("a different seed gave the same answers")
	}
}

func TestRoutesFollowTheirModel(t *testing.T) {
	p := newProber(t, threeRoutes)
	const dests, count = 5000, 4
	for _, tc := range []struct {
		provider     string
		rtt, spread  float64
		jitter, loss float64
	}{
		{"transit-a", 40, 50, 2, 0.5},
		{"transit-b", 20, 50, 2, 2},
		{"transit-c", 80, 10, 0, 25},
	} {
		lost, total := 0, 0
		for i := range dests {
			r := probe(t, p, tc.provider, addr(i), count)
			if r.Sent != count {
				t.Fatalf("%s sent %d", tc.provider, r.Sent)
			}
			lost += count - len(r.RTTs)
			total += count
			for _, d := range r.RTTs {
				ms := float64(d) / float64(time.Millisecond)
				lo := tc.rtt*(1-tc.spread/100) - tc.jitter
				hi := tc.rtt*(1+tc.spread/100) + tc.jitter
				if ms < lo-0.01 || ms > hi+0.01 {
					t.Fatalf("%s rtt %.2f outside %.2f..%.2f", tc.provider, ms, lo, hi)
				}
			}
		}
		got := 100 * float64(lost) / float64(total)
		if got < tc.loss*0.7-0.2 || got > tc.loss*1.3+0.2 {
			t.Fatalf("%s loss %.2f%%, model %.2f%%", tc.provider, got, tc.loss)
		}
	}
}

func TestRoutesWinOnDifferentDestinations(t *testing.T) {
	p := newProber(t, `
seed: 1
routes:
  - {provider: transit-a, rtt_ms: 30, spread_pct: 60}
  - {provider: transit-b, rtt_ms: 30, spread_pct: 60}
`)
	aFaster := 0
	const dests = 2000
	for i := range dests {
		a := probe(t, p, "transit-a", addr(i), 1)
		b := probe(t, p, "transit-b", addr(i), 1)
		if a.RTTs[0] < b.RTTs[0] {
			aFaster++
		}
	}
	if aFaster < dests*40/100 || aFaster > dests*60/100 {
		t.Fatalf("transit-a faster on %d of %d destinations, want about half", aFaster, dests)
	}
}

func TestIPv6AndUnknownProvider(t *testing.T) {
	p := newProber(t, threeRoutes)
	r := probe(t, p, "transit-b", netip.MustParseAddr("2001:db8::53"), 4)
	if r.Sent != 4 || len(r.RTTs) == 0 {
		t.Fatalf("ipv6 result %+v", r)
	}
	if _, err := p.Probe(context.Background(), plugin.ProbeRequest{Provider: "transit-z", Target: addr(1), Count: 4}); err == nil {
		t.Fatal("a provider with no route must fail")
	}
}

func TestConfigIsChecked(t *testing.T) {
	for name, tc := range map[string]struct{ yaml, want string }{
		"no routes":      {"seed: 1", "routes is required"},
		"no provider":    {"routes: [{rtt_ms: 10}]", "provider is required"},
		"duplicate":      {"routes: [{provider: a, rtt_ms: 10}, {provider: a, rtt_ms: 10}]", "duplicate"},
		"zero rtt":       {"routes: [{provider: a}]", "rtt_ms"},
		"spread":         {"routes: [{provider: a, rtt_ms: 10, spread_pct: 101}]", "spread_pct"},
		"jitter":         {"routes: [{provider: a, rtt_ms: 10, jitter_ms: -1}]", "jitter_ms"},
		"loss":           {"routes: [{provider: a, rtt_ms: 10, loss_pct: 101}]", "loss_pct"},
		"unknown key":    {"routes: [{provider: a, rtt_ms: 10, color: red}]", "color"},
		"not a provider": {"routes: [{provider: nope, rtt_ms: 10}]", "not configured"},
	} {
		c, err := plugin.ConfigFromYAML(tc.yaml)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := New(c, plugin.Env{Providers: []string{"a"}}); err == nil || !strings.Contains(err.Error(), tc.want) {
			t.Errorf("%s: err = %v, want %q", name, err, tc.want)
		}
	}
}

// The prober's own source imports nothing that can reach a network or run
// a program, so no packet to a real address can leave through it.
func TestSourceImportsNoNetwork(t *testing.T) {
	f, err := parser.ParseFile(token.NewFileSet(), "sim.go", nil, parser.ImportsOnly)
	if err != nil {
		t.Fatal(err)
	}
	banned := []string{"net", "os", "os/exec", "syscall", "golang.org/x/net", "golang.org/x/sys"}
	for _, im := range f.Imports {
		path, _ := strconv.Unquote(im.Path.Value)
		if slices.Contains(banned, path) || strings.HasPrefix(path, "golang.org/x/net/") {
			t.Errorf("sim.go imports %q", path)
		}
	}
}
