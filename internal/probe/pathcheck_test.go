package probe

import (
	"context"
	"fmt"
	"net/netip"
	"sync"
	"testing"

	"github.com/GrandArcher/Packeteer/internal/sockmark"
	"github.com/GrandArcher/Packeteer/pkg/plugin"
)

func TestSetPathMismatchMarksAndClears(t *testing.T) {
	p := &fakeProber{fn: ok(5, 5, 5)}
	e, _ := New([]Provider{provA}, []NamedProber{{Name: "p", Prober: p}},
		src(plugin.Target{Prefix: pfx1, Host: netip.MustParseAddr("198.51.100.1")}), opts())

	e.SetPathMismatch("transit-a", true)
	st := e.Providers()[0]
	if st.Up || st.Reason != PathMismatchReason {
		t.Fatalf("mismatch status = %+v", st)
	}
	e.SetPathMismatch("transit-a", false)
	if st := e.Providers()[0]; !st.Up || st.Reason != "" {
		t.Fatalf("cleared status = %+v", st)
	}
}

func TestSetPathMismatchSurvivesGoodRound(t *testing.T) {
	p := &fakeProber{fn: ok(5, 5, 5)}
	e, _ := New([]Provider{provA}, []NamedProber{{Name: "p", Prober: p}},
		src(plugin.Target{Prefix: pfx1, Host: netip.MustParseAddr("198.51.100.1")}), opts())

	e.SetPathMismatch("transit-a", true)
	e.RunOnce(context.Background())
	st := e.Providers()[0]
	if st.Up || st.Reason != PathMismatchReason {
		t.Fatalf("a good round cleared the mismatch: %+v", st)
	}
}

func TestSetPathMismatchKeepsSourceReason(t *testing.T) {
	p := &fakeProber{fn: func(context.Context, plugin.ProbeRequest) (plugin.ProbeResult, error) {
		return plugin.ProbeResult{}, fmt.Errorf("%w: 192.0.2.11", plugin.ErrSourceUnavailable)
	}}
	e, _ := New([]Provider{provA}, []NamedProber{{Name: "p", Prober: p}},
		src(plugin.Target{Prefix: pfx1, Host: netip.MustParseAddr("198.51.100.1")}), opts())

	e.RunOnce(context.Background())
	e.SetPathMismatch("transit-a", false)
	st := e.Providers()[0]
	if st.Up || st.Reason == "" || st.Reason == PathMismatchReason {
		t.Fatalf("source reason lost: %+v", st)
	}
}

func TestSetPathMismatchUnknownProvider(t *testing.T) {
	p := &fakeProber{fn: ok(5, 5, 5)}
	e, _ := New([]Provider{provA}, []NamedProber{{Name: "p", Prober: p}}, src(plugin.Target{Prefix: pfx1}), opts())

	e.SetPathMismatch("transit-z", true)
	if st := e.Providers()[0]; !st.Up || st.Reason != "" {
		t.Fatalf("unknown provider changed status: %+v", st)
	}
}

// Providers that share a source_ip are told apart only by their tag, so
// every probe request must carry its own provider's tag (#157).
func TestProbeRequestsCarryProviderMarking(t *testing.T) {
	var mu sync.Mutex
	seen := map[string]plugin.ProbeRequest{}
	p := &fakeProber{fn: func(_ context.Context, req plugin.ProbeRequest) (plugin.ProbeResult, error) {
		mu.Lock()
		seen[req.Provider] = req
		mu.Unlock()
		return ok(5, 5, 5)(context.Background(), req)
	}}
	shared := netip.MustParseAddr("192.0.2.11")
	provs := []Provider{
		{Name: "ix-a", Source: shared, Marking: sockmark.Marking{Mark: 101, DSCP: 10}},
		{Name: "ix-b", Source: shared, Marking: sockmark.Marking{DSCP: 12}},
		{Name: "plain", Source: netip.MustParseAddr("192.0.2.12")},
	}
	e, err := New(provs, []NamedProber{{Name: "p", Prober: p}},
		src(plugin.Target{Prefix: pfx1, Host: netip.MustParseAddr("198.51.100.1")}), opts())
	if err != nil {
		t.Fatal(err)
	}
	e.RunOnce(context.Background())
	mu.Lock()
	defer mu.Unlock()
	if a := seen["ix-a"]; a.Source != shared || a.Mark != 101 || a.DSCP != 10 {
		t.Errorf("ix-a request = %+v", a)
	}
	if b := seen["ix-b"]; b.Source != shared || b.Mark != 0 || b.DSCP != 12 {
		t.Errorf("ix-b request = %+v", b)
	}
	if c := seen["plain"]; c.Mark != 0 || c.DSCP != 0 {
		t.Errorf("untagged provider request = %+v", c)
	}
}
