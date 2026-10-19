package probe

import (
	"context"
	"net/netip"
	"sync"
	"testing"

	"github.com/GrandArcher/Packeteer/pkg/plugin"
)

func TestOnBatchCarriesEvidenceAndSources(t *testing.T) {
	p := &fakeProber{fn: ok(10, 12, 11)}
	var mu sync.Mutex
	var batch []Result
	o := opts()
	o.OnBatch = func(rs []Result) {
		mu.Lock()
		defer mu.Unlock()
		batch = append(batch, rs...)
	}
	sources := []NamedSource{
		{Name: "static", Source: &fakeSource{targets: []plugin.Target{{Prefix: pfx1, Host: netip.MustParseAddr("198.51.100.9")}}}},
		{Name: "vip", Source: &fakeSource{targets: []plugin.Target{{Prefix: pfx1}, {Prefix: pfx2, Host: netip.MustParseAddr("203.0.113.9")}}}},
	}
	e, err := New([]Provider{provA}, []NamedProber{{Name: "icmp", Prober: p}}, sources, o)
	if err != nil {
		t.Fatal(err)
	}
	e.RunOnce(context.Background())

	mu.Lock()
	defer mu.Unlock()
	if len(batch) != 2 {
		t.Fatalf("batch has %d results, want 2", len(batch))
	}
	for _, r := range batch {
		if r.Share == nil || len(r.Share.Hosts) != 1 {
			t.Fatalf("%s: share = %+v", r.Prefix, r.Share)
		}
		h := r.Share.Hosts[0]
		if h.Sent != 3 || len(h.RTTs) != 3 || h.RTTs[1] != ms(12)[0] {
			t.Errorf("%s: raw = %+v", r.Prefix, h)
		}
		want := []string{"vip"}
		if r.Prefix == pfx1 {
			want = []string{"static", "vip"}
		}
		if len(r.Share.Sources) != len(want) || r.Share.Sources[0] != want[0] || r.Share.Sources[len(want)-1] != want[len(want)-1] {
			t.Errorf("%s: sources = %v, want %v", r.Prefix, r.Share.Sources, want)
		}
	}
	// What the engine stores never keeps the raw samples.
	for _, r := range e.Results() {
		if r.Share != nil {
			t.Errorf("stored result for %s keeps Share", r.Prefix)
		}
	}
}

func TestNoShareWithoutOnBatch(t *testing.T) {
	p := &fakeProber{fn: ok(10, 12, 11)}
	e, err := New([]Provider{provA}, []NamedProber{{Name: "icmp", Prober: p}}, src(plugin.Target{Prefix: pfx1}), opts())
	if err != nil {
		t.Fatal(err)
	}
	e.RunOnce(context.Background())
	if e.keepShare() {
		t.Fatal("engine keeps evidence with no OnBatch")
	}
}
