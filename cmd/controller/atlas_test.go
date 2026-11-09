package main

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/GrandArcher/Packeteer/internal/atlas"
	"github.com/GrandArcher/Packeteer/internal/policy"
	"github.com/GrandArcher/Packeteer/internal/probe"
)

func TestMoveTestAddr(t *testing.T) {
	p := netip.MustParsePrefix("198.51.100.0/24")
	results := []probe.Result{
		{Provider: "transit-a", Prefix: p, Target: netip.MustParseAddr("198.51.100.7")},
		{Provider: "transit-b", Prefix: p, Target: netip.MustParseAddr("198.51.100.9")},
		{Provider: "transit-b", Prefix: netip.MustParsePrefix("203.0.113.0/24"), Target: netip.MustParseAddr("203.0.113.1")},
		{Provider: "transit-c", Prefix: p},
	}
	if a, ok := moveTestAddr(results, p, "transit-b"); !ok || a.String() != "198.51.100.9" {
		t.Errorf("provider address = %v %v", a, ok)
	}
	if a, ok := moveTestAddr(results, p, "transit-c"); !ok || a.String() != "198.51.100.7" {
		t.Errorf("fallback address = %v %v", a, ok)
	}
	if _, ok := moveTestAddr(results, netip.MustParsePrefix("192.0.2.0/24"), "transit-a"); ok {
		t.Error("an address for an unmeasured prefix")
	}
}

type atlasCalls struct {
	mu      sync.Mutex
	targets []string
}

func (c *atlasCalls) handler(w http.ResponseWriter, r *http.Request) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if r.Method == http.MethodPost && r.URL.Path == "/measurements/" {
		b, _ := io.ReadAll(r.Body)
		c.targets = append(c.targets, string(b))
		_, _ = w.Write([]byte(`{"measurements":[99]}`))
		return
	}
	_, _ = w.Write([]byte(`{}`))
}

func (c *atlasCalls) bodies() []string {
	c.mu.Lock()
	defer c.mu.Unlock()
	return append([]string(nil), c.targets...)
}

func TestAtlasAfterMoves(t *testing.T) {
	calls := &atlasCalls{}
	ts := httptest.NewServer(http.HandlerFunc(calls.handler))
	defer ts.Close()
	a := atlas.New(atlas.Config{Enabled: true, AfterMove: true, AfterMoveDelay: time.Nanosecond, BaseURL: ts.URL, StateFile: t.TempDir() + "/atlas.json"}, "fake-key-value", "test", nil)

	p := netip.MustParsePrefix("198.51.100.0/24")
	q := netip.MustParsePrefix("203.0.113.0/24")
	r := netip.MustParsePrefix("192.0.2.0/24")
	results := []probe.Result{
		{Provider: "transit-b", Prefix: p, Target: netip.MustParseAddr("198.51.100.9")},
		{Provider: "transit-b", Prefix: q, Target: netip.MustParseAddr("203.0.113.9")},
		{Provider: "transit-b", Prefix: r, Target: netip.MustParseAddr("192.0.2.9")},
	}
	changes := []policy.Change{
		{Action: policy.ActionImprove, New: policy.Improvement{Prefix: p, Provider: "transit-b"}},
		{Action: policy.ActionKeep, New: policy.Improvement{Prefix: q, Provider: "transit-b"}},
		{Action: policy.ActionRetire, Old: policy.Improvement{Prefix: q, Provider: "transit-b"}},
		// Decided but not on the wire (not allowlisted, or observe): no measurement.
		{Action: policy.ActionSwitch, New: policy.Improvement{Prefix: r, Provider: "transit-b"}},
	}
	atlasAfterMoves(a, func(x netip.Prefix) bool { return x == p || x == q }, changes, results)

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { a.Run(ctx); close(done) }()
	deadline := time.Now().Add(5 * time.Second)
	for len(calls.bodies()) == 0 && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	cancel()
	<-done

	got := calls.bodies()
	if len(got) != 1 || !strings.Contains(got[0], `"target":"198.51.100.9"`) || !strings.Contains(got[0], `"is_oneoff":true`) {
		t.Fatalf("measurements created: %v", got)
	}
	recs := a.Records(p)
	if len(recs) != 1 || recs[0].Trigger != atlas.TriggerMove || recs[0].Provider != "transit-b" {
		t.Errorf("records = %+v", recs)
	}
	if len(a.Records(q))+len(a.Records(r)) != 0 {
		t.Error("a prefix that did not move was measured")
	}
}

func TestAtlasAfterMovesOffMakesNothing(t *testing.T) {
	p := netip.MustParsePrefix("198.51.100.0/24")
	changes := []policy.Change{{Action: policy.ActionImprove, New: policy.Improvement{Prefix: p, Provider: "transit-b"}}}
	results := []probe.Result{{Provider: "transit-b", Prefix: p, Target: netip.MustParseAddr("198.51.100.9")}}
	// Off and no key both ignore the move before looking at the router.
	for name, a := range map[string]*atlas.Client{
		"nil":      nil,
		"disabled": atlas.New(atlas.Config{}, "k", "test", nil),
		"no key":   atlas.New(atlas.Config{Enabled: true, AfterMove: true, StateFile: t.TempDir() + "/a.json"}, "", "test", nil),
	} {
		called := false
		atlasAfterMoves(a, func(netip.Prefix) bool { called = true; return true }, changes, results)
		if called {
			t.Errorf("%s: the injected check ran", name)
		}
	}
}
