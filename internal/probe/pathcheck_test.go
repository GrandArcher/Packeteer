package probe

import (
	"context"
	"fmt"
	"net/netip"
	"testing"

	"github.com/GrandArcher/Packeteer/pkg/plugin"
)

func TestSetPathMismatchMarksAndClears(t *testing.T) {
	p := &fakeProber{fn: ok(5, 5, 5)}
	e, _ := New([]Provider{provA}, []NamedProber{{"p", p}},
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
	e, _ := New([]Provider{provA}, []NamedProber{{"p", p}},
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
	e, _ := New([]Provider{provA}, []NamedProber{{"p", p}},
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
	e, _ := New([]Provider{provA}, []NamedProber{{"p", p}}, src(plugin.Target{Prefix: pfx1}), opts())

	e.SetPathMismatch("transit-z", true)
	if st := e.Providers()[0]; !st.Up || st.Reason != "" {
		t.Fatalf("unknown provider changed status: %+v", st)
	}
}
