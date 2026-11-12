package pin

import (
	"errors"
	"math"
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/GrandArcher/Packeteer/pkg/plugin"
)

var (
	t0      = time.Date(2026, 11, 11, 12, 0, 0, 0, time.UTC)
	learned = netip.MustParsePrefix("198.51.100.0/24")
	rails   = Rails{
		Providers: []string{"transit-a", "transit-b"},
		Allowlist: []netip.Prefix{netip.MustParsePrefix("198.51.100.0/22"), netip.MustParsePrefix("2001:db8::/32")},
		Learned:   func(p netip.Prefix) bool { return p == learned || p == netip.MustParsePrefix("198.51.101.0/24") },
	}
)

func req(prefix string) Request {
	return Request{Prefix: netip.MustParsePrefix(prefix), Provider: "transit-b", MaxLossPct: 2, MaxRTTMs: 80, Duration: time.Hour, Reason: "lab", By: "noc1"}
}

func TestAddChecksTheRails(t *testing.T) {
	for name, tc := range map[string]struct {
		edit func(*Request)
		want string
	}{
		"no prefix":      {func(r *Request) { r.Prefix = netip.Prefix{} }, "prefix is required"},
		"host bits":      {func(r *Request) { r.Prefix = netip.MustParsePrefix("198.51.100.7/24") }, "host bits"},
		"default route":  {func(r *Request) { r.Prefix = netip.MustParsePrefix("0.0.0.0/0") }, "default route"},
		"provider":       {func(r *Request) { r.Provider = "transit-z" }, `provider "transit-z" is not configured`},
		"loss high":      {func(r *Request) { r.MaxLossPct = 101 }, "max_loss_pct"},
		"loss nan":       {func(r *Request) { r.MaxLossPct = math.NaN() }, "max_loss_pct"},
		"rtt negative":   {func(r *Request) { r.MaxRTTMs = -1 }, "max_rtt_ms"},
		"too short":      {func(r *Request) { r.Duration = time.Second }, "duration"},
		"too long":       {func(r *Request) { r.Duration = 8 * 24 * time.Hour }, "duration"},
		"reason":         {func(r *Request) { r.Reason = strings.Repeat("x", MaxReason+1) }, "reason"},
		"not allowlist":  {func(r *Request) { r.Prefix = netip.MustParsePrefix("203.0.113.0/24") }, "not inside allowlist.prefixes"},
		"not in the RIB": {func(r *Request) { r.Prefix = netip.MustParsePrefix("198.51.102.0/24") }, "not in the learned RIB view"},
	} {
		r := req("198.51.100.0/24")
		tc.edit(&r)
		s := NewStore()
		if _, err := s.Add(r, rails, t0); err == nil || !strings.Contains(err.Error(), tc.want) {
			t.Errorf("%s: err %v, want %q", name, err, tc.want)
		}
		if len(s.List(t0)) != 0 {
			t.Errorf("%s: a refused pin was kept", name)
		}
	}
	// No RIB view at all (IXP mode, or no bgp block) refuses every pin.
	if _, err := NewStore().Add(req("198.51.100.0/24"), Rails{Providers: rails.Providers, Allowlist: rails.Allowlist}, t0); err == nil || !strings.Contains(err.Error(), "learned RIB") {
		t.Errorf("no RIB: %v", err)
	}
}

func TestAddListRemoveAndVerdicts(t *testing.T) {
	s := NewStore()
	if s.Verdicts(t0) != nil {
		t.Fatal("verdicts with no pins")
	}
	p, err := s.Add(req("198.51.100.0/24"), rails, t0)
	if err != nil {
		t.Fatal(err)
	}
	if p.ID != "pin-1" || p.By != "noc1" || !p.Expires.Equal(t0.Add(time.Hour)) {
		t.Fatalf("pin %+v", p)
	}
	if _, err := s.Add(req("198.51.100.0/24"), rails, t0); !errors.Is(err, ErrConflict) || !strings.Contains(err.Error(), "pin-1") {
		t.Fatalf("second pin on the prefix: %v", err)
	}
	if _, err := s.Add(req("198.51.101.0/24"), rails, t0); err != nil {
		t.Fatal(err)
	}
	if l := s.List(t0); len(l) != 2 || l[0].Prefix != learned || l[1].ID != "pin-2" {
		t.Fatalf("list %+v", l)
	}
	v := s.Verdicts(t0)[learned]
	want := plugin.PolicyVerdict{Action: plugin.PolicyStatic, Providers: []string{"transit-b"}, Rule: "api pin-1", Match: "prefix 198.51.100.0/24", MaxLossPct: 2, MaxRTT: 80 * time.Millisecond}
	if v.Action != want.Action || len(v.Providers) != 1 || v.Providers[0] != "transit-b" || v.Rule != want.Rule || v.Match != want.Match || v.MaxLossPct != 2 || v.MaxRTT != want.MaxRTT {
		t.Fatalf("verdict %+v", v)
	}
	if _, ok := s.Remove("pin-9"); ok {
		t.Fatal("removed an unknown id")
	}
	if old, ok := s.Remove("pin-1"); !ok || old.Prefix != learned {
		t.Fatalf("remove: %+v %v", old, ok)
	}
	if _, ok := s.Verdicts(t0)[learned]; ok {
		t.Fatal("verdict kept after remove")
	}
}

func TestPinsExpireAndAreCapped(t *testing.T) {
	s := NewStore()
	if _, err := s.Add(req("198.51.100.0/24"), rails, t0); err != nil {
		t.Fatal(err)
	}
	end := t0.Add(time.Hour)
	if len(s.List(end.Add(-time.Nanosecond))) != 1 {
		t.Fatal("pin gone before its end")
	}
	if s.Verdicts(end) != nil || len(s.List(end)) != 0 {
		t.Fatal("pin kept at its end")
	}

	many := Rails{Providers: rails.Providers, Allowlist: rails.Allowlist, Learned: func(netip.Prefix) bool { return true }}
	base := netip.MustParsePrefix("2001:db8::/48").Addr().As16()
	for i := range MaxPins {
		a := base
		a[5] = byte(i)
		if _, err := s.Add(Request{Prefix: netip.PrefixFrom(netip.AddrFrom16(a), 48), Provider: "transit-a", Duration: time.Hour}, many, t0); err != nil {
			t.Fatalf("pin %d: %v", i, err)
		}
	}
	if _, err := s.Add(Request{Prefix: netip.MustParsePrefix("2001:db8:ffff::/48"), Provider: "transit-a", Duration: time.Hour}, many, t0); !errors.Is(err, ErrConflict) {
		t.Fatalf("pin past the cap: %v", err)
	}
}
