package rpki

import (
	"net/netip"
	"testing"

	"github.com/GrandArcher/Packeteer/pkg/plugin"
)

type fakeSource struct {
	plugin.Base
	validity plugin.RPKIValidity
	status   plugin.RPKIStatus
}

func (f *fakeSource) Validate(netip.Prefix, uint32) plugin.RPKIValidity { return f.validity }
func (f *fakeSource) Status() plugin.RPKIStatus                         { return f.status }

// #158: the first source with a fresh cache answers; a stale source is
// skipped so a second server can take over; with none the state is
// unknown (fail open).
func TestSetFallback(t *testing.T) {
	prefix := netip.MustParsePrefix("198.51.100.0/24")
	stale := &fakeSource{validity: plugin.RPKIInvalid, status: plugin.RPKIStatus{Source: "first", Stale: true}}
	fresh := &fakeSource{validity: plugin.RPKIValid, status: plugin.RPKIStatus{Source: "second", Up: true}}
	s := NewSet([]plugin.RPKI{stale, fresh})
	if !s.Enabled() {
		t.Fatal("Enabled = false with sources")
	}
	if got := s.Validate(prefix, 64500); got != plugin.RPKIValid {
		t.Fatalf("Validate = %q, want the fresh source's valid", got)
	}
	// The first fresh source answers even not-found: no fallthrough.
	notFound := &fakeSource{validity: plugin.RPKINotFound, status: plugin.RPKIStatus{Source: "first", Up: true}}
	s = NewSet([]plugin.RPKI{notFound, fresh})
	if got := s.Validate(prefix, 64500); got != plugin.RPKINotFound {
		t.Fatalf("Validate = %q, want the first fresh source's notfound", got)
	}
}

func TestSetEmpty(t *testing.T) {
	prefix := netip.MustParsePrefix("198.51.100.0/24")
	if got := NewSet(nil).Validate(prefix, 64500); got != plugin.RPKIUnknown {
		t.Fatalf("empty set = %q, want unknown", got)
	}
	var nilSet *Set
	if nilSet.Enabled() {
		t.Fatal("nil set Enabled = true")
	}
	if got := nilSet.Validate(prefix, 64500); got != plugin.RPKIUnknown {
		t.Fatalf("nil set = %q, want unknown", got)
	}
}
