package rpki

import (
	"net/netip"
	"testing"
	"time"

	"github.com/GrandArcher/Packeteer/pkg/plugin"
)

type fakeSource struct {
	plugin.Base
	validity plugin.RPKIValidity
	status   plugin.RPKIStatus
}

func (f *fakeSource) Validate(netip.Prefix, uint32) plugin.RPKIValidity { return f.validity }
func (f *fakeSource) Status() plugin.RPKIStatus                         { return f.status }

// #158: the first fresh, non-empty source answers. A stale source and an
// empty cache are skipped so a second server can take over. A fresh source
// that has VRPs answers notfound for an uncovered prefix and does not fall
// through. With no usable source the state is unknown (fail open).
func TestSetFallback(t *testing.T) {
	prefix := netip.MustParsePrefix("198.51.100.0/24")
	stale := &fakeSource{validity: plugin.RPKIInvalid, status: plugin.RPKIStatus{Source: "first", Stale: true, VRPs: 4}}
	fresh := &fakeSource{validity: plugin.RPKIValid, status: plugin.RPKIStatus{Source: "second", Up: true, VRPs: 4}}
	s := NewSet([]plugin.RPKI{stale, fresh})
	if !s.Enabled() {
		t.Fatal("Enabled = false with sources")
	}
	if got := s.Validate(prefix, 64500); got != plugin.RPKIValid {
		t.Fatalf("Validate = %q, want the fresh source's valid", got)
	}
	// The first fresh source with VRPs answers even not-found: no fallthrough.
	notFound := &fakeSource{validity: plugin.RPKINotFound, status: plugin.RPKIStatus{Source: "first", Up: true, VRPs: 4}}
	s = NewSet([]plugin.RPKI{notFound, fresh})
	if got := s.Validate(prefix, 64500); got != plugin.RPKINotFound {
		t.Fatalf("Validate = %q, want the first fresh source's notfound", got)
	}
	// A fresh empty cache (zero-VRP End of Data) must not answer notfound
	// and hide a backup that still has the invalid origin.
	empty := &fakeSource{validity: plugin.RPKINotFound, status: plugin.RPKIStatus{Source: "empty", Up: true}}
	backup := &fakeSource{validity: plugin.RPKIInvalid, status: plugin.RPKIStatus{Source: "backup", Up: true, VRPs: 3}}
	s = NewSet([]plugin.RPKI{empty, backup})
	if got := s.Validate(prefix, 64500); got != plugin.RPKIInvalid {
		t.Fatalf("Validate = %q, want the backup's invalid", got)
	}
	if got := NewSet([]plugin.RPKI{empty}).Validate(prefix, 64500); got != plugin.RPKIUnknown {
		t.Fatalf("only empty source = %q, want unknown", got)
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

// Version changes when a source completes a fetch or goes stale, so a
// cache of Validate results can invalidate without a RIB generation
// change.
func TestSetVersionChanges(t *testing.T) {
	at := time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC)
	src := &fakeSource{status: plugin.RPKIStatus{Up: true, VRPs: 10, Updated: at}}
	s := NewSet([]plugin.RPKI{src})
	first := s.Version()
	if first == 0 {
		t.Fatal("Version = 0 with a source")
	}
	// A completed fetch with a different payload count changes it.
	src.status = plugin.RPKIStatus{Up: true, VRPs: 11, Updated: at.Add(time.Minute)}
	if second := s.Version(); second == first {
		t.Fatal("Version did not change after a fetch")
	} else {
		first = second
	}
	// Going stale changes it even without a new fetch.
	src.status.Stale = true
	if third := s.Version(); third == first {
		t.Fatal("Version ignores staleness")
	}
	if NewSet(nil).Version() != 0 {
		t.Fatal("empty set Version is not 0")
	}
	var nilSet *Set
	if nilSet.Version() != 0 {
		t.Fatal("nil set Version is not 0")
	}
}
