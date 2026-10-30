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

type fakeAnswerer struct {
	answer plugin.RPKIAnswer
	asked  int
}

func (f *fakeAnswerer) Answer(netip.Prefix, uint32) plugin.RPKIAnswer {
	f.asked++
	return f.answer
}

// #200: Lookup names the source that answered and its fetch time; with the
// primary stale the second source answers. The display fallback is asked
// only by LookupDisplay and only when no source has usable data, so it can
// never reach a decision.
func TestSetLookupAndDisplay(t *testing.T) {
	prefix := netip.MustParsePrefix("198.51.100.0/24")
	at := time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC)
	primary := &fakeSource{validity: plugin.RPKIInvalid, status: plugin.RPKIStatus{Source: "routinator", Up: true, VRPs: 4, Updated: at}}
	backup := &fakeSource{validity: plugin.RPKIValid, status: plugin.RPKIStatus{Source: "backup", Up: true, VRPs: 4, Updated: at.Add(time.Minute)}}
	display := &fakeAnswerer{answer: plugin.RPKIAnswer{State: plugin.RPKINotFound, Source: "ripestat", Updated: at.Add(time.Hour)}}
	s := NewSet([]plugin.RPKI{primary, backup})
	s.SetDisplay(display)
	if got := s.Lookup(prefix, 64500); got != (plugin.RPKIAnswer{State: plugin.RPKIInvalid, Source: "routinator", Updated: at}) {
		t.Fatalf("Lookup = %+v, want the primary's answer", got)
	}
	if got := s.LookupDisplay(prefix, 64500); got.Source != "routinator" || display.asked != 0 {
		t.Fatalf("LookupDisplay = %+v asked %d, want the primary and no fallback", got, display.asked)
	}
	primary.status.Stale = true
	if got := s.Lookup(prefix, 64500); got.State != plugin.RPKIValid || got.Source != "backup" || !got.Updated.Equal(at.Add(time.Minute)) {
		t.Fatalf("Lookup = %+v, want the backup's answer", got)
	}
	backup.status.Stale = true
	if got := s.Lookup(prefix, 64500); got != (plugin.RPKIAnswer{State: plugin.RPKIUnknown}) {
		t.Fatalf("Lookup = %+v, want unknown with no fallback", got)
	}
	if display.asked != 0 {
		t.Fatal("Lookup asked the display fallback")
	}
	if got := s.LookupDisplay(prefix, 64500); got != display.answer {
		t.Fatalf("LookupDisplay = %+v, want the fallback's answer", got)
	}
	display.answer = plugin.RPKIAnswer{State: plugin.RPKIUnknown}
	if got := s.LookupDisplay(prefix, 64500); got.State != plugin.RPKIUnknown || got.Source != "" {
		t.Fatalf("LookupDisplay = %+v, want unknown", got)
	}
}

type coveringSource struct {
	fakeSource
	vrps []plugin.RPKIVRP
}

func (c *coveringSource) Covering(netip.Prefix) []plugin.RPKIVRP { return c.vrps }

// #289: Covering asks the source Validate would use, and is nil when that
// source cannot list payloads or has no fresh data.
func TestSetCovering(t *testing.T) {
	prefix := netip.MustParsePrefix("198.51.100.0/24")
	vrp := plugin.RPKIVRP{Prefix: netip.MustParsePrefix("198.51.100.0/22"), MaxLen: 24, ASN: 64500}
	fresh := plugin.RPKIStatus{Up: true, VRPs: 1}
	with := &coveringSource{fakeSource: fakeSource{status: fresh}, vrps: []plugin.RPKIVRP{vrp}}
	if got := NewSet([]plugin.RPKI{with}).Covering(prefix); len(got) != 1 || got[0] != vrp {
		t.Fatalf("Covering = %+v", got)
	}
	if got := NewSet([]plugin.RPKI{&fakeSource{status: fresh}}).Covering(prefix); got != nil {
		t.Fatalf("a source without Covering answered %+v", got)
	}
	stale := &coveringSource{fakeSource: fakeSource{status: plugin.RPKIStatus{Stale: true, VRPs: 1}}, vrps: []plugin.RPKIVRP{vrp}}
	if got := NewSet([]plugin.RPKI{stale}).Covering(prefix); got != nil {
		t.Fatalf("a stale source answered %+v", got)
	}
}
