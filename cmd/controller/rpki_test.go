package main

import (
	"fmt"
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/GrandArcher/Packeteer/internal/pluginhost"
	"github.com/GrandArcher/Packeteer/internal/policy"
	"github.com/GrandArcher/Packeteer/internal/probe"
	"github.com/GrandArcher/Packeteer/internal/rpki"
	"github.com/GrandArcher/Packeteer/pkg/plugin"
)

type fakeRPKI struct {
	plugin.Base
	validity plugin.RPKIValidity
}

func (f fakeRPKI) Validate(netip.Prefix, uint32) plugin.RPKIValidity { return f.validity }
func (f fakeRPKI) Status() plugin.RPKIStatus                         { return plugin.RPKIStatus{Up: true, VRPs: 1} }

// #158: newRPKISet wraps the configured sources in order and is off when
// none is configured.
func TestNewRPKISet(t *testing.T) {
	if newRPKISet(nil).Enabled() {
		t.Fatal("nil plugins set is enabled")
	}
	if newRPKISet(&pluginhost.Set{}).Enabled() {
		t.Fatal("empty plugins set is enabled")
	}
	set := &pluginhost.Set{RPKISources: []pluginhost.Instance[plugin.RPKI]{
		{Name: "a", Type: "fake", Plugin: fakeRPKI{validity: plugin.RPKIValid}},
	}}
	got := newRPKISet(set)
	if !got.Enabled() {
		t.Fatal("set with one source is not enabled")
	}
	if v := got.Validate(netip.MustParsePrefix("198.51.100.0/24"), 64500); v != plugin.RPKIValid {
		t.Fatalf("Validate = %q", v)
	}

	// #200: the display fallback answers LookupDisplay only, and the
	// statuses list the sources, not the fallback.
	set = &pluginhost.Set{
		RPKISources: []pluginhost.Instance[plugin.RPKI]{{Name: "a", Type: "fake", Plugin: fakeRPKI{validity: plugin.RPKIUnknown}}},
		RPKIDisplay: &pluginhost.Instance[plugin.RPKI]{Name: "ripestat", Type: "ripestat", Plugin: fakeDisplay{}},
	}
	got = newRPKISet(set)
	p := netip.MustParsePrefix("198.51.100.0/24")
	if a := got.Lookup(p, 64500); a.State != plugin.RPKIUnknown {
		t.Fatalf("Lookup = %+v, want the source's unknown", a)
	}
	if a := got.LookupDisplay(p, 64500); a.State != plugin.RPKINotFound || a.Source != "ripestat" {
		t.Fatalf("LookupDisplay = %+v, want the fallback", a)
	}
	if st := rpkiStatuses(set); len(st) != 1 || st[0].VRPs != 1 {
		t.Fatalf("statuses = %+v", st)
	}
}

type fakeDisplay struct{ fakeRPKI }

func (fakeDisplay) Answer(netip.Prefix, uint32) plugin.RPKIAnswer {
	return plugin.RPKIAnswer{State: plugin.RPKINotFound, Source: "ripestat"}
}

// fakeOrigins validates by origin AS: an origin in invalid is invalid,
// any other is valid.
type fakeOrigins struct {
	plugin.Base
	invalid map[uint32]bool
}

func (f fakeOrigins) Validate(_ netip.Prefix, origin uint32) plugin.RPKIValidity {
	if f.invalid[origin] {
		return plugin.RPKIInvalid
	}
	return plugin.RPKIValid
}
func (f fakeOrigins) Status() plugin.RPKIStatus {
	return plugin.RPKIStatus{Source: "routinator", Up: true, VRPs: 1, Updated: rpkiFetched}
}

var rpkiFetched = time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC)

type fakePaths map[string][][]uint32

func (f fakePaths) ProviderPaths(_ netip.Prefix, provider string) [][]uint32 { return f[provider] }

// fillRPKI labels each provider by the origins (the last AS) of all its
// learned paths, the worst one winning, with the source that answered, and
// skips a provider without a path or with RPKI off. rpkiRoutes keeps every
// distinct origin of every provider for history (#200).
func TestFillRPKI(t *testing.T) {
	p := netip.MustParsePrefix("198.51.100.0/24")
	src := rpki.NewSet([]plugin.RPKI{fakeOrigins{invalid: map[uint32]bool{64511: true}}})
	in := &policy.Input{Results: []probe.Result{
		{Provider: "transit-a", Prefix: p},
		{Provider: "transit-b", Prefix: p},
		{Provider: "ix-peer-a", Prefix: p},
		{Provider: "ix-peer-b", Prefix: p},
	}}
	routes := rpkiRoutes(fakePaths{
		"transit-a": {{64496, 64511}},
		// The first path (as ProviderPath would pick) is valid; a later
		// add-path or BMP path from the same provider is invalid.
		"transit-b": {{64497, 64500}, {64497, 64511}},
		"ix-peer-a": {{64501, 64500}, {64501, 64500}},
	}, in.Results, src)
	var got []string
	for _, rt := range routes {
		got = append(got, fmt.Sprintf("%s AS%d %s", rt.Provider, rt.Origin, rt.Answer.State))
	}
	if strings.Join(got, ", ") != "transit-a AS64511 invalid, transit-b AS64500 valid, transit-b AS64511 invalid, ix-peer-a AS64500 valid" {
		t.Fatalf("routes = %v", got)
	}
	fillRPKI(in, routes)
	want := map[string]plugin.RPKIValidity{
		"transit-a": plugin.RPKIInvalid,
		"transit-b": plugin.RPKIInvalid,
		"ix-peer-a": plugin.RPKIValid,
	}
	if len(in.RPKI[p]) != len(want) {
		t.Fatalf("labels = %+v, want %+v", in.RPKI[p], want)
	}
	for provider, w := range want {
		if got := in.RPKI[p][provider]; got != (plugin.RPKIAnswer{State: w, Source: "routinator", Updated: rpkiFetched}) {
			t.Fatalf("%s validity = %+v, want %q from routinator", provider, got, w)
		}
	}

	off := &policy.Input{Results: []probe.Result{{Provider: "transit-a", Prefix: p}}}
	fillRPKI(off, rpkiRoutes(fakePaths{"transit-a": {{64500}}}, off.Results, rpki.NewSet(nil)))
	if len(off.RPKI) != 0 {
		t.Fatalf("RPKI off labelled a path: %+v", off.RPKI)
	}
}
