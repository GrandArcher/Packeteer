package main

import (
	"net/netip"
	"testing"

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
func (f fakeOrigins) Status() plugin.RPKIStatus { return plugin.RPKIStatus{Up: true, VRPs: 1} }

type fakePaths map[string][][]uint32

func (f fakePaths) ProviderPaths(_ netip.Prefix, provider string) [][]uint32 { return f[provider] }

// fillRPKI labels each provider by the origins (the last AS) of all its
// learned paths, the worst one winning, and skips a provider without a
// path or with RPKI off.
func TestFillRPKI(t *testing.T) {
	p := netip.MustParsePrefix("198.51.100.0/24")
	src := rpki.NewSet([]plugin.RPKI{fakeOrigins{invalid: map[uint32]bool{64511: true}}})
	in := &policy.Input{Results: []probe.Result{
		{Provider: "transit-a", Prefix: p},
		{Provider: "transit-b", Prefix: p},
		{Provider: "ix-peer-a", Prefix: p},
		{Provider: "ix-peer-b", Prefix: p},
	}}
	fillRPKI(in, fakePaths{
		"transit-a": {{64496, 64511}},
		// The first path (as ProviderPath would pick) is valid; a later
		// add-path or BMP path from the same provider is invalid.
		"transit-b": {{64497, 64500}, {64497, 64511}},
		"ix-peer-a": {{64501, 64500}, {64501, 64500}},
	}, src)
	want := map[string]plugin.RPKIValidity{
		"transit-a": plugin.RPKIInvalid,
		"transit-b": plugin.RPKIInvalid,
		"ix-peer-a": plugin.RPKIValid,
	}
	if len(in.RPKI[p]) != len(want) {
		t.Fatalf("labels = %+v, want %+v", in.RPKI[p], want)
	}
	for provider, w := range want {
		if got := in.RPKI[p][provider]; got != w {
			t.Fatalf("%s validity = %q, want %q", provider, got, w)
		}
	}

	off := &policy.Input{Results: []probe.Result{{Provider: "transit-a", Prefix: p}}}
	fillRPKI(off, fakePaths{"transit-a": {{64500}}}, rpki.NewSet(nil))
	if len(off.RPKI) != 0 {
		t.Fatalf("RPKI off labelled a path: %+v", off.RPKI)
	}
}
