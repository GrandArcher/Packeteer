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
func (f fakeRPKI) Status() plugin.RPKIStatus                         { return plugin.RPKIStatus{Up: true} }

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

type fakePaths struct {
	path []uint32
	ok   bool
}

func (f fakePaths) ProviderPath(netip.Prefix, string) ([]uint32, bool) { return f.path, f.ok }

// fillRPKI labels each provider path by its origin (the last AS) and skips
// a provider without a path or with RPKI off.
func TestFillRPKI(t *testing.T) {
	p := netip.MustParsePrefix("198.51.100.0/24")
	src := rpki.NewSet([]plugin.RPKI{fakeRPKI{validity: plugin.RPKIInvalid}})
	in := &policy.Input{Results: []probe.Result{{Provider: "transit-a", Prefix: p}}}
	fillRPKI(in, fakePaths{path: []uint32{64500, 64511}, ok: true}, src)
	if got := in.RPKI[p]["transit-a"]; got != plugin.RPKIInvalid {
		t.Fatalf("validity = %q", got)
	}

	noPath := &policy.Input{Results: []probe.Result{{Provider: "transit-a", Prefix: p}}}
	fillRPKI(noPath, fakePaths{ok: false}, src)
	if len(noPath.RPKI) != 0 {
		t.Fatalf("a provider without a path was labelled: %+v", noPath.RPKI)
	}

	off := &policy.Input{Results: []probe.Result{{Provider: "transit-a", Prefix: p}}}
	fillRPKI(off, fakePaths{path: []uint32{64500}, ok: true}, rpki.NewSet(nil))
	if len(off.RPKI) != 0 {
		t.Fatalf("RPKI off labelled a path: %+v", off.RPKI)
	}
}
