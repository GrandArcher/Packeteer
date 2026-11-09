package main

import (
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/GrandArcher/Packeteer/internal/config"
	"github.com/GrandArcher/Packeteer/internal/pluginhost"
	"github.com/GrandArcher/Packeteer/internal/policy"
	"github.com/GrandArcher/Packeteer/internal/probe"
	"github.com/GrandArcher/Packeteer/pkg/plugin"
)

func TestEventWatchMEDOverridden(t *testing.T) {
	s := &sink{}
	w := newEventWatch(s, "inject")
	p := netip.MustParsePrefix("198.51.100.0/24")
	o := &policy.MEDOverride{ASN: 64496, Preferred: "link-1", PreferredMED: 10, Chosen: "link-2", ChosenMED: 50, ScoreGap: 42}
	imp := policy.Improvement{Prefix: p, Provider: "link-2", Native: "link-1", MEDOverride: o}
	w.improvements(time.Unix(10, 0), []policy.Change{
		{Action: policy.ActionImprove, New: imp},
		{Action: policy.ActionRetire, Old: imp},
	})
	got := s.take()
	if kinds(got) != "improvement.added,med.overridden,improvement.removed" {
		t.Fatalf("kinds %s", kinds(got))
	}
	f := got[1].Fields
	if f["prefix"] != p.String() || f["asn"] != "64496" || f["provider"] != "link-2" || f["med"] != "50" ||
		f["preferred"] != "link-1" || f["preferred_med"] != "10" || f["score_gap"] != "42.0" || f["mode"] != "inject" {
		t.Fatalf("fields %+v", f)
	}
	if !strings.Contains(got[1].Message, "overrides AS64496 MED: link-2 (MED 50) over link-1 (MED 10)") {
		t.Fatalf("message %q", got[1].Message)
	}
}

// fakeMEDs answers ProviderMED from a fixed table.
type fakeMEDs map[string]policy.NeighborMED

func (f fakeMEDs) ProviderMED(_ netip.Prefix, provider string) (uint32, uint32, bool) {
	m, ok := f[provider]
	return m.ASN, m.MED, ok
}

func medResults(p netip.Prefix, providers ...string) []probe.Result {
	var out []probe.Result
	for _, name := range providers {
		out = append(out, probe.Result{Provider: name, Prefix: p})
	}
	return out
}

func TestFillMEDAndPolicyConfig(t *testing.T) {
	p := netip.MustParsePrefix("198.51.100.0/24")
	in := policy.Input{Results: medResults(p, "link-1", "link-2", "transit-b")}
	fillMED(&in, fakeMEDs{"link-1": {ASN: 64496, MED: 10}, "link-2": {ASN: 64496, MED: 0}})
	if len(in.MED[p]) != 2 || in.MED[p]["link-1"].MED != 10 || in.MED[p]["link-2"] != (policy.NeighborMED{ASN: 64496}) {
		t.Fatalf("med = %+v", in.MED)
	}
	empty := policy.Input{Results: medResults(p, "transit-b")}
	if fillMED(&empty, fakeMEDs{}); empty.MED != nil {
		t.Fatalf("no MED = %+v", empty.MED)
	}

	pc, err := policyConfig(mustParse(t, liveApplyConfig(179, "observe", "5m", "1h")))
	if err != nil || !pc.MEDTieBreak || pc.MEDMargin != 20 {
		t.Fatalf("default: tie break %v margin %v (%v)", pc.MEDTieBreak, pc.MEDMargin, err)
	}
	off := strings.Replace(liveApplyConfig(179, "observe", "5m", "1h"),
		"thresholds: {min_loss_delta_pct: 90, min_rtt_delta_ms: 5000}",
		"thresholds: {min_loss_delta_pct: 90, min_rtt_delta_ms: 5000, med_tie_break: false, med_margin: 5}", 1)
	if pc, _ := policyConfig(mustParse(t, off)); pc.MEDTieBreak || pc.MEDMargin != 5 {
		t.Fatalf("set: tie break %v margin %v", pc.MEDTieBreak, pc.MEDMargin)
	}
}

// medCatalog is an inbound announcer catalog with a MED action on link-1.
type medCatalog struct{ plugin.InboundAnnouncer }

func (medCatalog) Action(p string) (plugin.InboundAction, bool) {
	if p == "link-1" {
		return plugin.InboundAction{Provider: p, MED: 100, Communities: []string{"64512:1301"}}, true
	}
	return plugin.InboundAction{}, false
}

func TestCheckInboundMEDNeedsASecondLink(t *testing.T) {
	set := &pluginhost.Set{Inbound: &pluginhost.Instance[plugin.InboundAnnouncer]{Plugin: medCatalog{}}}
	cfg := func(asn2 uint32, exclude bool) *config.Config {
		return &config.Config{Inbound: &config.Inbound{}, Providers: []config.Provider{
			{Name: "link-1", ASN: 64496}, {Name: "link-2", ASN: asn2, Exclude: exclude}, {Name: "transit-b", ASN: 64497}}}
	}
	if err := checkInboundMED(cfg(64496, false), set); err != nil {
		t.Fatalf("two links to AS 64496: %v", err)
	}
	for name, c := range map[string]*config.Config{
		"other asn":     cfg(64499, false),
		"no asn":        cfg(0, false),
		"link excluded": cfg(64496, true),
	} {
		err := checkInboundMED(c, set)
		if err == nil || !strings.Contains(err.Error(), `provider "link-1" has a med action but no other provider shares its asn`) {
			t.Errorf("%s: err = %v", name, err)
		}
	}
	if err := checkInboundMED(&config.Config{Providers: cfg(0, false).Providers}, set); err != nil {
		t.Fatalf("no inbound block: %v", err)
	}
}
