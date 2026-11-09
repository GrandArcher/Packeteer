package main

import (
	"github.com/GrandArcher/Packeteer/internal/auth"
	"github.com/GrandArcher/Packeteer/internal/auth/authtest"
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/GrandArcher/Packeteer/internal/plugins/scorer/weighted"
	"github.com/GrandArcher/Packeteer/internal/policy"
	"github.com/GrandArcher/Packeteer/internal/probe"
	"github.com/GrandArcher/Packeteer/pkg/plugin"
)

func TestPolicyConfigFlapQuarantine(t *testing.T) {
	on, err := policyConfig(mustParse(t, liveApplyConfig(179, "observe", "5m", "1h")+"flap_quarantine: {max_flips: 4, window: 30m, cooldown: 5m, max_cooldown: 1h}\n"))
	if err != nil {
		t.Fatal(err)
	}
	want := policy.FlapConfig{MaxFlips: 4, Window: 30 * time.Minute, Cooldown: 5 * time.Minute, MaxCooldown: time.Hour}
	if on.Flap != want {
		t.Fatalf("flap = %+v, want %+v", on.Flap, want)
	}
	def, err := policyConfig(mustParse(t, liveApplyConfig(179, "observe", "5m", "1h")))
	if err != nil || def.Flap.MaxFlips == 0 {
		t.Fatalf("quarantine is on by default: %+v %v", def.Flap, err)
	}
	off, err := policyConfig(mustParse(t, liveApplyConfig(179, "observe", "5m", "1h")+"flap_quarantine: {disabled: true}\n"))
	if err != nil || off.Flap != (policy.FlapConfig{}) {
		t.Fatalf("disabled flap = %+v %v", off.Flap, err)
	}
}

// Oscillating latency parks the prefix; the decision loop reports it once,
// an operator release reports it ended and wakes the loop, and the engine
// decides the prefix again at once.
func TestQuarantineEventsAndRelease(t *testing.T) {
	p := netip.MustParsePrefix("198.51.100.0/24")
	cfg := policy.Config{Mode: "observe", MinLossDeltaPct: 1, MinRTTDelta: 15 * time.Millisecond, HoldTime: time.Minute,
		MaxImprovements: 50, MaxResultAge: 2 * time.Minute,
		Flap: policy.FlapConfig{MaxFlips: 3, Window: time.Hour, Cooldown: 10 * time.Minute, MaxCooldown: time.Hour}}
	scorer, err := weighted.New(plugin.Config{}, plugin.Env{})
	if err != nil {
		t.Fatal(err)
	}
	dec := policy.NewEngine(cfg, scorer)
	out := &sink{}
	w := newEventWatch(out, "observe")
	at := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	round := func(i int) {
		a, b := 50.0, 30.0
		if i%2 == 1 {
			a, b = 30.0, 50.0
		}
		res := []probe.Result{
			{Provider: "a", Prefix: p, Time: at, Stats: probe.Stats{Sent: 10, Received: 10, RTTAvg: time.Duration(a * float64(time.Millisecond))}},
			{Provider: "b", Prefix: p, Time: at, Stats: probe.Stats{Sent: 10, Received: 10, RTTAvg: time.Duration(b * float64(time.Millisecond))}},
		}
		in := policy.Input{Results: res, ProviderUp: map[string]bool{"a": true, "b": true}, RIBEnabled: true, RIBReady: true, Native: map[netip.Prefix]string{p: "a"}}
		dec.Evaluate(in, at)
		w.quarantines(at, dec.QuarantineChanges())
		at = at.Add(2 * time.Minute)
	}
	for i := range 4 {
		round(i)
	}
	evs := out.take()
	if kinds(evs) != plugin.EventFlapQuarantined {
		t.Fatalf("events = %s", kinds(evs))
	}
	if f := evs[0].Fields; f["prefix"] != p.String() || f["strikes"] != "1" || f["flips"] != "4" || f["until"] == "" || !strings.Contains(evs[0].Message, "native path") {
		t.Fatalf("event %+v", evs[0])
	}
	round(4)
	if got := out.take(); len(got) != 0 {
		t.Fatalf("repeated event while parked: %s", kinds(got))
	}

	poked := 0
	ctl := quarantineControl{decider: dec, out: out, poke: func() { poked++ }, now: func() time.Time { return at }}
	if ctl.Release(netip.MustParsePrefix("203.0.113.0/24")) || poked != 0 || len(out.take()) != 0 {
		t.Fatal("released a prefix that is not quarantined")
	}
	if !ctl.Release(p) || poked != 1 || len(dec.Quarantined()) != 0 {
		t.Fatalf("release: poked %d left %v", poked, dec.Quarantined())
	}
	rel := out.take()
	if kinds(rel) != plugin.EventFlapReleased || rel[0].Fields["reason"] != "operator release" {
		t.Fatalf("release events = %+v", rel)
	}
}

func TestAuditQuarantinesWritesSystemRecords(t *testing.T) {
	st := authtest.New()
	audit := auth.NewAuditor(st, nil, nil)
	p := netip.MustParsePrefix("198.51.100.0/24")
	auditQuarantines(audit, nil)
	auditQuarantines(nil, []policy.QuarantineChange{{Action: policy.QuarantineStart}})
	auditQuarantines(audit, []policy.QuarantineChange{
		{Action: policy.QuarantineStart, Reason: "flap quarantine: 7 provider changes", Quarantine: policy.Quarantine{Prefix: p}},
		{Action: policy.QuarantineRelease, Reason: "cool-down elapsed", Quarantine: policy.Quarantine{Prefix: p}},
	})
	for end := time.Now().Add(5 * time.Second); len(st.Records()) < 2; time.Sleep(5 * time.Millisecond) {
		if time.Now().After(end) {
			t.Fatalf("records = %+v", st.Records())
		}
	}
	got := st.Records()
	if got[0].Action != "flap.quarantine" || got[1].Action != "flap.release" || got[0].Actor != "system" || got[0].Target != p.String() || got[0].Result != auth.ResultOK || !strings.Contains(got[0].Detail, "7 provider changes") {
		t.Fatalf("records = %+v", got)
	}
}
