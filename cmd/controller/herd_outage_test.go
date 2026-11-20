package main

import (
	"context"
	"maps"
	"net/netip"
	"reflect"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/GrandArcher/Packeteer/internal/herd"
	"github.com/GrandArcher/Packeteer/internal/pluginhost"
	"github.com/GrandArcher/Packeteer/internal/plugins/source/outage"
	"github.com/GrandArcher/Packeteer/pkg/plugin"
)

type eventSink []plugin.Event

func (s *eventSink) Emit(ev plugin.Event) { *s = append(*s, ev) }

// outageWired builds an outage source wired as the daemon wires it, with
// note on its events, and feeds it samples.
func outageWired(t *testing.T, note func(plugin.Event) plugin.Event, samples *[]outage.Sample) (*outage.Source, *eventSink) {
	t.Helper()
	c, err := plugin.ConfigFromYAML("min_prefixes: 3\nwindow: 1m\nloss_pct: 20\ninterval: 5s\n")
	if err != nil {
		t.Fatal(err)
	}
	raw, err := outage.New(c, plugin.Env{})
	if err != nil {
		t.Fatal(err)
	}
	s := raw.(*outage.Source)
	sink := &eventSink{}
	wireOutage(&pluginhost.Set{Sources: []pluginhost.Instance[plugin.TargetSource]{{Name: "outage", Type: outage.TypeName, Plugin: s}}}, nil, nil, sink, note)
	routes := []outage.Route{}
	for i, p := range []string{"192.0.2.0/24", "198.51.100.0/24", "203.0.113.0/24"} {
		routes = append(routes, outage.Route{Prefix: netip.MustParsePrefix(p), ASPath: []uint32{64500, 64496 + uint32(i)}, Provider: "transit-a"})
	}
	s.SetSnapshots(func() []outage.Sample { return *samples }, func() []outage.Route { return routes })
	return s, sink
}

// herdFields splits an event's herd annotation from the rest.
func herdFields(ev plugin.Event) (rest, note map[string]string) {
	rest, note = map[string]string{}, map[string]string{}
	for k, v := range ev.Fields {
		if strings.HasPrefix(k, "herd_") {
			note[k] = v
		} else {
			rest[k] = v
		}
	}
	return rest, note
}

// The outage second opinion (#686) adds herd_asn, herd_reporting, and
// herd_degraded to an AS or circuit incident and nothing else: an outage
// source wired with it opens, re-queues, and clears exactly what one
// without it does, and a cleared incident carries no annotation.
func TestHerdOutageNoteAnnotatesAndChangesNoIncident(t *testing.T) {
	cfg := mustParse(t, strings.Replace(herdYAML(t.TempDir()),
		"  - {name: transit-a, source_ip: 192.0.2.11, next_hop: 192.0.2.1}",
		"  - {name: transit-a, source_ip: 192.0.2.11, next_hop: 192.0.2.1, asn: 64501}\n  - {name: transit-b, source_ip: 192.0.2.12, next_hop: 192.0.2.2}", 1))
	ops := map[uint32]herd.Opinion{64500: {Reporting: 3, Degraded: 2}, 64501: {Reporting: 2}}
	note := herdOutageNote(cfg, func(asn uint32) (herd.Opinion, bool) { return ops[asn], true })

	var samples []outage.Sample
	withNote, noted := outageWired(t, note, &samples)
	plain, bare := outageWired(t, nil, &samples)
	now := time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC)
	phase := func(lossA, lossB float64) {
		samples = nil
		for _, p := range []string{"192.0.2.0/24", "198.51.100.0/24", "203.0.113.0/24"} {
			samples = append(samples,
				outage.Sample{Provider: "transit-a", Prefix: netip.MustParsePrefix(p), LossPct: lossA, Time: now},
				outage.Sample{Provider: "transit-b", Prefix: netip.MustParsePrefix(p), LossPct: lossB, Time: now})
		}
		if a, b := withNote.Evaluate(now), plain.Evaluate(now); a != b {
			t.Fatalf("wake %v with the note, %v without", a, b)
		}
		ta, _ := withNote.Targets(context.Background())
		tb, _ := plain.Targets(context.Background())
		if !reflect.DeepEqual(ta, tb) {
			t.Fatalf("targets %v with the note, %v without", ta, tb)
		}
		now = now.Add(time.Second)
	}
	phase(90, 90) // AS64500 on both providers
	phase(90, 0)  // circuit transit-a
	phase(0, 0)   // cleared
	if len(*noted) != 4 || len(*bare) != 4 {
		t.Fatalf("events %+v with the note, %+v without", *noted, *bare)
	}
	want := []map[string]string{
		{"herd_asn": "64500", "herd_reporting": "3", "herd_degraded": "2"},
		{"herd_asn": "64501", "herd_reporting": "2", "herd_degraded": "0"},
		{}, {},
	}
	kinds := []string{plugin.EventOutageAS, plugin.EventOutageCircuit, plugin.EventOutageCleared, plugin.EventOutageCleared}
	for i, ev := range *noted {
		b := (*bare)[i]
		rest, got := herdFields(ev)
		if ev.Kind != kinds[i] || ev.Kind != b.Kind || ev.Message != b.Message || ev.Severity != b.Severity || !maps.Equal(rest, b.Fields) {
			t.Errorf("event %d = %+v, without the note %+v", i, ev, b)
		}
		if !maps.Equal(got, want[i]) {
			t.Errorf("event %d (%s) herd fields = %v, want %v", i, ev.Kind, got, want[i])
		}
	}
}

// Before herd's first refresh, for a circuit whose provider has no asn,
// and with herd off, the event goes out as the outage source made it.
func TestHerdOutageNoteLeavesEventsAloneWithoutAnOpinion(t *testing.T) {
	cfg := mustParse(t, herdYAML(t.TempDir()))
	var none atomic.Pointer[herd.Herd]
	if op, ok := herdOpinion(&none)(64500); ok || op != (herd.Opinion{}) {
		t.Errorf("opinion before herd is built = %+v, %v", op, ok)
	}
	asked := false
	notes := map[string]func(plugin.Event) plugin.Event{
		"not refreshed": herdOutageNote(cfg, herdOpinion(&none)),
		"no provider asn": herdOutageNote(cfg, func(uint32) (herd.Opinion, bool) {
			asked = true
			return herd.Opinion{Reporting: 1}, true
		}),
	}
	for name, note := range notes {
		for _, ev := range []plugin.Event{
			{Kind: plugin.EventOutageAS, Fields: map[string]string{"asn": "64500"}},
			{Kind: plugin.EventOutageCircuit, Fields: map[string]string{"provider": "transit-a"}},
		} {
			if name == "no provider asn" && ev.Kind == plugin.EventOutageAS {
				continue
			}
			if got := note(ev); !maps.Equal(got.Fields, ev.Fields) {
				t.Errorf("%s: %s fields = %v", name, ev.Kind, got.Fields)
			}
		}
	}
	if asked {
		t.Error("a circuit with no provider asn was looked up")
	}
	off := mustParse(t, strings.Replace(herdYAML(t.TempDir()), "herd:\n  enabled: true", "herd:\n  enabled: false", 1))
	if herdOutageNote(off, herdOpinion(&none)) != nil {
		t.Error("the note is wired with herd off")
	}
}
