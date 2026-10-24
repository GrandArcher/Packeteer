package main

import (
	"context"
	"errors"
	"net/netip"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/GrandArcher/Packeteer/internal/config"
	"github.com/GrandArcher/Packeteer/internal/history"
	"github.com/GrandArcher/Packeteer/internal/httpapi"
	"github.com/GrandArcher/Packeteer/internal/notify"
	"github.com/GrandArcher/Packeteer/internal/pluginhost"
	"github.com/GrandArcher/Packeteer/internal/probe"
	"github.com/GrandArcher/Packeteer/internal/syshealth"
	"github.com/GrandArcher/Packeteer/pkg/plugin"
)

type failingNotifier struct{ plugin.Base }

func (failingNotifier) Notify(context.Context, plugin.Event) error {
	return errors.New(`webhook: Post "https://hooks.example.net/T0/s3cr3t": connection refused`)
}

type readOnlyStore struct{ plugin.Base }

func (readOnlyStore) Write(context.Context, plugin.HistoryBatch) error {
	return errors.New("attempt to write a readonly database")
}
func (readOnlyStore) Read(context.Context, plugin.HistoryQuery) (plugin.History, error) {
	return plugin.History{}, nil
}

type fixedSource struct {
	plugin.Base
	err error
}

func (f fixedSource) Targets(context.Context) ([]plugin.Target, error) { return nil, f.err }

type fixedProber struct{ plugin.Base }

func (fixedProber) Probe(context.Context, plugin.ProbeRequest) (plugin.ProbeResult, error) {
	return plugin.ProbeResult{}, errors.New("unused")
}

// The failures the System page must show are injected into the real
// hooks the controller wires: a notifier that fails to deliver, a store
// that cannot be written, a source that errors, and a BMP router whose
// session closes. Each lands on its own row, and nothing else changes.
func TestSystemFactsShowInjectedFailures(t *testing.T) {
	health := syshealth.New(nil)
	store := readOnlyStore{}
	set := &pluginhost.Set{
		Probers:   []pluginhost.Instance[plugin.Prober]{{Name: "icmp", Type: "icmp", Plugin: fixedProber{}}},
		Sources:   []pluginhost.Instance[plugin.TargetSource]{{Name: "feed", Type: "static", Plugin: fixedSource{err: errors.New("feed unreachable")}}},
		Storage:   &pluginhost.Instance[plugin.Storage]{Name: "db", Type: "sqlite", Plugin: store},
		Notifiers: []pluginhost.Instance[plugin.Notifier]{{Name: "hook", Type: "webhook", Plugin: failingNotifier{}}, {Name: "mail", Type: "smtp", Plugin: failingNotifier{}}},
	}

	// Notifier: the dispatcher's own delivery path reports into the tracker.
	d := newDispatcher(&pluginhost.Set{Notifiers: set.Notifiers[:1]}, notify.Options{
		Result: func(name string, err error) { health.Record(notifierKey(name), err) }})
	d.Emit(plugin.NewEvent(plugin.EventProviderDown, time.Now(), "down", nil))
	closeCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := d.Close(closeCtx); err != nil {
		t.Fatal(err)
	}

	// Storage: the history recorder's flush reports its write.
	rec := history.New(history.Options{Store: store, FlushEvery: time.Hour, OnWrite: func(err error) { health.Record(historyKey, err) }})
	rec.Probe(probe.Result{Provider: "transit-a", Prefix: netip.MustParsePrefix("198.51.100.0/24"), Time: time.Now(),
		Stats: probe.Stats{Sent: 1, Received: 1}})
	if err := rec.Flush(context.Background()); err == nil {
		t.Fatal("flush to a read-only store succeeded")
	}

	// RIB source: a router reports a peer up, then its session closes. The
	// events still reach the view.
	router := netip.MustParseAddr("192.0.2.254")
	bmpCfg, err := config.Parse([]byte(bmpConfig))
	if err != nil {
		t.Fatal(err)
	}
	bmpSet, err := pluginhost.Build(bmpCfg, pluginhost.Options{})
	if err != nil {
		t.Fatal(err)
	}
	view, err := newRIB(bmpCfg, nil)
	if err != nil {
		t.Fatal(err)
	}
	var sink func(plugin.RIBEvent)
	bmpSet.RIBSources[0].Plugin = &sinkSpy{RIBSource: bmpSet.RIBSources[0].Plugin, got: &sink}
	if err := wireRIBSources(bmpSet, view, health, nil, nil); err != nil {
		t.Fatal(err)
	}
	name := bmpSet.RIBSources[0].Name
	sink(plugin.RIBEvent{Kind: plugin.RIBPeerUp, Router: router, Peer: plugin.RIBPeer{Address: netip.MustParseAddr("192.0.2.22")}})
	if got := health.Under(ribRouterPrefix(name)); len(got) != 1 || !got[router.String()].OK {
		t.Fatalf("router not tracked up: %+v", got)
	}
	sink(plugin.RIBEvent{Kind: plugin.RIBRouterDown, Router: router})
	set.RIBSources = []pluginhost.Instance[plugin.RIBSource]{bmpSet.RIBSources[0]}

	var eng atomic.Pointer[probe.Engine]
	e, err := probe.New([]probe.Provider{{Name: "transit-a", Source: netip.MustParseAddr("192.0.2.11")}},
		[]probe.NamedProber{{Name: "icmp", Prober: fixedProber{}}},
		[]probe.NamedSource{{Name: "feed", Source: fixedSource{err: errors.New("feed unreachable")}}},
		probe.Options{Interval: time.Second, Timeout: time.Millisecond, Packets: 1, Workers: 1, PerTargetConcurrency: 1})
	if err != nil {
		t.Fatal(err)
	}
	e.RunOnce(context.Background())
	eng.Store(e)

	facts := systemFacts(set, &eng, health, nil)()
	if len(facts.Sources) != 1 || !facts.Sources[0].Seen || facts.Sources[0].Err != "feed unreachable" {
		t.Errorf("source facts = %+v", facts.Sources)
	}
	if facts.Storage == nil || facts.Storage.Last == nil || facts.Storage.Last.OK || !strings.Contains(facts.Storage.Last.Err, "readonly") {
		t.Errorf("storage fact = %+v", facts.Storage)
	}
	byName := map[string]httpapi.NotifierFact{}
	for _, n := range facts.Notifiers {
		byName[n.Name] = n
	}
	if h := byName["hook"]; h.Last == nil || h.Last.OK || !strings.Contains(h.Last.Err, "connection refused") {
		t.Errorf("failing notifier fact = %+v", h)
	}
	if m := byName["mail"]; m.Last != nil {
		t.Errorf("a notifier that never fired has a result: %+v", m)
	}
	if len(facts.RIBSources) != 1 || facts.RIBSources[0].Routers[router.String()].OK {
		t.Errorf("rib source facts = %+v", facts.RIBSources)
	}

	// Through the page's builder, the rows carry the state and no URL path.
	sys := httpapi.BuildSystem(httpapi.Snapshot{Mode: "observe"}, facts, nil, nil)
	state := map[string]string{}
	for _, c := range sys.Components {
		state[c.Kind+"/"+c.Name] = c.State
		if strings.Contains(c.Error+c.Detail, "s3cr3t") {
			t.Errorf("%s/%s leaks the hook URL: %+v", c.Kind, c.Name, c)
		}
	}
	for key, want := range map[string]string{
		"storage/db": httpapi.StateDown, "notifier/hook": httpapi.StateDown, "notifier/mail": httpapi.StateIdle,
		"source/feed": httpapi.StateDown, "rib_source/" + name: httpapi.StateDown, "announcer/announcer": httpapi.StateIdle,
	} {
		if state[key] != want {
			t.Errorf("%s = %q, want %q", key, state[key], want)
		}
	}
}

func TestStorageOutcomeShowsAFailedWriterOverAPassingOne(t *testing.T) {
	now := time.Date(2026, 9, 1, 10, 0, 0, 0, time.UTC)
	tr := syshealth.New(func() time.Time { return now })
	if got := storageOutcome(tr); got != nil {
		t.Fatalf("no write yet, outcome = %+v", got)
	}
	tr.Record(historyKey, errors.New("history write failed"))
	now = now.Add(time.Minute)
	tr.Record(eventsKey, nil)
	if got := storageOutcome(tr); got == nil || got.OK || got.Err != "history write failed" {
		t.Fatalf("event write hid a failed history write: %+v", got)
	}
	now = now.Add(time.Minute)
	tr.Record(historyKey, nil)
	if got := storageOutcome(tr); got == nil || !got.OK {
		t.Fatalf("both writers ok, outcome = %+v", got)
	}
}
