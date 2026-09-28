package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/GrandArcher/Packeteer/internal/policy"
	"github.com/GrandArcher/Packeteer/internal/probe"
	"github.com/GrandArcher/Packeteer/internal/rib"
	"github.com/GrandArcher/Packeteer/pkg/plugin"
)

type sink struct {
	mu  sync.Mutex
	got []plugin.Event
}

func (s *sink) Emit(e plugin.Event) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.got = append(s.got, e)
}

func (s *sink) take() []plugin.Event {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := s.got
	s.got = nil
	return out
}

func kinds(evs []plugin.Event) string {
	var k []string
	for _, e := range evs {
		k = append(k, e.Kind)
	}
	return strings.Join(k, ",")
}

func TestEventWatchImprovements(t *testing.T) {
	s := &sink{}
	w := newEventWatch(s, "observe")
	p := netip.MustParsePrefix("198.51.100.0/24")
	now := time.Unix(10, 0)
	w.improvements(now, []policy.Change{
		{Action: policy.ActionImprove, New: policy.Improvement{Prefix: p, Provider: "transit-b", Native: "transit-a", Cause: "performance", Reason: "loss"}},
		{Action: policy.ActionSwitch, Old: policy.Improvement{Prefix: p, Provider: "transit-b"}, New: policy.Improvement{Prefix: p, Provider: "transit-c", Native: "transit-a"}},
		{Action: policy.ActionRetire, Old: policy.Improvement{Prefix: p, Provider: "transit-c", Native: "transit-a", Reason: "stale"}},
		{Action: policy.ActionKeep},
	})
	got := s.take()
	if kinds(got) != "improvement.added,improvement.switched,improvement.removed" {
		t.Fatalf("kinds %s", kinds(got))
	}
	if got[0].Fields["prefix"] != p.String() || got[0].Fields["mode"] != "observe" || !strings.Contains(got[0].Message, "not announced") {
		t.Fatalf("added %+v", got[0])
	}
	if got[1].Fields["previous"] != "transit-b" || got[2].Fields["provider"] != "transit-c" || got[2].Fields["reason"] != "stale" {
		t.Fatalf("switch/remove %+v %+v", got[1], got[2])
	}
	if !got[0].Time.Equal(now) || got[0].DedupKey() != got[2].DedupKey() {
		t.Fatal("time or dedup key")
	}
	wi := newEventWatch(s, "inject")
	wi.improvements(now, []policy.Change{{Action: policy.ActionImprove, New: policy.Improvement{Prefix: p, Provider: "transit-b"}}})
	if e := s.take(); strings.Contains(e[0].Message, "not announced") {
		t.Fatalf("inject message %q", e[0].Message)
	}
}

func TestEventWatchProviderTransitions(t *testing.T) {
	s := &sink{}
	w := newEventWatch(s, "inject")
	src := netip.MustParseAddr("192.0.2.10")
	st := func(up bool) []probe.ProviderStatus {
		return []probe.ProviderStatus{{Name: "transit-a", Source: src, Up: up, Reason: "bind failed"}, {Name: "transit-b", Up: true}}
	}
	now := time.Now()
	w.providerStatus(now, st(true))
	if e := s.take(); len(e) != 0 {
		t.Fatalf("first up must be quiet: %s", kinds(e))
	}
	w.providerStatus(now, st(false))
	w.providerStatus(now, st(false))
	e := s.take()
	if kinds(e) != "provider.down" || e[0].Severity != plugin.SeverityCritical || e[0].Fields["reason"] != "bind failed" {
		t.Fatalf("down: %+v", e)
	}
	w.providerStatus(now, st(true))
	if e := s.take(); kinds(e) != "provider.up" {
		t.Fatalf("up: %s", kinds(e))
	}
	// A provider first seen down is reported.
	w2 := newEventWatch(s, "inject")
	w2.providerStatus(now, st(false))
	if e := s.take(); kinds(e) != "provider.down" {
		t.Fatalf("initial down: %s", kinds(e))
	}
}

func TestEventWatchPeers(t *testing.T) {
	s := &sink{}
	w := newEventWatch(s, "observe")
	a := netip.MustParseAddr("192.0.2.1")
	peer := func(est bool, state string) []rib.PeerState {
		return []rib.PeerState{{Address: a, Description: "edge1", State: state, Established: est}}
	}
	now := time.Now()
	w.peerStatus(now, peer(false, "idle"))
	if e := s.take(); len(e) != 0 {
		t.Fatalf("never-up session must be quiet: %s", kinds(e))
	}
	w.peerStatus(now, peer(true, "established"))
	w.peerStatus(now, peer(true, "established"))
	w.peerStatus(now, peer(false, "active"))
	e := s.take()
	if kinds(e) != "bgp.session_up,bgp.session_down" || e[1].Fields["neighbor"] != "192.0.2.1" || e[1].Fields["state"] != "active" {
		t.Fatalf("peers %+v", e)
	}
}

func TestEventWatchCommit(t *testing.T) {
	s := &sink{}
	w := newEventWatch(s, "observe")
	u := func(p95 float64) []plugin.Usage {
		return []plugin.Usage{
			{Provider: "transit-a", CommitMbps: 100, Samples: 10, InMbps95: p95, OutMbps95: 20, Mode: plugin.PercentileSeparate},
			{Provider: "transit-b", CommitMbps: 0, Samples: 10, InMbps95: 500},  // no commit
			{Provider: "transit-c", CommitMbps: 100, Samples: 0, InMbps95: 500}, // no samples yet
		}
	}
	now := time.Now()
	w.commit(now, u(90))
	w.commit(now, u(120))
	w.commit(now, u(130))
	w.commit(now, u(100))
	e := s.take()
	if kinds(e) != "commit.exceeded,commit.cleared" {
		t.Fatalf("commit kinds %s", kinds(e))
	}
	if e[0].Fields["usage_mbps"] != "120.0" || e[0].Fields["commit_mbps"] != "100.0" || e[0].Severity != plugin.SeverityWarning {
		t.Fatalf("exceeded %+v", e[0])
	}
	w.commit(now, []plugin.Usage{{Provider: "transit-a", CommitMbps: 100, Samples: 1, Single: true, UsageMbps: 101}})
	if e := s.take(); kinds(e) != "commit.exceeded" {
		t.Fatalf("single figure: %s", kinds(e))
	}
}

func TestCommitDue(t *testing.T) {
	w := newEventWatch(&sink{}, "observe")
	t0 := time.Unix(1000, 0)
	if !w.commitDue(t0) || w.commitDue(t0.Add(30*time.Second)) || !w.commitDue(t0.Add(time.Minute)) {
		t.Fatal("commit checks must be spaced by commitCheckInterval")
	}
}

func TestEventWatchAnnounce(t *testing.T) {
	s := &sink{}
	w := newEventWatch(s, "inject")
	now := time.Now()
	w.announce(now, nil)
	w.announce(now, errors.New("session down"))
	w.announce(now, errors.New("session down"))
	w.announce(now, nil)
	if e := s.take(); kinds(e) != "announce.failed,announce.recovered" {
		t.Fatalf("announce kinds %s", kinds(e))
	}
	var nilW *eventWatch
	nilW.announce(now, errors.New("x")) // no panic
}

// TestEventsDocCoversCatalog keeps docs/EVENTS.md in step with the catalog.
func TestEventsDocCoversCatalog(t *testing.T) {
	doc, err := os.ReadFile("../../docs/EVENTS.md")
	if err != nil {
		t.Fatal(err)
	}
	text := string(doc)
	for _, s := range plugin.EventCatalog() {
		row := "| `" + s.Kind + "` | " + string(s.Severity) + " | " + strconv.Itoa(s.TrapID) + " |"
		if !strings.Contains(text, row) {
			t.Errorf("docs/EVENTS.md is missing the row prefix %q", row)
		}
	}
}

func TestRunNotifyTest(t *testing.T) {
	var got []string
	var mu sync.Mutex
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var ev plugin.Event
		_ = json.NewDecoder(r.Body).Decode(&ev)
		mu.Lock()
		got = append(got, ev.Kind)
		mu.Unlock()
		w.WriteHeader(http.StatusNoContent)
	}))
	defer srv.Close()
	example, err := os.ReadFile(filepath.Join("..", "..", "config.example.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "c.yaml")
	cfg := string(example) + "\nnotifiers:\n" +
		"  - type: webhook\n    name: hook\n    config: {url: \"" + srv.URL + "\"}\n" +
		"  - type: webhook\n    name: pager\n    config: {url: \"" + srv.URL + "\", min_severity: critical}\n" +
		"  - type: webhook\n    name: dead\n    config: {url: \"http://127.0.0.1:1/x\", timeout: 1s}\n"
	if err := os.WriteFile(path, []byte(cfg), 0o600); err != nil {
		t.Fatal(err)
	}
	var out, errOut bytes.Buffer
	code := run(context.Background(), []string{"-notify-test", "-config", path}, noEnv, &out, &errOut)
	if code != 1 {
		t.Fatalf("exit %d (want 1 for the dead notifier)\n%s%s", code, out.String(), errOut.String())
	}
	for _, want := range []string{"notify-test: hook: sent", "notify-test: pager: filtered", "notify-test: dead: FAILED"} {
		if !strings.Contains(out.String(), want) {
			t.Errorf("stdout missing %q:\n%s", want, out.String())
		}
	}
	mu.Lock()
	defer mu.Unlock()
	if len(got) != 1 || got[0] != plugin.EventTest {
		t.Fatalf("received %v", got)
	}

	out.Reset()
	if code := run(context.Background(), []string{"-notify-test", "-config", filepath.Join("..", "..", "config.example.yaml")}, noEnv, &out, &errOut); code != 1 ||
		!strings.Contains(out.String(), "no notifiers configured") {
		t.Fatalf("exit %d: %s", code, out.String())
	}
}
