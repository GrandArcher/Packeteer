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

// #346: outside inject the router's path did not move, so no event says a
// prefix was steered; inject keeps its wording.
func TestEventWatchImprovementWording(t *testing.T) {
	p := netip.MustParsePrefix("198.51.100.0/24")
	changes := []policy.Change{
		{Action: policy.ActionImprove, New: policy.Improvement{Prefix: p, Provider: "lab-b", Native: "lab-a", Reason: "loss"}},
		{Action: policy.ActionSwitch, Old: policy.Improvement{Prefix: p, Provider: "lab-b", Native: "lab-a"}, New: policy.Improvement{Prefix: p, Provider: "lab-c", Native: "lab-a"}},
		{Action: policy.ActionRetire, Old: policy.Improvement{Prefix: p, Provider: "lab-c", Native: "lab-a", Reason: "native path better again"}},
	}
	cases := []struct {
		mode string
		want []string
	}{
		{"observe", []string{
			"Recommends moving 198.51.100.0/24 from lab-a to lab-b (not announced, observe mode)",
			"Recommends moving 198.51.100.0/24 from lab-a to lab-c (not announced, observe mode)",
			"No longer recommends moving 198.51.100.0/24 from lab-a to lab-c (native path better again) (not announced, observe mode)",
		}},
		{"suggest", []string{
			"Recommends moving 198.51.100.0/24 from lab-a to lab-b (not announced, suggest mode)",
			"Recommends moving 198.51.100.0/24 from lab-a to lab-c (not announced, suggest mode)",
			"No longer recommends moving 198.51.100.0/24 from lab-a to lab-c (native path better again) (not announced, suggest mode)",
		}},
		{"inject", []string{
			"198.51.100.0/24 steered to lab-b",
			"198.51.100.0/24 switched to lab-c",
			"198.51.100.0/24 returned to native routing (native path better again)",
		}},
	}
	for _, c := range cases {
		s := &sink{}
		newEventWatch(s, c.mode).improvements(time.Unix(10, 0), changes)
		got := s.take()
		if len(got) != len(c.want) {
			t.Fatalf("%s: %d events, want %d", c.mode, len(got), len(c.want))
		}
		for i, e := range got {
			if e.Message != c.want[i] {
				t.Errorf("%s event %d = %q, want %q", c.mode, i, e.Message, c.want[i])
			}
			if c.mode != "inject" && strings.Contains(e.Message, "steered") {
				t.Errorf("%s event %d says steered: %q", c.mode, i, e.Message)
			}
		}
	}
}

// probes builds one result per loss figure for a provider. A negative
// loss is a probe that errored.
func probes(provider string, losses ...float64) []probe.Result {
	var out []probe.Result
	for i, l := range losses {
		r := probe.Result{Provider: provider, Prefix: netip.PrefixFrom(netip.AddrFrom4([4]byte{198, 51, 100, byte(i)}), 32)}
		switch {
		case l < 0:
			r.Err = "no route"
		case l >= 100:
			r.Stats = probe.Stats{Sent: 3}
		default:
			r.Stats = probe.Stats{Sent: 3, Received: 3, LossPct: l}
		}
		out = append(out, r)
	}
	return out
}

func TestEventWatchProviderTransitions(t *testing.T) {
	s := &sink{}
	w := newEventWatch(s, "inject")
	src := netip.MustParseAddr("192.0.2.10")
	st := func(up bool) []probe.ProviderStatus {
		return []probe.ProviderStatus{{Name: "transit-a", Source: src, Up: up, Reason: "bind failed"}, {Name: "transit-b", Up: true}}
	}
	res := append(probes("transit-a", 0), probes("transit-b", 0)...)
	now := time.Now()
	w.providerStatus(now, st(true), res, 5, 50)
	if e := s.take(); len(e) != 0 {
		t.Fatalf("first up must be quiet: %s", kinds(e))
	}
	w.providerStatus(now, st(false), res, 5, 50)
	w.providerStatus(now, st(false), res, 5, 50)
	e := s.take()
	if kinds(e) != "provider.down" || e[0].Severity != plugin.SeverityCritical || e[0].Fields["reason"] != "bind failed" ||
		!strings.Contains(e[0].Message, "probe source failed (bind failed)") {
		t.Fatalf("down: %+v", e)
	}
	w.providerStatus(now, st(true), res, 5, 50)
	if e := s.take(); kinds(e) != "provider.up" || e[0].Message != "Provider transit-a is healthy again" {
		t.Fatalf("up: %+v", e)
	}
	// A provider first seen down is reported.
	w2 := newEventWatch(s, "inject")
	w2.providerStatus(now, st(false), res, 5, 50)
	if e := s.take(); kinds(e) != "provider.down" {
		t.Fatalf("initial down: %s", kinds(e))
	}
}

// A provider whose probes all fail is down, one above the degraded loss is
// degraded, and each clears with provider.up (#347).
func TestEventWatchProviderMeasured(t *testing.T) {
	s := &sink{}
	w := newEventWatch(s, "observe")
	up := func(names ...string) []probe.ProviderStatus {
		var out []probe.ProviderStatus
		for _, n := range names {
			out = append(out, probe.ProviderStatus{Name: n, Up: true})
		}
		return out
	}
	now := time.Now()
	check := func(res []probe.Result, want string) []plugin.Event {
		t.Helper()
		w.providerStatus(now, up("lab-a", "lab-b", "lab-c"), res, 5, 50)
		e := s.take()
		if kinds(e) != want {
			t.Fatalf("kinds = %q, want %q: %+v", kinds(e), want, e)
		}
		return e
	}
	healthy := probes("lab-a", 0, 0)
	// Nothing measured yet: quiet.
	check(nil, "")
	// lab-b loses every packet, lab-c never gets a probe through.
	e := check(append(append(append([]probe.Result{}, healthy...), probes("lab-b", 100, 100)...), probes("lab-c", -1, -1)...), "provider.down,provider.down")
	if e[0].Fields["provider"] != "lab-b" || e[0].Fields["reason"] != "100% loss" || e[0].Severity != plugin.SeverityCritical ||
		e[0].Message != "Provider lab-b is down: 100% loss on its probes" {
		t.Fatalf("lab-b: %+v", e[0])
	}
	if e[1].Fields["provider"] != "lab-c" || e[1].Fields["reason"] != "no answer" {
		t.Fatalf("lab-c: %+v", e[1])
	}
	// The same state is not repeated.
	check(append(append(append([]probe.Result{}, healthy...), probes("lab-b", 100, 100)...), probes("lab-c", -1, -1)...), "")
	// lab-b answers with 20% mean loss: degraded, a warning. lab-c recovers.
	e = check(append(append(append([]probe.Result{}, healthy...), probes("lab-b", 20, 20)...), probes("lab-c", 0)...), "provider.degraded,provider.up")
	if e[0].Severity != plugin.SeverityWarning || e[0].Fields["loss_pct"] != "20.0" || e[0].Fields["state"] != "degraded" ||
		e[0].Message != "Provider lab-b is degraded: 20% loss on its probes" {
		t.Fatalf("degraded: %+v", e[0])
	}
	// Worse again: down. Then back under the degraded line.
	check(append(append(append([]probe.Result{}, healthy...), probes("lab-b", 60, 60)...), probes("lab-c", 0)...), "provider.down")
	e = check(append(append(append([]probe.Result{}, healthy...), probes("lab-b", 1, 1)...), probes("lab-c", 0)...), "provider.up")
	if e[0].Fields["provider"] != "lab-b" || e[0].Resolves() != true || e[0].DedupKey() != "packeteer/provider/provider=lab-b" {
		t.Fatalf("up: %+v", e[0])
	}
	// A degraded event shares the dedup key that provider.up resolves.
	if d := plugin.NewEvent(plugin.EventProviderDegraded, now, "", map[string]string{"provider": "lab-b"}); d.DedupKey() != e[0].DedupKey() {
		t.Fatalf("dedup keys differ: %s vs %s", d.DedupKey(), e[0].DedupKey())
	}
	// Results that vanish keep the last state instead of flapping.
	check(nil, "")
}

func TestEventWatchPeers(t *testing.T) {
	s := &sink{}
	w := newEventWatch(s, "observe")
	a := netip.MustParseAddr("192.0.2.1")
	peer := func(est bool, state string) []rib.PeerState {
		return []rib.PeerState{{Address: a, Description: "edge1", State: state, Established: est}}
	}
	now := time.Now()
	const after = 5 * time.Minute
	w.peerStatus(now, peer(false, "idle"), after)
	if e := s.take(); len(e) != 0 {
		t.Fatalf("a session that is only starting must be quiet: %s", kinds(e))
	}
	w.peerStatus(now, peer(true, "established"), after)
	w.peerStatus(now, peer(true, "established"), after)
	w.peerStatus(now, peer(false, "active"), after)
	e := s.take()
	if kinds(e) != "bgp.session_up,bgp.session_down" || e[1].Fields["neighbor"] != "192.0.2.1" || e[1].Fields["state"] != "active" {
		t.Fatalf("peers %+v", e)
	}
	// Long after, the dropped session is not reported a second time.
	w.peerStatus(now.Add(time.Hour), peer(false, "active"), after)
	if e := s.take(); len(e) != 0 {
		t.Fatalf("a dropped session is reported once: %s", kinds(e))
	}
}

// A session that never reaches Established raises one event after the wait
// and bgp.session_up resolves it (#347).
func TestEventWatchPeerNeverEstablished(t *testing.T) {
	s := &sink{}
	w := newEventWatch(s, "observe")
	a := netip.MustParseAddr("192.0.2.1")
	peer := func(est bool, state string) []rib.PeerState {
		return []rib.PeerState{{Address: a, Description: "edge1", State: state, Established: est}}
	}
	t0 := time.Unix(1000, 0)
	const after = 5 * time.Minute
	w.peerStatus(t0, peer(false, "idle"), after)
	w.peerStatus(t0.Add(after-time.Second), peer(false, "active"), after)
	if e := s.take(); len(e) != 0 {
		t.Fatalf("before the wait: %s", kinds(e))
	}
	w.peerStatus(t0.Add(after), peer(false, "active"), after)
	e := s.take()
	if kinds(e) != "bgp.session_not_established" || e[0].Severity != plugin.SeverityCritical || e[0].Fields["state"] != "active" ||
		e[0].Fields["neighbor"] != "192.0.2.1" || e[0].Fields["after"] != "5m0s" ||
		!strings.Contains(e[0].Message, "edge1 (192.0.2.1) is still active after 5m0s") {
		t.Fatalf("not established: %+v", e)
	}
	w.peerStatus(t0.Add(2*after), peer(false, "idle"), after)
	if e := s.take(); len(e) != 0 {
		t.Fatalf("repeated: %s", kinds(e))
	}
	w.peerStatus(t0.Add(3*after), peer(true, "established"), after)
	e = s.take()
	if kinds(e) != "bgp.session_up" || e[0].DedupKey() != "packeteer/bgp/neighbor=192.0.2.1" || !e[0].Resolves() {
		t.Fatalf("up: %+v", e)
	}
	// With the wait off (zero) nothing fires.
	w2 := newEventWatch(s, "observe")
	w2.peerStatus(t0, peer(false, "idle"), 0)
	w2.peerStatus(t0.Add(time.Hour), peer(false, "idle"), 0)
	if e := s.take(); len(e) != 0 {
		t.Fatalf("zero wait: %s", kinds(e))
	}
}

// A routine restart in a mode that announces nothing is info and says so;
// inject, or a failed withdraw, keeps the warning (#347).
func TestEventWatchStopping(t *testing.T) {
	now := time.Now()
	for name, tc := range map[string]struct {
		mode      string
		announces bool
		err       error
		sev       plugin.Severity
		msg       string
		withdrawn string
	}{
		"observe": {"observe", false, nil, plugin.SeverityInfo, "Packeteer is shutting down (observe mode: it announced no routes)", "true"},
		"inject":  {"inject", true, nil, plugin.SeverityWarning, "Packeteer is shutting down; Packeteer routes withdrawn", "true"},
		"failed":  {"observe", false, errors.New("session lost"), plugin.SeverityWarning, "Packeteer is shutting down; Packeteer routes withdrawn", "false"},
	} {
		s := &sink{}
		newEventWatch(s, tc.mode).stopping(now, tc.mode, tc.announces, tc.err)
		e := s.take()
		if len(e) != 1 || e[0].Kind != plugin.EventControllerStopping || e[0].Severity != tc.sev || e[0].Message != tc.msg ||
			e[0].Fields["withdrawn"] != tc.withdrawn || e[0].Fields["mode"] != tc.mode {
			t.Errorf("%s: %+v", name, e)
		}
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

// #200: a source that was answering and goes stale (or empty) raises
// rpki.stale once, with its error, and rpki.fresh when it answers again.
// A source that never had data, or loads after the first round, raises
// nothing, so rpki.fresh never comes without an rpki.stale.
func TestRPKIEvents(t *testing.T) {
	out := &sink{}
	w := newEventWatch(out, "observe")
	now := time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC)
	fresh := plugin.RPKIStatus{Source: "routinator", Up: true, VRPs: 3, Updated: now}
	never := plugin.RPKIStatus{Source: "backup", Stale: true}
	loading := plugin.RPKIStatus{Source: "routinator", Error: "connection refused"}
	w.rpki(now, []plugin.RPKIStatus{loading, never})
	w.rpki(now.Add(time.Minute), []plugin.RPKIStatus{fresh, never})
	if got := out.take(); len(got) != 0 {
		t.Fatalf("startup events = %+v, want none: a source that loads late was never stale", got)
	}
	stale := plugin.RPKIStatus{Source: "routinator", Stale: true, VRPs: 3, Updated: now, Error: "connection refused"}
	for range 2 {
		w.rpki(now.Add(2*time.Hour), []plugin.RPKIStatus{stale, never})
	}
	got := out.take()
	if len(got) != 1 || got[0].Kind != plugin.EventRPKIStale || got[0].Severity != plugin.SeverityWarning ||
		got[0].Fields["source"] != "routinator" || got[0].Fields["error"] != "connection refused" || got[0].Fields["updated"] != "2026-01-02T03:04:05Z" {
		t.Fatalf("stale events = %+v", got)
	}
	w.rpki(now.Add(3*time.Hour), []plugin.RPKIStatus{fresh, never})
	got = out.take()
	if len(got) != 1 || got[0].Kind != plugin.EventRPKIFresh || !got[0].Resolves() || got[0].DedupKey() != "packeteer/rpki/source=routinator" {
		t.Fatalf("fresh events = %+v", got)
	}
	w.rpki(now.Add(5*time.Hour), []plugin.RPKIStatus{stale, never})
	if got := out.take(); len(got) != 1 || got[0].Kind != plugin.EventRPKIStale {
		t.Fatalf("second stale events = %+v", got)
	}
}
