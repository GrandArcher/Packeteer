package httpapi

import (
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/GrandArcher/Packeteer/internal/policy"
	"github.com/GrandArcher/Packeteer/internal/probe"
	"github.com/GrandArcher/Packeteer/pkg/plugin"
)

// TestConfidenceOnAPI checks that every probe row and decision candidate
// carries its confidence (#202), with the passive state Decide applied.
func TestConfidenceOnAPI(t *testing.T) {
	p := netip.MustParsePrefix("198.51.100.0/24")
	at := time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC)
	tcp := probe.Confidence{Level: probe.ConfidenceHigh, Score: 1, Protocol: "tcp", Replies: 4, Sent: 4}
	icmp := probe.Confidence{Level: probe.ConfidenceLow, Score: 0.25, Protocol: "icmp", Replies: 4, Sent: 4, Passive: probe.PassiveDisagree}
	e := newUIWith(t, func(o *Options) {
		o.Snapshot = func() Snapshot {
			return Assemble(Input{
				Version: "test", Mode: "observe", Started: true, At: at,
				Results: []probe.Result{
					{Provider: "transit-a", Prefix: p, Prober: "ping", Stats: probe.Stats{Sent: 4, Received: 4, LossPct: 0, RTTAvg: 40 * time.Millisecond}, Time: at,
						Confidence: probe.Confidence{Level: probe.ConfidenceMedium, Score: 0.5, Protocol: "icmp", Replies: 4, Sent: 4}},
					{Provider: "transit-b", Prefix: p, Prober: "syn", Indirect: true, Stats: probe.Stats{Sent: 4, Received: 1, LossPct: 75, RTTAvg: 30 * time.Millisecond}, Time: at,
						Confidence: probe.Confidence{Level: probe.ConfidenceLow, Score: 0.25, Protocol: "tcp", Replies: 1, Sent: 4, Indirect: true}},
				},
				Decisions: []policy.Decision{{
					Prefix: p, Native: "transit-a", Current: "transit-a", Recommended: "transit-b", Action: policy.ActionNone,
					Reason: "require_evidence: ICMP-only measurement for transit-a (icmp, 4/4 replies, passive disagrees)",
					Candidates: []policy.Candidate{
						{Provider: "transit-a", Usable: true, Confidence: icmp},
						{Provider: "transit-b", Usable: true, Confidence: tcp},
					},
				}},
			})
		}
	})
	viewer := plugin.RoleViewer
	rec, _ := e.do(t, "GET", "/api/decisions", viewer, nil)
	for _, want := range []string{
		`"confidence":{"level":"low","score":0.25,"protocol":"icmp","replies":4,"sent":4,"passive":"disagree"},"evidence":"icmp, 4/4 replies, passive disagrees"`,
		`"confidence":{"level":"high","score":1,"protocol":"tcp","replies":4,"sent":4},"evidence":"tcp, 4/4 replies"`,
	} {
		if rec.Code != 200 || !strings.Contains(rec.Body.String(), want) {
			t.Fatalf("decisions = %d %s, want %s", rec.Code, rec.Body.String(), want)
		}
	}
	for _, path := range []string{"/api/probes", "/api/prefixes"} {
		rec, _ = e.do(t, "GET", path, viewer, nil)
		for _, want := range []string{
			`"confidence":{"level":"medium","score":0.5,"protocol":"icmp","replies":4,"sent":4},"evidence":"icmp, 4/4 replies"`,
			`"confidence":{"level":"low","score":0.25,"protocol":"tcp","replies":1,"sent":4,"indirect":true},"evidence":"tcp, 1/4 replies, traceroute hop"`,
		} {
			if rec.Code != 200 || !strings.Contains(rec.Body.String(), want) {
				t.Fatalf("%s = %d %s, want %s", path, rec.Code, rec.Body.String(), want)
			}
		}
	}
}

// TestConfidenceAssets checks the prefix card and Why panel wiring (#202).
// The rendered card is covered by the UI smoke steps in CI.
func TestConfidenceAssets(t *testing.T) {
	app := mustWeb(t, "web/app.js")
	page := mustWeb(t, "web/prefix.js")
	for _, s := range []string{
		`["Provider", "Loss", "RTT", "Jitter", "Probe", "Confidence"]`,
		`confidenceCell(pr.confidence && pr.confidence.level, pr.evidence)`,
		`level === "low" ? "badge warn" : "badge"`,
	} {
		if !strings.Contains(app, s) {
			t.Errorf("app.js missing %s", s)
		}
	}
	for _, s := range []string{
		`evidence: "Measurement evidence"`,
		`confidenceCell(s.confidence, s.evidence)`,
		`"Score", "Confidence", "State"`,
	} {
		if !strings.Contains(page, s) {
			t.Errorf("prefix.js missing %s", s)
		}
	}
	if strings.Contains(app[strings.Index(app, "function confidenceCell"):], "innerHTML") {
		t.Error("confidenceCell builds markup")
	}
}
