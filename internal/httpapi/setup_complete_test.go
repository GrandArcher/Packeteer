package httpapi

import (
	"context"
	"net/netip"
	"os"
	"os/exec"
	"strings"
	"testing"

	"github.com/GrandArcher/Packeteer/internal/preflight"
	"github.com/GrandArcher/Packeteer/internal/probe"
	"github.com/GrandArcher/Packeteer/internal/rib"
	"github.com/GrandArcher/Packeteer/pkg/plugin"
)

// upInput is an observe install whose iBGP neighbor is established, with a
// prefix learned and both providers measured.
func upInput() Input {
	in := firstRun()
	in.BGPConfigured = true
	in.RIBReady = true
	in.RIBPrefixes = 1
	in.Peers = []rib.PeerState{{Address: netip.MustParseAddr("192.0.2.254"), State: "established", Established: true}}
	return in
}

func TestSetupCompleteStates(t *testing.T) {
	cases := []struct {
		name   string
		mut    func(*Input)
		egress bool
		want   bool
	}{
		{"session up, prefix learned, probes fine", func(*Input) {}, false, true},
		{"no neighbor configured", func(in *Input) { in.BGPConfigured, in.Peers = false, nil }, false, false},
		{"session down", func(in *Input) { in.Peers[0].Established, in.Peers[0].State = false, "active" }, false, false},
		{"one of two sessions down", func(in *Input) {
			in.Peers = append(in.Peers, rib.PeerState{Address: netip.MustParseAddr("192.0.2.253"), State: "active"})
		}, false, false},
		{"nothing learned", func(in *Input) { in.RIBPrefixes = 0 }, false, false},
		{"a probe source is down", func(in *Input) {
			in.Status[1] = probe.ProviderStatus{Name: "transit-b", Up: false, Reason: "probe source address unavailable"}
		}, false, false},
		{"preflight egress fails", func(*Input) {}, true, false},
		{"controller still starting", func(in *Input) { in.Started = false }, false, false},
	}
	for _, c := range cases {
		in := upInput()
		c.mut(&in)
		o := BuildOverview(Assemble(in), Setup{Sources: []string{"static"}, DegradedLossPct: 5, DownLossPct: 50}, nil)
		if got := setupComplete(o, c.egress); got != c.want {
			t.Errorf("%s: setupComplete = %v, want %v (bgp %+v, problems %+v)", c.name, got, c.want, o.BGP, o.Problems)
		}
	}
}

func TestEgressCheckFails(t *testing.T) {
	rep := preflight.Report{Results: []preflight.Result{{ID: preflight.CheckEgress, Status: preflight.Warn}, {ID: "timers", Status: preflight.Fail}}}
	if egressCheckFails(rep) {
		t.Fatal("a warning, or another failing check, is not an egress failure")
	}
	rep.Results[0].Status = preflight.Fail
	if !egressCheckFails(rep) {
		t.Fatal("a failing probe_egress was not seen")
	}
}

// The API reports the state, reads the last preflight run, and goes back to
// incomplete when that run fails probe_egress.
func TestOverviewAPISetupComplete(t *testing.T) {
	facts := goodFacts()
	e := newUIWith(t, func(o *Options) { o.Snapshot = func() Snapshot { return Assemble(upInput()) } })
	store, err := preflight.OpenStore("")
	if err != nil {
		t.Fatal(err)
	}
	e.srv.SetPreflight(fakePreflight{preflight.NewRunner(func(context.Context) preflight.Facts { return facts }, store, nil)})
	complete := func() any {
		_, got := e.do(t, "GET", "/api/overview", plugin.RoleViewer, nil)
		return got["setup_complete"]
	}
	if complete() != true {
		t.Fatal("not complete before any preflight run")
	}
	e.do(t, "POST", "/api/preflight/run", plugin.RoleOperator, nil)
	if complete() != true {
		t.Fatal("not complete after a passing run")
	}
	facts.Providers[0].Egress = preflight.EgressMismatch
	e.do(t, "POST", "/api/preflight/run", plugin.RoleOperator, nil)
	if complete() != false {
		t.Fatal("complete while probe_egress fails")
	}
}

// TestSetupPage runs setup_page_test.js: the checklist's complete and
// incomplete states and the policy routing panel, against a DOM stand-in.
// Skipped without Node locally and required in CI.
func TestSetupPage(t *testing.T) {
	node, err := exec.LookPath("node")
	if err != nil {
		if os.Getenv("CI") != "" {
			t.Fatal("node is required in CI to run the setup page test")
		}
		t.Skip("node not installed")
	}
	out, err := exec.Command(node, "setup_page_test.js").CombinedOutput()
	if err != nil || !strings.Contains(string(out), "ok") {
		t.Fatalf("setup page: %v\n%s", err, out)
	}
}
