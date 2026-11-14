package pbr

import (
	"context"
	"errors"
	"slices"
	"strings"
	"testing"
)

func newManager(h *fakeHost, es []Entry) *Manager {
	return &Manager{Run: h.exec, Entries: func() []Entry { return es }}
}

// A preview runs no changing command, lists what apply would run, and says
// each provider does not leave through its next hop yet.
func TestManagerPreviewChangesNothing(t *testing.T) {
	h := newHost()
	h.rules = []string{"1001:\tfrom 198.51.100.5 lookup 5000", "2500:\tfrom 198.51.100.6 lookup 5000"}
	before := slices.Clone(h.rules)
	m := newManager(h, entries(t, twoProviders))
	p, err := m.Preview(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(h.log) != 0 || !slices.Equal(h.rules, before) || len(h.routes) != 0 {
		t.Fatalf("preview changed the host: log=%v rules=%v routes=%v", h.log, h.rules, h.routes)
	}
	var cmds []string
	for _, l := range p.Lines {
		cmds = append(cmds, l.Command)
		if l.Remove {
			t.Fatalf("a fresh host has nothing to remove: %+v", l)
		}
	}
	want := []string{
		"ip route replace default via 192.0.2.1 table 1001",
		"ip route replace default via 192.0.2.2 table 1002",
		"ip rule add from 192.0.2.11 lookup 1001 priority 2001",
		"ip rule add from 192.0.2.12 fwmark 7 lookup 1002 priority 2002",
	}
	if !slices.Equal(cmds, want) {
		t.Fatalf("lines =\n%s\nwant\n%s", strings.Join(cmds, "\n"), strings.Join(want, "\n"))
	}
	if len(p.Paths) != 2 || p.Paths[0].OK || p.Paths[1].OK || p.Paths[0].Provider != "transit-a" || p.Token == "" {
		t.Fatalf("paths = %+v token = %q", p.Paths, p.Token)
	}
}

// Apply with the token of the shown plan installs the routes, and the
// kernel then sends each source through its next hop. Rules outside the
// managed priorities and tables stay as they were.
func TestManagerApplyMatchesNextHops(t *testing.T) {
	h := newHost()
	foreign := []string{"1001:\tfrom 198.51.100.5 lookup 5000", "2500:\tfrom 198.51.100.6 lookup 5000", "100:\tfrom 198.51.100.7 lookup 2005"}
	h.rules = slices.Clone(foreign)
	m := newManager(h, entries(t, twoProviders))
	p, err := m.Preview(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	res, err := m.Apply(context.Background(), p.Token)
	if err != nil {
		t.Fatal(err)
	}
	if res.Applied != 4 || !res.Verified {
		t.Fatalf("result = %+v", res)
	}
	if h.routes["4 1001"] != "192.0.2.1" || h.routes["4 1002"] != "192.0.2.2" {
		t.Fatalf("routes = %v", h.routes)
	}
	for _, r := range foreign {
		if !slices.Contains(h.rules, r) {
			t.Fatalf("rule %q is gone: %v", r, h.rules)
		}
	}
	for _, c := range h.log {
		for _, r := range foreign {
			if strings.Contains(c, strings.Fields(r)[2]) {
				t.Fatalf("a command touched a rule that is not Packeteer's: %s", c)
			}
		}
	}
	// The same plan again has nothing to do.
	again, err := m.Preview(context.Background())
	if err != nil || len(again.Lines) != 0 || !again.Paths[0].OK || !again.Paths[1].OK {
		t.Fatalf("second preview = %+v, %v", again, err)
	}
}

// A provider that is gone has its rules and routes removed, and a rule that
// is not Packeteer's is still left alone.
func TestManagerApplyRemovesOnlyPacketeerRules(t *testing.T) {
	h := newHost()
	es := entries(t, twoProviders)
	m := newManager(h, es)
	p, _ := m.Preview(context.Background())
	if _, err := m.Apply(context.Background(), p.Token); err != nil {
		t.Fatal(err)
	}
	h.rules = append(h.rules, "1002:\tfrom 198.51.100.5 lookup 1002", "2002:\tiif eth9 lookup 1002")
	m.Entries = func() []Entry { return es[:1] }
	p, err := m.Preview(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	for _, l := range p.Lines {
		if !l.Remove || strings.Contains(l.Command, "198.51.100.5") || strings.Contains(l.Command, "eth9") {
			t.Fatalf("unexpected line %+v", l)
		}
	}
	if _, err := m.Apply(context.Background(), p.Token); err != nil {
		t.Fatal(err)
	}
	for _, r := range []string{"1002:\tfrom 198.51.100.5 lookup 1002", "2002:\tiif eth9 lookup 1002"} {
		if !slices.Contains(h.rules, r) {
			t.Fatalf("foreign rule %q removed: %v", r, h.rules)
		}
	}
	if h.routes["4 1002"] != "" {
		t.Fatalf("route of the removed provider stays: %v", h.routes)
	}
}

// Without the confirmed token, or with the token of an older plan, nothing
// runs.
func TestManagerApplyRefusesAnotherPlan(t *testing.T) {
	h := newHost()
	es := entries(t, twoProviders)
	m := newManager(h, es)
	p, _ := m.Preview(context.Background())
	for _, tok := range []string{"", "deadbeef"} {
		if _, err := m.Apply(context.Background(), tok); !errors.Is(err, ErrPlanChanged) {
			t.Fatalf("token %q: %v", tok, err)
		}
	}
	m.Entries = func() []Entry { return es[:1] }
	if _, err := m.Apply(context.Background(), p.Token); !errors.Is(err, ErrPlanChanged) {
		t.Fatalf("stale token: %v", err)
	}
	if len(h.log) != 0 || len(h.rules) != 0 {
		t.Fatalf("a refused apply changed the host: %v %v", h.log, h.rules)
	}
}

// A failing step undoes what ran and returns the error; the host is as it
// was.
func TestManagerApplyFailureRollsBack(t *testing.T) {
	h := newHost()
	h.fail["rule add from 192.0.2.12 fwmark 7 lookup 1002 priority 2002"] = struct{}{}
	m := newManager(h, entries(t, twoProviders))
	p, _ := m.Preview(context.Background())
	if _, err := m.Apply(context.Background(), p.Token); err == nil {
		t.Fatal("apply passed a failing step")
	}
	if len(h.rules) != 0 || len(h.routes) != 0 {
		t.Fatalf("host not restored: rules=%v routes=%v", h.rules, h.routes)
	}
}

// A route that leaves the wrong way after the change is reported, not hidden.
func TestManagerApplyReportsAPathThatDoesNotVerify(t *testing.T) {
	h := newHost()
	es := entries(t, twoProviders)
	m := newManager(h, es)
	p, _ := m.Preview(context.Background())
	// Another rule outranks the new one for this source.
	h.rules = append(h.rules, "100:\tfrom 192.0.2.11 lookup 1002")
	h.routes["4 1002"] = "192.0.2.77"
	res, err := m.Apply(context.Background(), p.Token)
	if err != nil {
		t.Fatal(err)
	}
	if res.Verified || res.Paths[0].OK || res.Paths[0].Detail == "" || !res.Paths[1].OK {
		t.Fatalf("result = %+v", res)
	}
}

func TestManagerNoProviders(t *testing.T) {
	m := newManager(newHost(), nil)
	if _, err := m.Preview(context.Background()); err == nil {
		t.Fatal("previewed with no provider")
	}
}
