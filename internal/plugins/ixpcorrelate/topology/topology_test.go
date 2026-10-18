package topology

import (
	"context"
	"fmt"
	"strings"
	"testing"
	"time"

	"gopkg.in/yaml.v3"

	"github.com/GrandArcher/Packeteer/pkg/plugin"
)

var t0 = time.Date(2026, 10, 18, 12, 0, 0, 0, time.UTC)

// sw is a switch in a documentation colo.
func sw(id int, colo string) plugin.FabricSwitch {
	return plugin.FabricSwitch{ID: id, Name: fmt.Sprintf("sw%d", id), Colo: colo}
}

// smp is one probe of one member address from one vantage.
func smp(vantage string, asn uint32, addr string, bad bool, switches ...plugin.FabricSwitch) plugin.FabricSample {
	return plugin.FabricSample{
		Vantage: vantage, ASN: asn, Name: fmt.Sprintf("member-%d", asn), Address: addr,
		Family: "ipv4", VLANID: 10, IXPID: 1, Switches: switches,
		Sent: 5, Received: 5, PastTolerance: bad,
	}
}

// members returns n members starting at base, one address each behind sw.
func members(base uint32, n int, bad bool, sws ...plugin.FabricSwitch) []plugin.FabricSample {
	var out []plugin.FabricSample
	for i := 0; i < n; i++ {
		asn := base + uint32(i)
		out = append(out, smp("v1", asn, fmt.Sprintf("192.0.2.%d", asn-64000), bad, sws...))
	}
	return out
}

func cat(parts ...[]plugin.FabricSample) []plugin.FabricSample {
	var out []plugin.FabricSample
	for _, p := range parts {
		out = append(out, p...)
	}
	return out
}

func newCorrelator(t *testing.T, yamlCfg string) (*Correlator, *[]plugin.Event) {
	t.Helper()
	var node yaml.Node
	if err := yaml.Unmarshal([]byte(yamlCfg), &node); err != nil {
		t.Fatal(err)
	}
	p, err := New(plugin.NewConfig(&node), plugin.Env{})
	if err != nil {
		t.Fatal(err)
	}
	c := p.(*Correlator)
	var got []plugin.Event
	c.SetEventSink(func(e plugin.Event) { got = append(got, e) })
	c.now = func() time.Time { return t0 }
	return c, &got
}

// round feeds one fabric round. n distinguishes rounds.
func round(c *Correlator, n int, samples []plugin.FabricSample) {
	c.evaluate(plugin.FabricView{Configured: true, Round: t0.Add(time.Duration(n) * time.Minute), Samples: samples})
}

func kinds(evs []plugin.Event) []string {
	var out []string
	for _, e := range evs {
		out = append(out, e.Kind+" "+e.Fields["scope"]+e.Fields["asn"]+" "+e.Fields["group"])
	}
	return out
}

func TestSwitchFaultIsFabricNotMember(t *testing.T) {
	c, got := newCorrelator(t, "rounds: 1")
	s1, s2 := sw(1, "colo-a"), sw(2, "colo-b")
	round(c, 1, cat(members(64500, 5, true, s1), members(64600, 4, false, s2)))
	want := []string{
		"ixp.fabric_degraded colo colo-a",
		"ixp.fabric_degraded switch 1",
	}
	if g := kinds(*got); !sameSet(g, want) {
		t.Fatalf("events %v, want %v", g, want)
	}
	for _, e := range *got {
		if e.Kind == plugin.EventMemberDegraded {
			t.Fatalf("a member behind a degraded switch must not raise member_degraded: %+v", e)
		}
		if e.Fields["members"] != "5" || e.Fields["degraded"] != "5" || e.Fields["ixp_id"] != "1" {
			t.Fatalf("fields %v", e.Fields)
		}
		if e.Fields["asns"] != "64500,64501,64502,64503,64504" {
			t.Fatalf("asns %q", e.Fields["asns"])
		}
	}
	v := c.View()
	if len(v.Members) != 0 {
		t.Fatalf("members %+v", v.Members)
	}
	var sw2 *plugin.CorrelationGroup
	for i := range v.Groups {
		if v.Groups[i].Name == "sw2" {
			sw2 = &v.Groups[i]
		}
	}
	if sw2 == nil || sw2.Members != 4 || sw2.Degraded != 0 || sw2.Active {
		t.Fatalf("sw2 %+v", sw2)
	}
}

func sameSet(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	m := map[string]int{}
	for _, x := range a {
		m[x]++
	}
	for _, x := range b {
		m[x]--
	}
	for _, n := range m {
		if n != 0 {
			return false
		}
	}
	return true
}

func TestSingleMemberIsMemberNotFabric(t *testing.T) {
	c, got := newCorrelator(t, "rounds: 1")
	s1 := sw(1, "colo-a")
	round(c, 1, cat(members(64500, 1, true, s1), members(64501, 8, false, s1)))
	if g := kinds(*got); len(g) != 1 || g[0] != "ixp.member_degraded 64500 " {
		t.Fatalf("events %v", g)
	}
	e := (*got)[0]
	if e.Severity != plugin.SeverityWarning || e.Fields["addresses"] != "1" || e.Fields["name"] != "member-64500" {
		t.Fatalf("event %+v", e)
	}
	v := c.View()
	if len(v.Members) != 1 || v.Members[0].ASN != 64500 || !v.Members[0].Active {
		t.Fatalf("members %+v", v.Members)
	}
	for _, g := range v.Groups {
		if g.Active || g.Degraded != 1 {
			t.Fatalf("group %+v", g)
		}
	}
}

func TestThresholds(t *testing.T) {
	s1 := sw(1, "colo-a")
	cases := []struct {
		name        string
		cfg         string
		bad, good   int
		wantFabric  bool
		wantMembers int
	}{
		{"two of two is below min_members", "rounds: 1", 2, 0, false, 2},
		{"three of three fires", "rounds: 1", 3, 0, true, 0},
		{"three of ten is under the share", "rounds: 1", 3, 7, false, 3},
		{"five of ten fires at 50 percent", "rounds: 1", 5, 5, true, 0},
		{"custom share", "rounds: 1\ndegraded_pct: 20", 3, 7, true, 0},
		{"custom min_members", "rounds: 1\nmin_members: 2", 2, 0, true, 0},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			c, got := newCorrelator(t, tc.cfg)
			round(c, 1, cat(members(64500, tc.bad, true, s1), members(64700, tc.good, false, s1)))
			fabric, mem := 0, 0
			for _, e := range *got {
				switch e.Kind {
				case plugin.EventFabricDegraded:
					fabric++
				case plugin.EventMemberDegraded:
					mem++
				}
			}
			if (fabric > 0) != tc.wantFabric || mem != tc.wantMembers {
				t.Fatalf("fabric %d members %d, events %v", fabric, mem, kinds(*got))
			}
		})
	}
}

func TestMeasurementRules(t *testing.T) {
	c, got := newCorrelator(t, "rounds: 1\nmin_members: 2")
	s1 := sw(1, "colo-a")
	// 64500 is bad from v1 but fine from v2: not degraded. 64501 and
	// 64502 are bad from every vantage that measured them. 64503 has only
	// probe errors: not measured. 64504 has one bad and one good address:
	// not degraded.
	samples := []plugin.FabricSample{
		smp("v1", 64500, "192.0.2.1", true, s1), smp("v2", 64500, "192.0.2.1", false, s1),
		smp("v1", 64501, "192.0.2.2", true, s1), smp("v2", 64501, "192.0.2.2", true, s1),
		smp("v1", 64502, "192.0.2.3", true, s1),
		smp("v1", 64504, "192.0.2.5", true, s1), smp("v1", 64504, "192.0.2.6", false, s1),
		{Vantage: "v1", ASN: 64503, Address: "192.0.2.4", IXPID: 1, VLANID: 10, Switches: []plugin.FabricSwitch{s1}, Error: "send failed", PastTolerance: true},
	}
	round(c, 1, samples)
	v := c.View()
	var g plugin.CorrelationGroup
	for _, x := range v.Groups {
		if x.Scope == plugin.ScopeSwitch {
			g = x
		}
	}
	if g.Members != 4 || g.Degraded != 2 || len(g.ASNs) != 2 || g.ASNs[0] != 64501 || g.ASNs[1] != 64502 || !g.Active {
		t.Fatalf("group %+v", g)
	}
	if g.DegradedPct != 50 {
		t.Fatalf("pct %v", g.DegradedPct)
	}
	if len(*got) != 2 { // switch and colo
		t.Fatalf("events %v", kinds(*got))
	}
}

func TestMemberOnTwoSwitches(t *testing.T) {
	c, got := newCorrelator(t, "rounds: 1")
	s1, s2 := sw(1, "colo-a"), sw(2, "colo-b")
	// 64500 has an address behind each switch. Only the one behind sw1 is
	// bad, so the member is degraded in sw1 but not overall.
	samples := cat(
		[]plugin.FabricSample{smp("v1", 64500, "192.0.2.1", true, s1), smp("v1", 64500, "192.0.2.2", false, s2)},
		members(64501, 2, true, s1),
	)
	round(c, 1, samples)
	if g := kinds(*got); !sameSet(g, []string{"ixp.fabric_degraded switch 1", "ixp.fabric_degraded colo colo-a"}) {
		t.Fatalf("events %v", g)
	}
}

func TestBundleGroup(t *testing.T) {
	cfg := "rounds: 1\nbundles:\n  - name: core-1\n    ixp_id: 1\n    switches: [1, 2]\n  - name: core-other\n    ixp_id: 2\n    switches: [1]\n"
	c, got := newCorrelator(t, cfg)
	s1, s2, s3 := sw(1, "colo-a"), sw(2, "colo-b"), sw(3, "colo-c")
	// Two members per switch on the bundle fail, which is under min_members
	// for each switch and colo but not for the bundle.
	round(c, 1, cat(members(64500, 2, true, s1), members(64510, 2, true, s2), members(64520, 4, false, s3)))
	g := kinds(*got)
	if len(g) != 1 || g[0] != "ixp.fabric_degraded bundle core-1" {
		t.Fatalf("events %v", g)
	}
	if (*got)[0].Fields["degraded"] != "4" || (*got)[0].Fields["members"] != "4" {
		t.Fatalf("fields %v", (*got)[0].Fields)
	}
	// A member behind a degraded bundle is explained, so no member event.
	for _, e := range *got {
		if e.Kind == plugin.EventMemberDegraded {
			t.Fatalf("member event %+v", e)
		}
	}
}

func TestHysteresis(t *testing.T) {
	c, got := newCorrelator(t, "") // rounds default 2
	s1 := sw(1, "colo-a")
	bad := members(64500, 4, true, s1)
	good := members(64500, 4, false, s1)

	round(c, 1, bad)
	if len(*got) != 0 {
		t.Fatalf("one bad round raised %v", kinds(*got))
	}
	round(c, 2, good) // a single bad round does not count
	round(c, 3, bad)
	if len(*got) != 0 {
		t.Fatalf("a broken streak raised %v", kinds(*got))
	}
	round(c, 4, bad)
	if len(*got) != 2 {
		t.Fatalf("two bad rounds in a row: %v", kinds(*got))
	}
	// The same round again is not a new observation.
	round(c, 4, good)
	if len(*got) != 2 {
		t.Fatalf("repeated round: %v", kinds(*got))
	}
	round(c, 5, good)
	if len(*got) != 2 {
		t.Fatalf("one good round resolved: %v", kinds(*got))
	}
	if v := c.View(); !v.Groups[0].Active {
		t.Fatalf("the group stays active until it clears: %+v", v.Groups)
	}
	round(c, 6, good)
	if len(*got) != 4 {
		t.Fatalf("recovery: %v", kinds(*got))
	}
	rec := (*got)[2:]
	for i, want := range []string{plugin.EventFabricRecovered, plugin.EventFabricRecovered} {
		if rec[i].Kind != want || !rec[i].Resolves() {
			t.Fatalf("recovery %d: %+v", i, rec[i])
		}
	}
	if (*got)[0].DedupKey() != findKind(rec, (*got)[0].Fields["scope"]).DedupKey() {
		t.Fatalf("a recovery must share its problem's dedup key")
	}
	round(c, 7, good)
	if len(c.groups) != 0 || len(c.member) != 0 {
		t.Fatalf("state leaked: %d groups %d members", len(c.groups), len(c.member))
	}
}

func findKind(evs []plugin.Event, scope string) plugin.Event {
	for _, e := range evs {
		if e.Fields["scope"] == scope {
			return e
		}
	}
	return plugin.Event{}
}

func TestMemberThenFabric(t *testing.T) {
	c, got := newCorrelator(t, "rounds: 1")
	s1 := sw(1, "colo-a")
	round(c, 1, cat(members(64500, 1, true, s1), members(64501, 5, false, s1)))
	if g := kinds(*got); len(g) != 1 || g[0] != "ixp.member_degraded 64500 " {
		t.Fatalf("events %v", g)
	}
	// The rest of the switch fails too: now the whole switch is the
	// problem and the first member is no longer a separate one.
	*got = nil
	round(c, 2, members(64500, 6, true, s1))
	g := kinds(*got)
	if !sameSet(g, []string{"ixp.fabric_degraded switch 1", "ixp.fabric_degraded colo colo-a", "ixp.member_recovered 64500 "}) {
		t.Fatalf("events %v", g)
	}
}

func TestStaleFabricResolves(t *testing.T) {
	c, got := newCorrelator(t, "rounds: 1")
	s1 := sw(1, "colo-a")
	round(c, 1, members(64500, 4, true, s1))
	if len(*got) != 2 {
		t.Fatalf("events %v", kinds(*got))
	}
	*got = nil
	c.evaluate(plugin.FabricView{Configured: true, Stale: true, Round: t0.Add(2 * time.Minute), Samples: members(64500, 4, true, s1)})
	if g := kinds(*got); !sameSet(g, []string{"ixp.fabric_recovered switch 1", "ixp.fabric_recovered colo colo-a"}) {
		t.Fatalf("events %v", g)
	}
	v := c.View()
	if !v.Stale || len(v.Groups) != 0 || len(v.Members) != 0 {
		t.Fatalf("view %+v", v)
	}
}

func TestNoRoundNoEvaluation(t *testing.T) {
	c, got := newCorrelator(t, "rounds: 1")
	c.evaluate(plugin.FabricView{Configured: true, Samples: members(64500, 4, true, sw(1, "c"))})
	if len(*got) != 0 || !c.View().Round.IsZero() {
		t.Fatalf("a view with no round was evaluated: %v", kinds(*got))
	}
}

func TestAsnListIsBounded(t *testing.T) {
	c, got := newCorrelator(t, "rounds: 1")
	round(c, 1, members(64500, 14, true, sw(1, "colo-a")))
	if a := (*got)[0].Fields["asns"]; strings.Count(a, ",") != maxASNsInEvent || !strings.HasSuffix(a, ",...") {
		t.Fatalf("asns %q", a)
	}
	if (*got)[0].Fields["degraded"] != "14" {
		t.Fatalf("fields %v", (*got)[0].Fields)
	}
}

func TestStartReadsFabricAndStops(t *testing.T) {
	c, _ := newCorrelator(t, "rounds: 1")
	ch := make(chan plugin.Event, 4)
	c.SetEventSink(func(e plugin.Event) { ch <- e })
	c.SetFabric(func() plugin.FabricView {
		return plugin.FabricView{Configured: true, Round: t0, Samples: members(64500, 3, true, sw(1, "colo-a"))}
	})
	if err := c.Start(context.Background()); err != nil {
		t.Fatal(err)
	}
	select {
	case e := <-ch:
		if e.Kind != plugin.EventFabricDegraded {
			t.Fatalf("event %+v", e)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("no event from the loop")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := c.Stop(ctx); err != nil {
		t.Fatal(err)
	}
}

func TestConfigValidation(t *testing.T) {
	cases := []struct{ name, cfg, want string }{
		{"min_members low", "min_members: 1", "min_members"},
		{"degraded_pct high", "degraded_pct: 101", "degraded_pct"},
		{"degraded_pct negative", "degraded_pct: -1", "degraded_pct"},
		{"rounds high", "rounds: 11", "rounds"},
		{"bundle name", "bundles: [{name: 'a b', switches: [1]}]", "bundles[0].name"},
		{"bundle duplicate", "bundles: [{name: a, switches: [1]}, {name: a, switches: [2]}]", "duplicated"},
		{"bundle no switches", "bundles: [{name: a}]", "switches"},
		{"bundle bad switch", "bundles: [{name: a, switches: [0]}]", "switch id"},
		{"bundle bad ixp", "bundles: [{name: a, ixp_id: -1, switches: [1]}]", "ixp_id"},
		{"unknown key", "extra: 1", "extra"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var node yaml.Node
			if err := yaml.Unmarshal([]byte(tc.cfg), &node); err != nil {
				t.Fatal(err)
			}
			_, err := New(plugin.NewConfig(&node), plugin.Env{})
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("err %v, want %q", err, tc.want)
			}
		})
	}
	if _, err := New(plugin.NewConfig(nil), plugin.Env{}); err != nil {
		t.Fatalf("defaults: %v", err)
	}
}

func TestSwitchEventKeyIsTheIDNotTheName(t *testing.T) {
	c, got := newCorrelator(t, "rounds: 1")
	s1 := plugin.FabricSwitch{ID: 1, Name: "old-name"}
	round(c, 1, members(64500, 4, true, s1))
	renamed := plugin.FabricSwitch{ID: 1, Name: "new-name"}
	round(c, 2, members(64500, 4, false, renamed))
	if len(*got) != 2 {
		t.Fatalf("events %v", kinds(*got))
	}
	problem, recovery := (*got)[0], (*got)[1]
	if problem.Fields["name"] != "old-name" || recovery.Fields["name"] != "new-name" {
		t.Fatalf("names %v %v", problem.Fields, recovery.Fields)
	}
	if problem.DedupKey() != recovery.DedupKey() {
		t.Fatalf("a rename changed the dedup key: %q vs %q", problem.DedupKey(), recovery.DedupKey())
	}

	c, got = newCorrelator(t, "rounds: 1")
	twin := plugin.FabricSwitch{ID: 2, Name: "old-name"}
	round(c, 1, cat(members(64500, 4, true, s1), members(64600, 4, true, twin)))
	var keys []string
	for _, e := range *got {
		if e.Fields["scope"] == plugin.ScopeSwitch {
			keys = append(keys, e.DedupKey())
		}
	}
	if len(keys) != 2 || keys[0] == keys[1] {
		t.Fatalf("two switches with one name share a dedup key: %v", keys)
	}
}

func TestOpenIncidentStaysInViewWhenUnmeasured(t *testing.T) {
	c, got := newCorrelator(t, "") // rounds default 2
	s1 := sw(1, "colo-a")
	bad := members(64500, 4, true, s1)
	round(c, 1, bad)
	round(c, 2, bad)
	if len(*got) != 2 {
		t.Fatalf("events %v", kinds(*got))
	}
	// A lone member elsewhere, degraded for two rounds, opens its own event.
	lone := members(64700, 1, true, sw(9, "colo-z"))
	round(c, 3, cat(bad, lone))
	round(c, 4, cat(bad, lone))
	if len(*got) != 3 || (*got)[2].Kind != plugin.EventMemberDegraded {
		t.Fatalf("events %v", kinds(*got))
	}

	// Nothing is measured in the next round: both events are still open.
	round(c, 5, []plugin.FabricSample{smp("v1", 64800, "192.0.2.99", false, sw(5, "colo-q"))})
	v := c.View()
	var open []string
	for _, g := range v.Groups {
		if g.Active {
			if g.Members != 0 || g.Degraded != 0 || g.ASNs == nil {
				t.Fatalf("unmeasured open group %+v", g)
			}
			open = append(open, g.Scope+" "+g.Name)
		}
	}
	if !sameSet(open, []string{"switch sw1", "colo colo-a"}) {
		t.Fatalf("open groups %v in %+v", open, v.Groups)
	}
	if len(v.Members) != 1 || v.Members[0].ASN != 64700 || !v.Members[0].Active || v.Members[0].Name != "member-64700" {
		t.Fatalf("members %+v", v.Members)
	}
}
