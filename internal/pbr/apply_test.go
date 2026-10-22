package pbr

import (
	"context"
	"fmt"
	"slices"
	"strconv"
	"strings"
	"testing"

	"github.com/GrandArcher/Packeteer/internal/config"
)

// fakeHost is a Linux policy routing table that understands the ip commands
// Plan, Apply and Verify use. Lines in rules and routes are in the form ip
// prints them.
type fakeHost struct {
	rules  []string            // "2001:\tfrom 192.0.2.11 lookup 1001"
	routes map[string]string   // "4 1001" or "6 1001" -> next hop
	log    []string            // every changing command, in order
	fail   map[string]struct{} // commands (joined) that fail
}

func newHost() *fakeHost { return &fakeHost{routes: map[string]string{}, fail: map[string]struct{}{}} }

func (h *fakeHost) exec(_ context.Context, args ...string) (string, error) {
	line := strings.Join(args, " ")
	if _, bad := h.fail[line]; bad {
		return "", fmt.Errorf("ip %s: RTNETLINK answers: File exists", line)
	}
	fam := "4"
	if args[0] == "-6" {
		fam, args = "6", args[1:]
	}
	isSix := func(s string) bool { return strings.Contains(s, ":") }
	switch {
	case args[0] == "rule" && args[1] == "show":
		var b strings.Builder
		for _, r := range h.rules {
			if isSix(strings.Fields(r)[2]) == (fam == "6") {
				b.WriteString(r + "\n")
			}
		}
		return b.String(), nil
	case args[0] == "route" && args[1] == "show":
		if nh := h.routes[fam+" "+args[3]]; nh != "" {
			return "default via " + nh + " dev eth0\n", nil
		}
		return "", nil
	case args[0] == "rule" && args[1] == "add":
		h.log = append(h.log, line)
		prio := args[slices.Index(args, "priority")+1]
		sel := "from " + args[3]
		if i := slices.Index(args, "fwmark"); i >= 0 {
			m, _ := strconv.Atoi(args[i+1])
			sel += fmt.Sprintf(" fwmark %#x", m)
		}
		h.rules = append(h.rules, prio+":\t"+sel+" lookup "+args[slices.Index(args, "lookup")+1])
	case args[0] == "rule" && args[1] == "del":
		h.log = append(h.log, line)
		prio := args[slices.Index(args, "priority")+1] + ":"
		h.rules = slices.DeleteFunc(h.rules, func(r string) bool { return strings.HasPrefix(r, prio) })
	case args[0] == "route" && args[1] == "replace":
		h.log = append(h.log, line)
		h.routes[fam+" "+args[len(args)-1]] = args[4]
	case args[0] == "route" && args[1] == "del":
		h.log = append(h.log, line)
		delete(h.routes, fam+" "+args[len(args)-1])
	case args[0] == "route" && args[1] == "get":
		from := args[4]
		for _, r := range h.rules {
			f := strings.Fields(r)
			if f[2] == from {
				table := f[len(f)-1]
				return fmt.Sprintf("%s from %s via %s dev eth0 table %s\n", args[2], from, h.routes[fam+" "+table], table), nil
			}
		}
		return args[2] + " dev eth0\n", nil
	}
	return "", nil
}

func entries(t *testing.T, providers string) []Entry {
	t.Helper()
	c, err := config.Parse([]byte("asn: 64512\nrouter_id: 192.0.2.10\nproviders:\n" + providers))
	if err != nil {
		t.Fatal(err)
	}
	return Entries(c)
}

const twoProviders = `
  - {name: transit-a, source_ip: 192.0.2.11, next_hop: 192.0.2.1}
  - {name: transit-b, source_ip: 192.0.2.12, next_hop: 192.0.2.2, fwmark: 7}
`

func plan(t *testing.T, h *fakeHost, es []Entry) []string {
	t.Helper()
	steps, err := Plan(context.Background(), h.exec, es)
	if err != nil {
		t.Fatal(err)
	}
	var out []string
	for _, s := range steps {
		out = append(out, s.String())
	}
	return out
}

func TestPlanAddsEverythingOnAFreshHost(t *testing.T) {
	h := newHost()
	got := plan(t, h, entries(t, twoProviders))
	want := []string{
		"+ ip route replace default via 192.0.2.1 table 1001",
		"+ ip route replace default via 192.0.2.2 table 1002",
		"+ ip rule add from 192.0.2.11 lookup 1001 priority 2001",
		"+ ip rule add from 192.0.2.12 fwmark 7 lookup 1002 priority 2002",
	}
	if !slices.Equal(got, want) {
		t.Fatalf("plan =\n%s\nwant\n%s", strings.Join(got, "\n"), strings.Join(want, "\n"))
	}
}

func TestApplyThenPlanIsEmptyAndVerifies(t *testing.T) {
	h := newHost()
	es := entries(t, twoProviders)
	steps, err := Plan(context.Background(), h.exec, es)
	if err != nil {
		t.Fatal(err)
	}
	if err := Apply(context.Background(), h.exec, steps); err != nil {
		t.Fatal(err)
	}
	if got := plan(t, h, es); len(got) != 0 {
		t.Fatalf("second plan = %v, want nothing to do", got)
	}
	if errs := Verify(context.Background(), h.exec, es); len(errs) != 0 {
		t.Fatalf("verify = %v", errs)
	}
}

func TestPlanRemovesWhatARemovedProviderLeftBehind(t *testing.T) {
	h := newHost()
	es := entries(t, twoProviders)
	steps, _ := Plan(context.Background(), h.exec, es)
	if err := Apply(context.Background(), h.exec, steps); err != nil {
		t.Fatal(err)
	}
	// A hand-written rule outside Packeteer's priorities, and one inside the
	// priority range that points at an unmanaged table, stay.
	h.rules = append(h.rules, "1001:\tfrom 198.51.100.5 lookup transit-a", "2500:\tfrom 198.51.100.6 lookup 5000")
	got := plan(t, h, es[:1])
	want := []string{
		"- ip rule del from 192.0.2.12 fwmark 7 lookup 1002 priority 2002",
		"- ip route del default via 192.0.2.2 table 1002",
	}
	if !slices.Equal(got, want) {
		t.Fatalf("plan =\n%s\nwant\n%s", strings.Join(got, "\n"), strings.Join(want, "\n"))
	}
	if err := Apply(context.Background(), h.exec, mustPlan(t, h, es[:1])); err != nil {
		t.Fatal(err)
	}
	if len(h.rules) != 3 || h.routes["4 1002"] != "" {
		t.Fatalf("rules = %q routes = %v", h.rules, h.routes)
	}
}

func mustPlan(t *testing.T, h *fakeHost, es []Entry) []Step {
	t.Helper()
	steps, err := Plan(context.Background(), h.exec, es)
	if err != nil {
		t.Fatal(err)
	}
	return steps
}

func TestPlanReplacesAChangedNextHop(t *testing.T) {
	h := newHost()
	es := entries(t, twoProviders)
	if err := Apply(context.Background(), h.exec, mustPlan(t, h, es)); err != nil {
		t.Fatal(err)
	}
	es[0].NextHop = es[0].NextHop.Next()
	got := plan(t, h, es)
	if len(got) != 1 || got[0] != "+ ip route replace default via 192.0.2.2 table 1001" {
		t.Fatalf("plan = %v", got)
	}
}

func TestPlanHandlesIPv6(t *testing.T) {
	h := newHost()
	es := entries(t, `
  - {name: transit-v6, source_ip: "2001:db8:ffff::31", next_hop: "2001:db8:ffff::1"}
`)
	got := plan(t, h, es)
	want := []string{
		"+ ip -6 route replace default via 2001:db8:ffff::1 table 1001",
		"+ ip -6 rule add from 2001:db8:ffff::31 lookup 1001 priority 2001",
	}
	if !slices.Equal(got, want) {
		t.Fatalf("plan = %v", got)
	}
	if err := Apply(context.Background(), h.exec, mustPlan(t, h, es)); err != nil {
		t.Fatal(err)
	}
	if got := plan(t, h, es); len(got) != 0 {
		t.Fatalf("second plan = %v", got)
	}
}

func TestPlanRefusals(t *testing.T) {
	h := newHost()
	if _, err := Plan(context.Background(), h.exec, nil); err == nil {
		t.Fatal("planned with no provider")
	}
	es := entries(t, `
  - {name: ix-a, source_ip: 192.0.2.31, next_hop: 203.0.113.11, dscp: 10}
`)
	if _, err := Plan(context.Background(), h.exec, es); err == nil || !strings.Contains(err.Error(), "nftables") {
		t.Fatalf("dscp only = %v", err)
	}
	h.fail["rule show"] = struct{}{}
	if _, err := Plan(context.Background(), h.exec, entries(t, twoProviders)); err == nil {
		t.Fatal("planned without reading the host")
	}
}

func TestApplyStopsAtTheFirstFailure(t *testing.T) {
	h := newHost()
	h.fail["route replace default via 192.0.2.2 table 1002"] = struct{}{}
	err := Apply(context.Background(), h.exec, mustPlan(t, h, entries(t, twoProviders)))
	if err == nil || !strings.Contains(err.Error(), "File exists") {
		t.Fatalf("apply = %v", err)
	}
	if len(h.log) != 1 || len(h.rules) != 0 {
		t.Fatalf("ran %v after the failure, rules %v", h.log, h.rules)
	}
}

func TestVerifyNamesTheProviderThatLeavesTheWrongWay(t *testing.T) {
	h := newHost()
	es := entries(t, twoProviders)
	if err := Apply(context.Background(), h.exec, mustPlan(t, h, es)); err != nil {
		t.Fatal(err)
	}
	h.routes["4 1002"] = "192.0.2.1"
	errs := Verify(context.Background(), h.exec, es)
	if len(errs) != 1 || !strings.Contains(errs[0].Error(), "transit-b") || !strings.Contains(errs[0].Error(), "not via 192.0.2.2") {
		t.Fatalf("verify = %v", errs)
	}
	h.rules = nil
	if errs := Verify(context.Background(), h.exec, es); len(errs) != 2 {
		t.Fatalf("verify without rules = %v", errs)
	}
}

func TestParseRulesKeepsOnlyRulesItCanReadBack(t *testing.T) {
	got := parseRules("0:\tfrom all lookup local\n2001:\tfrom 192.0.2.11 fwmark 0x7/0xffffffff lookup 1001\n2002:\tfrom 192.0.2.12 iif eth0 lookup 1002\nbad line\n")
	var seen []string
	for _, r := range got {
		seen = append(seen, fmt.Sprintf("%d %s %d %d", r.prio, r.from, r.mark, r.table))
	}
	// "lookup local" has no numeric table, and a rule with an iif selector is
	// not one this package wrote.
	want := []string{"0 all 0 0", "2001 192.0.2.11 7 1001"}
	if !slices.Equal(seen, want) {
		t.Fatalf("rules = %v, want %v", seen, want)
	}
	if managed(0, 0) || !managed(2001, 1001) || managed(2001, 5000) || managed(1001, 1001) {
		t.Fatal("managed ranges are wrong")
	}
}
