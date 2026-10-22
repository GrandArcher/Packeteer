package pbr

import (
	"context"
	"fmt"
	"net/netip"
	"os/exec"
	"slices"
	"strconv"
	"strings"
)

// managedSpan is how many tables and rule priorities above tableBase and
// prioBase belong to Packeteer. A rule is Packeteer's when both its priority
// and its table are in these ranges, so a hand-written rule is never touched.
const managedSpan = 999

// verifySink is the destination of the route lookup that checks an applied
// rule. It is a documentation address and nothing is sent to it.
var verifySink = netip.MustParseAddr("203.0.113.254")

// Exec runs the ip command with args and returns its output.
type Exec func(ctx context.Context, args ...string) (string, error)

// HostExec runs the host's ip command. In the container that is BusyBox's,
// which needs --network host and NET_ADMIN to change the host's routing.
func HostExec(ctx context.Context, args ...string) (string, error) {
	out, err := exec.CommandContext(ctx, "ip", args...).CombinedOutput()
	if err != nil {
		return string(out), fmt.Errorf("ip %s: %w: %s", strings.Join(args, " "), err, strings.TrimSpace(string(out)))
	}
	return string(out), nil
}

// Step is one ip command of a plan.
type Step struct {
	// Remove is true for a command that deletes something Packeteer set up
	// earlier and no provider needs now.
	Remove bool
	Args   []string
}

// String is the command line, as the diff shows it.
func (s Step) String() string {
	sign := "+ "
	if s.Remove {
		sign = "- "
	}
	return sign + "ip " + strings.Join(s.Args, " ")
}

// rule is one ip rule, reduced to the selectors this package writes.
type rule struct {
	prio  int
	from  string
	mark  uint32
	table int
}

// famArgs is the ip option that selects the address family.
func famArgs(six bool) []string {
	if six {
		return []string{"-6"}
	}
	return nil
}

func (r rule) args(verb string, fam []string) []string {
	a := append(slices.Clone(fam), "rule", verb, "from", r.from)
	if r.mark != 0 {
		a = append(a, "fwmark", strconv.FormatUint(uint64(r.mark), 10))
	}
	return append(a, "lookup", strconv.Itoa(r.table), "priority", strconv.Itoa(r.prio))
}

func managed(prio, table int) bool {
	return prio > prioBase && prio <= prioBase+managedSpan && table > tableBase && table <= tableBase+managedSpan
}

// parseRules reads `ip rule show`. A line it cannot read is skipped: an
// unreadable rule is never one of ours to delete.
func parseRules(out string) []rule {
	var rules []rule
	for _, line := range strings.Split(out, "\n") {
		f := strings.Fields(line)
		if len(f) == 0 || !strings.HasSuffix(f[0], ":") {
			continue
		}
		prio, err := strconv.Atoi(strings.TrimSuffix(f[0], ":"))
		if err != nil {
			continue
		}
		r := rule{prio: prio, table: -1}
		other := false
		for i := 1; i < len(f); i++ {
			switch f[i] {
			case "from":
				if i+1 < len(f) {
					i++
					r.from = f[i]
				}
			case "fwmark":
				if i+1 < len(f) {
					i++
					m, _, _ := strings.Cut(f[i], "/")
					v, err := strconv.ParseUint(m, 0, 32)
					if err != nil {
						other = true
					}
					r.mark = uint32(v)
				}
			case "lookup", "table":
				if i+1 < len(f) {
					i++
					r.table, _ = strconv.Atoi(f[i])
				}
			default:
				// Any other selector (iif, to, tos, ...) is not a rule this package wrote.
				other = true
			}
		}
		if !other && r.table >= 0 {
			rules = append(rules, r)
		}
	}
	return rules
}

// parseDefault reads `ip route show table N` and returns the next hop of the
// default route, or "" when there is none.
func parseDefault(out string) string {
	for _, line := range strings.Split(out, "\n") {
		f := strings.Fields(line)
		if len(f) >= 3 && f[0] == "default" && f[1] == "via" {
			return f[2]
		}
	}
	return ""
}

// host is what ip reports now for the managed tables and priorities.
type host struct {
	rules  []rule
	tables map[int]string // default next hop by table
}

func readHost(ctx context.Context, run Exec, v4, v6 bool) (map[bool]*host, error) {
	have := map[bool]*host{}
	for _, six := range []bool{false, true} {
		fam := famArgs(six)
		out, err := run(ctx, append(slices.Clone(fam), "rule", "show")...)
		if err != nil {
			if (six && !v6) || (!six && !v4) {
				continue // a family nothing uses may be absent from the kernel
			}
			return nil, err
		}
		h := &host{tables: map[int]string{}}
		for _, r := range parseRules(out) {
			if !managed(r.prio, r.table) {
				continue
			}
			h.rules = append(h.rules, r)
			if _, ok := h.tables[r.table]; ok {
				continue
			}
			rout, err := run(ctx, append(slices.Clone(fam), "route", "show", "table", strconv.Itoa(r.table))...)
			if err != nil {
				return nil, err
			}
			h.tables[r.table] = parseDefault(rout)
		}
		have[six] = h
	}
	return have, nil
}

// desired is the rules and default routes the entries need.
func desired(entries []Entry) (rules map[bool][]rule, routes map[bool]map[int]string) {
	rules = map[bool][]rule{}
	routes = map[bool]map[int]string{false: {}, true: {}}
	for _, e := range entries {
		six := e.Source.Is6()
		table := tableBase + e.N
		routes[six][table] = e.NextHop.String()
		rules[six] = append(rules[six], rule{prio: prioBase + e.N, from: e.Source.String(), mark: e.FwMark, table: table})
	}
	return rules, routes
}

// Plan lists the ip commands that make the host match entries, and removes
// what an earlier run set up for a provider that is gone. A DSCP-only
// provider needs an nftables rule, which this package does not apply.
func Plan(ctx context.Context, run Exec, entries []Entry) ([]Step, error) {
	if len(entries) == 0 {
		return nil, fmt.Errorf("no provider is measured from this instance")
	}
	if err := linuxMarkClash(entries); err != nil {
		return nil, err
	}
	for _, e := range entries {
		if e.FwMark == 0 && e.DSCP != 0 {
			return nil, fmt.Errorf("provider %s sets dscp but no fwmark: a DSCP match needs an nftables rule, which -apply does not set up (set a fwmark, or run the nft lines of `-pbr linux` by hand)", e.Name)
		}
	}
	v4, v6 := families(entries)
	have, err := readHost(ctx, run, v4, v6)
	if err != nil {
		return nil, err
	}
	wantRules, wantRoutes := desired(entries)
	var steps []Step
	for _, six := range []bool{false, true} {
		fam := famArgs(six)
		h := have[six]
		if h == nil {
			h = &host{tables: map[int]string{}}
		}
		// Delete first, so a rule moved to another priority never overlaps
		// with its old copy.
		for _, r := range h.rules {
			if !slices.Contains(wantRules[six], r) {
				steps = append(steps, Step{Remove: true, Args: r.args("del", fam)})
			}
		}
		var stale []int
		for table := range h.tables {
			if _, ok := wantRoutes[six][table]; !ok {
				stale = append(stale, table)
			}
		}
		slices.Sort(stale)
		for _, table := range stale {
			if via := h.tables[table]; via != "" {
				steps = append(steps, Step{Remove: true, Args: append(slices.Clone(fam), "route", "del", "default", "via", via, "table", strconv.Itoa(table))})
			}
		}
		for _, e := range entries {
			if e.Source.Is6() != six {
				continue
			}
			table := tableBase + e.N
			if h.tables[table] != e.NextHop.String() {
				steps = append(steps, Step{Args: append(slices.Clone(fam), "route", "replace", "default", "via", e.NextHop.String(), "table", strconv.Itoa(table))})
			}
		}
		for _, r := range wantRules[six] {
			if !slices.Contains(h.rules, r) {
				steps = append(steps, Step{Args: r.args("add", fam)})
			}
		}
	}
	return steps, nil
}

// Apply runs the steps in order and stops at the first failure.
func Apply(ctx context.Context, run Exec, steps []Step) error {
	for _, s := range steps {
		if _, err := run(ctx, s.Args...); err != nil {
			return err
		}
	}
	return nil
}

// Verify asks the kernel which way a packet from each entry's source (with
// its fwmark) would leave, and reports the entries that do not go through
// their next hop. Nothing is sent.
func Verify(ctx context.Context, run Exec, entries []Entry) []error {
	var errs []error
	for _, e := range entries {
		sink := verifySink
		if e.Source.Is6() {
			sink = netip.MustParseAddr("2001:db8:ffff::1")
		}
		args := append(famArgs(e.Source.Is6()), "route", "get", sink.String(), "from", e.Source.String())
		if e.FwMark != 0 {
			args = append(args, "mark", strconv.FormatUint(uint64(e.FwMark), 10))
		}
		out, err := run(ctx, args...)
		if err != nil {
			errs = append(errs, fmt.Errorf("%s: %w", e.Name, err))
			continue
		}
		if !leavesVia(out, e.NextHop) {
			errs = append(errs, fmt.Errorf("%s: a packet from %s leaves as %q, not via %s", e.Name, e.Source, strings.TrimSpace(out), e.NextHop))
		}
	}
	return errs
}

// leavesVia reports whether `ip route get` output names nh as the gateway.
func leavesVia(out string, nh netip.Addr) bool {
	f := strings.Fields(out)
	for i := 0; i+1 < len(f); i++ {
		if f[i] == "via" {
			a, err := netip.ParseAddr(f[i+1])
			return err == nil && a.Unmap() == nh
		}
	}
	return false
}
