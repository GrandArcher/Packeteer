// Package frr is the FRR backend of the read-only router check (#626). It
// talks to bgpd's vty socket the way vtysh does and sends only the show
// commands on its allowlist; it never enters configure mode, writes, or
// clears anything.
package frr

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/netip"
	"slices"
	"strings"

	"github.com/GrandArcher/Packeteer/internal/plugins/routercheck/readonly"
	"github.com/GrandArcher/Packeteer/pkg/plugin"
)

// TypeName is the router_check type.
const TypeName = "frr"

func init() { plugin.RouterChecks.Register(TypeName, New) }

// Config is preflight.router_check.config for type frr.
type Config struct {
	// SocketEnv names the environment variable that holds the path of
	// bgpd's vty socket (bgpd.vty in FRR's run directory).
	SocketEnv string `yaml:"socket_env"`
}

var allow = readonly.NewAllowlist(
	`show bgp neighbors json`,
	// FRR has show route-map in the privileged node only. On the daemon
	// socket enable takes no password and only changes the node, as vtysh
	// does on connect; no configure, write, or clear command is listed.
	`enable`,
	`show route-map `+readonly.Name+` json`,
	`show bgp (?:large-)?community-list `+readonly.Name+` detail`,
)

// maxReply bounds one reply; a full neighbor list is far smaller.
const maxReply = 16 << 20

// Reader is the frr router check.
type Reader struct {
	plugin.Base
	socket string
}

// New validates the config. It does not connect.
func New(c plugin.Config, env plugin.Env) (plugin.RouterCheck, error) {
	var cfg Config
	if err := c.Decode(&cfg); err != nil {
		return nil, err
	}
	p, err := readonly.Path(env.Getenv, "socket_env", cfg.SocketEnv, env.CheckOnly)
	if err != nil {
		return nil, err
	}
	return &Reader{socket: p}, nil
}

// CheckFilters reads the sessions and their route-maps from bgpd.
func (r *Reader) CheckFilters(ctx context.Context, q plugin.FilterQuery) ([]plugin.FilterFinding, error) {
	conn, err := readonly.Dial(ctx, r.socket)
	if err != nil {
		return nil, err
	}
	defer conn.Close()
	return check(&session{w: conn, r: bufio.NewReader(conn)}, q)
}

// session is one connection to a daemon's vty socket.
type session struct {
	w       io.Writer
	r       *bufio.Reader
	enabled bool
}

// run sends one allowlisted command and returns its output and FRR's
// status byte (0 is success). A command ends in a NUL; the reply ends in
// three NULs and the status.
func (s *session) run(cmd string) (string, byte, error) {
	if err := allow.Check(cmd); err != nil {
		return "", 0, err
	}
	if _, err := io.WriteString(s.w, cmd+"\x00"); err != nil {
		return "", 0, fmt.Errorf("send to bgpd: %w", readonly.Scrub(err))
	}
	var out []byte
	zeros := 0
	for {
		b, err := s.r.ReadByte()
		if err != nil {
			return "", 0, fmt.Errorf("read from bgpd: %w", readonly.Scrub(err))
		}
		switch {
		case zeros == 3:
			return string(out), b, nil
		case b == 0:
			zeros++
		case zeros > 0:
			return "", 0, errors.New("read from bgpd: malformed reply")
		default:
			out = append(out, b)
			if len(out) > maxReply {
				return "", 0, errors.New("read from bgpd: reply too long")
			}
		}
	}
}

// show runs a privileged show command, entering the enable node once.
func (s *session) show(cmd string) (string, byte, error) {
	if !s.enabled {
		if _, st, err := s.run("enable"); err != nil || st != 0 {
			return "", st, errors.Join(err, errors.New("bgpd refused enable"))
		}
		s.enabled = true
	}
	return s.run(cmd)
}

type family struct {
	In  string `json:"routeMapForIncomingAdvertisements"`
	Out string `json:"routeMapForOutgoingAdvertisements"`
	// RequiresPolicy is set when ebgp-requires-policy holds back every
	// route because no outbound policy is configured.
	RequiresPolicy string `json:"outboundEbgpRequiresPolicy"`
}

type neighbor struct {
	addr     string
	Internal bool              `json:"nbrInternalLink"`
	External bool              `json:"nbrExternalLink"`
	Families map[string]family `json:"addressFamilyInfo"`
}

// families are the address families the check reads, with the name FRR's
// address-family command uses.
var families = []struct{ key, cli string }{{"ipv4Unicast", "ipv4 unicast"}, {"ipv6Unicast", "ipv6 unicast"}}

type rule struct {
	Seq    int      `json:"sequenceNumber"`
	Type   string   `json:"type"`
	Match  []string `json:"matchClauses"`
	Set    []string `json:"setClauses"`
	Call   string   `json:"callClause"`
	Action string   `json:"action"`
}

// commList is a community list as `show bgp community-list NAME detail`
// prints it.
type commList struct {
	expanded bool
	entries  []listEntry
}

type listEntry struct {
	permit bool
	values []string
}

type checker struct {
	s     *session
	q     plugin.FilterQuery
	kw    string // the route-map match keyword for the community type
	maps  map[string][]rule
	lists map[string]*commList
}

func check(s *session, q plugin.FilterQuery) ([]plugin.FilterFinding, error) {
	out, st, err := s.run("show bgp neighbors json")
	if err != nil {
		return nil, err
	}
	if st != 0 {
		return nil, fmt.Errorf("bgpd answered %d to show bgp neighbors: %s", st, firstLine(out))
	}
	var raw map[string]json.RawMessage
	if err := json.Unmarshal([]byte(out), &raw); err != nil {
		return nil, fmt.Errorf("show bgp neighbors json: %w", err)
	}
	var ns []neighbor
	for k, v := range raw {
		n := neighbor{addr: k}
		if json.Unmarshal(v, &n) == nil && (n.Internal || n.External) {
			ns = append(ns, n)
		}
	}
	slices.SortFunc(ns, func(a, b neighbor) int { return strings.Compare(a.addr, b.addr) })
	c := &checker{s: s, q: q, kw: "community", maps: map[string][]rule{}, lists: map[string]*commList{}}
	if strings.Count(q.Community, ":") == 2 {
		c.kw = "large-community"
	}
	var findings []plugin.FilterFinding
	pk := slices.IndexFunc(ns, func(n neighbor) bool {
		a, err := netip.ParseAddr(n.addr)
		return err == nil && a.Unmap() == q.Packeteer.Unmap()
	})
	if pk < 0 {
		findings = append(findings, plugin.FilterFinding{
			Verdict: plugin.VerdictFail,
			Detail:  fmt.Sprintf("The router has no BGP neighbor %s (Packeteer).", q.Packeteer),
			Fix:     fmt.Sprintf("Add the session for Packeteer from Router snippets: neighbor %s with your own AS number and route-map packeteer-in in.", q.Packeteer),
		})
	} else {
		f, err := c.imports(ns[pk])
		if err != nil {
			return nil, err
		}
		findings = append(findings, f...)
	}
	ebgp := 0
	for _, n := range ns {
		if !n.External {
			continue
		}
		ebgp++
		f, err := c.exports(n)
		if err != nil {
			return nil, err
		}
		findings = append(findings, f...)
	}
	if ebgp == 0 {
		findings = append(findings, plugin.FilterFinding{Verdict: plugin.VerdictPass, Detail: "The router has no eBGP neighbor."})
	}
	return findings, nil
}

// imports checks the policy on Packeteer's session.
func (c *checker) imports(n neighbor) ([]plugin.FilterFinding, error) {
	if !n.Internal {
		return []plugin.FilterFinding{{
			Verdict: plugin.VerdictFail,
			Detail:  fmt.Sprintf("Neighbor %s (Packeteer) is not an iBGP session.", n.addr),
			Fix:     fmt.Sprintf("Set neighbor %s remote-as to your own AS number: Packeteer is an iBGP neighbor (Router snippets).", n.addr),
		}}, nil
	}
	var out []plugin.FilterFinding
	for _, fam := range families {
		f, ok := n.Families[fam.key]
		if !ok {
			continue
		}
		where := fmt.Sprintf("Import from Packeteer %s (%s)", n.addr, fam.cli)
		if f.In == "" {
			out = append(out, plugin.FilterFinding{
				Verdict: plugin.VerdictFail,
				Detail:  where + ": no inbound route-map, so every route from Packeteer is accepted.",
				Fix:     fmt.Sprintf("Under address-family %s: neighbor %s route-map packeteer-in in, with packeteer-in from Router snippets (permit only %s, deny the rest).", fam.cli, n.addr, c.q.Community),
			})
			continue
		}
		f2, err := c.importMap(where, f.In)
		if err != nil {
			return nil, err
		}
		out = append(out, f2)
	}
	if len(out) == 0 {
		out = append(out, plugin.FilterFinding{
			Verdict: plugin.VerdictUnknown,
			Detail:  fmt.Sprintf("Neighbor %s (Packeteer) has no IPv4 or IPv6 unicast family active.", n.addr),
		})
	}
	return out, nil
}

func (c *checker) importMap(where, name string) (plugin.FilterFinding, error) {
	rules, unknown, err := c.routeMap(name)
	if err != nil || unknown != "" {
		return plugin.FilterFinding{Verdict: plugin.VerdictUnknown, Detail: where + ": " + unknown}, err
	}
	permits := 0
	for _, r := range rules {
		if why := unsupported(r); why != "" {
			return plugin.FilterFinding{Verdict: plugin.VerdictUnknown, Detail: fmt.Sprintf("%s: route-map %s entry %d %s; read it by hand.", where, name, r.Seq, why)}, nil
		}
		if r.Type != "permit" {
			if len(r.Match) == 0 {
				break // denies everything after it
			}
			continue
		}
		if set := rewrites(r); set != "" {
			return plugin.FilterFinding{Verdict: plugin.VerdictUnknown, Detail: fmt.Sprintf("%s: route-map %s entry %d sets %s, which can remove %s before the eBGP filters look for it; read it by hand.", where, name, r.Seq, set, c.q.Community)}, nil
		}
		ok, never, why, err := c.requiresOurs(r)
		if err != nil {
			return plugin.FilterFinding{}, err
		}
		switch {
		case never:
			continue
		case why != "":
			return plugin.FilterFinding{Verdict: plugin.VerdictUnknown, Detail: fmt.Sprintf("%s: route-map %s entry %d: %s.", where, name, r.Seq, why)}, nil
		case !ok:
			return plugin.FilterFinding{
				Verdict: plugin.VerdictFail,
				Detail:  fmt.Sprintf("%s: route-map %s entry %d permits routes without %s.", where, name, r.Seq, c.q.Community),
				Fix:     fmt.Sprintf("Make every permit entry of route-map %s match a %s list that permits only %s (match %s packeteer), or remove entry %d.", name, c.kw, c.q.Community, c.kw, r.Seq),
			}, nil
		}
		permits++
	}
	if permits == 0 {
		return plugin.FilterFinding{
			Verdict: plugin.VerdictFail,
			Detail:  fmt.Sprintf("%s: route-map %s never permits %s, so Packeteer's routes are dropped.", where, name, c.q.Community),
			Fix:     fmt.Sprintf("Add route-map %s permit 10 with match %s packeteer, the %s list for %s (Router snippets).", name, c.kw, c.kw, c.q.Community),
		}, nil
	}
	return plugin.FilterFinding{Verdict: plugin.VerdictPass, Detail: fmt.Sprintf("%s: route-map %s permits only routes with %s.", where, name, c.q.Community)}, nil
}

// exports checks one eBGP session's outbound policy.
func (c *checker) exports(n neighbor) ([]plugin.FilterFinding, error) {
	var out []plugin.FilterFinding
	for _, fam := range families {
		f, ok := n.Families[fam.key]
		if !ok {
			continue
		}
		where := fmt.Sprintf("Export to eBGP neighbor %s (%s)", n.addr, fam.cli)
		switch {
		case f.Out == "" && f.RequiresPolicy != "":
			out = append(out, plugin.FilterFinding{Verdict: plugin.VerdictPass, Detail: where + ": no outbound policy and ebgp-requires-policy is on, so nothing is sent."})
			continue
		case f.Out == "":
			out = append(out, plugin.FilterFinding{
				Verdict: plugin.VerdictFail,
				Detail:  fmt.Sprintf("%s: no outbound route-map, so routes with %s are sent.", where, c.q.Community),
				Fix:     fmt.Sprintf("Under address-family %s: neighbor %s route-map ebgp-out out, with ebgp-out from Router snippets (deny 10 with match %s packeteer first, then the terms you send).", fam.cli, n.addr, c.kw),
			})
			continue
		}
		f2, err := c.exportMap(where, f.Out)
		if err != nil {
			return nil, err
		}
		out = append(out, f2)
	}
	return out, nil
}

func (c *checker) exportMap(where, name string) (plugin.FilterFinding, error) {
	rules, unknown, err := c.routeMap(name)
	if err != nil || unknown != "" {
		return plugin.FilterFinding{Verdict: plugin.VerdictUnknown, Detail: where + ": " + unknown}, err
	}
	for _, r := range rules {
		if why := unsupported(r); why != "" {
			return plugin.FilterFinding{Verdict: plugin.VerdictUnknown, Detail: fmt.Sprintf("%s: route-map %s entry %d %s; read it by hand.", where, name, r.Seq, why)}, nil
		}
		if r.Type == "permit" {
			return plugin.FilterFinding{
				Verdict: plugin.VerdictFail,
				Detail:  fmt.Sprintf("%s: route-map %s entry %d permits before %s is denied.", where, name, r.Seq, c.q.Community),
				Fix:     fmt.Sprintf("Add a deny entry to route-map %s with a sequence number below %d and match %s packeteer, the %s list for %s (Router snippets), so it comes before every permit.", name, r.Seq, c.kw, c.kw, c.q.Community),
			}, nil
		}
		if len(r.Match) == 0 {
			return plugin.FilterFinding{Verdict: plugin.VerdictPass, Detail: fmt.Sprintf("%s: route-map %s denies everything at entry %d.", where, name, r.Seq)}, nil
		}
		ok, why, err := c.deniesOurs(r)
		if err != nil {
			return plugin.FilterFinding{}, err
		}
		if why != "" {
			return plugin.FilterFinding{Verdict: plugin.VerdictUnknown, Detail: fmt.Sprintf("%s: route-map %s entry %d: %s.", where, name, r.Seq, why)}, nil
		}
		if ok {
			return plugin.FilterFinding{Verdict: plugin.VerdictPass, Detail: fmt.Sprintf("%s: route-map %s denies %s at entry %d, before any permit.", where, name, c.q.Community, r.Seq)}, nil
		}
	}
	return plugin.FilterFinding{Verdict: plugin.VerdictPass, Detail: fmt.Sprintf("%s: route-map %s permits nothing.", where, name)}, nil
}

// unsupported says why the check cannot follow an entry: one that calls
// another route-map or does not exit on a match.
func unsupported(r rule) string {
	switch {
	case r.Call != "":
		return "calls route-map " + r.Call
	case r.Action != "" && r.Action != "Exit routemap":
		return "continues on a match (" + r.Action + ")"
	}
	return ""
}

// rewrites returns the first set clause of r that can take the community
// off a route: a community set that is not additive, or a list delete.
func rewrites(r rule) string {
	for _, set := range r.Set {
		f := strings.Fields(set)
		switch {
		case len(f) == 0:
		case f[0] == "comm-list" || f[0] == "large-comm-list":
			return set
		case (f[0] == "community" || f[0] == "large-community") && f[len(f)-1] != "additive":
			return set
		}
	}
	return ""
}

// requiresOurs reports whether a permit entry matches only routes that
// carry the community. never is set when it matches no route at all: it
// names a community list the router does not have. why is set when the
// entry cannot be read.
func (c *checker) requiresOurs(r rule) (ok, never bool, why string, err error) {
	for _, m := range r.Match {
		l, why, err := c.clauseList(m)
		if err != nil || why != "" {
			return false, false, why, err
		}
		if l == nil {
			if strings.HasPrefix(m, c.kw+" ") {
				return false, true, "", nil
			}
			continue
		}
		match, uncertain := l.matchesOurs(c.q.Community)
		if uncertain {
			return false, false, uncertainWhy(m), nil
		}
		if match && l.requires(c.q.Community) {
			return true, false, "", nil
		}
	}
	return false, false, "", nil
}

func uncertainWhy(clause string) string {
	return "the list in match " + clause + " denies some communities before it decides on the Packeteer community, and a Packeteer route can carry more than that one; read it by hand"
}

// deniesOurs reports whether a deny entry matches every Packeteer route:
// each of its clauses is a community list that matches the community.
func (c *checker) deniesOurs(r rule) (ok bool, why string, err error) {
	for _, m := range r.Match {
		l, why, err := c.clauseList(m)
		if err != nil || why != "" {
			return false, why, err
		}
		if l == nil {
			return false, "", nil
		}
		match, uncertain := l.matchesOurs(c.q.Community)
		if uncertain {
			return false, uncertainWhy(m), nil
		}
		if !match {
			return false, "", nil
		}
	}
	return true, "", nil
}

// clauseList returns the community list a match clause names, or nil when
// the clause matches on something else or the list does not exist.
func (c *checker) clauseList(clause string) (*commList, string, error) {
	f := strings.Fields(clause)
	if len(f) < 2 || f[0] != c.kw {
		return nil, "", nil
	}
	if len(f) > 2 {
		return nil, "match " + clause + " is not read", nil
	}
	l, err := c.list(f[1])
	switch {
	case errors.Is(err, readonly.ErrRefused):
		return nil, fmt.Sprintf("list name %q is not read", f[1]), nil
	case err != nil:
		return nil, "", err
	case l != nil && l.expanded:
		return nil, "expanded list " + f[1] + " is not read", nil
	}
	return l, "", nil
}

// routeMap returns a route-map's entries in order. unknown is set when it
// cannot be read.
func (c *checker) routeMap(name string) ([]rule, string, error) {
	if r, ok := c.maps[name]; ok {
		return r, "", nil
	}
	out, st, err := c.s.show("show route-map " + name + " json")
	if errors.Is(err, readonly.ErrRefused) {
		return nil, fmt.Sprintf("route-map name %q is not read.", name), nil
	}
	if err != nil {
		return nil, "", err
	}
	if st != 0 {
		return nil, fmt.Sprintf("bgpd answered %d to show route-map %s.", st, name), nil
	}
	rules, ok, err := findMap(out, name)
	if err != nil {
		return nil, "", fmt.Errorf("show route-map %s json: %w", name, err)
	}
	if !ok {
		return nil, fmt.Sprintf("route-map %s is applied but not defined.", name), nil
	}
	c.maps[name] = rules
	return rules, "", nil
}

type mapJSON struct {
	Rules *[]rule `json:"rules"`
}

// findMap reads route-map name from bgpd's JSON, which has it at the top
// level; vtysh merges daemons by nesting each under its name ("BGP").
func findMap(out, name string) ([]rule, bool, error) {
	var top map[string]json.RawMessage
	if err := json.Unmarshal([]byte(out), &top); err != nil {
		return nil, false, err
	}
	if raw, ok := top[name]; ok {
		var m mapJSON
		if err := json.Unmarshal(raw, &m); err == nil && m.Rules != nil {
			return *m.Rules, true, nil
		}
	}
	for _, raw := range top {
		var nested map[string]mapJSON
		if json.Unmarshal(raw, &nested) == nil && nested[name].Rules != nil {
			return *nested[name].Rules, true, nil
		}
	}
	return nil, false, nil
}

// list reads a community list; nil when the router has none by that name.
func (c *checker) list(name string) (*commList, error) {
	if l, ok := c.lists[name]; ok {
		return l, nil
	}
	out, st, err := c.s.run("show bgp " + c.kw + "-list " + name + " detail")
	if err != nil {
		return nil, err
	}
	var l *commList
	if st == 0 {
		l = parseList(out)
	}
	c.lists[name] = l
	return l, nil
}

func parseList(out string) *commList {
	l := &commList{}
	for _, line := range strings.Split(out, "\n") {
		f := strings.Fields(line)
		switch {
		case len(f) == 0:
		case !strings.HasPrefix(line, " "):
			l.expanded = l.expanded || strings.Contains(line, "expanded")
		case f[0] == "permit" || f[0] == "deny":
			l.entries = append(l.entries, listEntry{permit: f[0] == "permit", values: f[1:]})
		}
	}
	return l
}

// routeHas reports whether v is one of the values every Packeteer route
// carries: its community, and NO_EXPORT with a standard community.
func routeHas(community, v string) bool {
	return v == community || strings.Count(community, ":") == 1 && v == "no-export"
}

// matchesOurs reports whether the list matches a route with only the values
// every Packeteer route carries. A route can carry more (communities_cause,
// a marker), so a deny entry that names other values before the deciding
// entry makes the answer uncertain.
func (l *commList) matchesOurs(community string) (match, uncertain bool) {
	for _, e := range l.entries {
		other := slices.ContainsFunc(e.values, func(v string) bool { return !routeHas(community, v) })
		switch {
		case !other:
			return e.permit, false
		case !e.permit:
			return false, true
		}
	}
	return false, false
}

// requires reports whether every permit entry needs the community.
func (l *commList) requires(community string) bool {
	for _, e := range l.entries {
		if e.permit && !slices.Contains(e.values, community) {
			return false
		}
	}
	return true
}

func firstLine(s string) string {
	s, _, _ = strings.Cut(strings.TrimSpace(s), "\n")
	return s
}
