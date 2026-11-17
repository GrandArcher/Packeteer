// Package routeros is the RouterOS 7 backend of the read-only router check
// (#637). It reads the BGP connections and routing filter rules over the
// REST API with GET requests to a fixed list of paths; it never sends
// POST, PUT, PATCH, or DELETE, and never follows a redirect.
package routeros

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/netip"
	"net/url"
	"strings"
	"time"

	"github.com/GrandArcher/Packeteer/internal/plugins/rosrest"
	"github.com/GrandArcher/Packeteer/internal/plugins/routercheck/readonly"
	"github.com/GrandArcher/Packeteer/pkg/plugin"
)

// TypeName is the router_check type.
const TypeName = "routeros"

func init() { plugin.RouterChecks.Register(TypeName, New) }

// Config is preflight.router_check.config for type routeros.
type Config = rosrest.Config

// allow is every path the reader may GET, below /rest.
var allow = readonly.NewAllowlist(
	`/routing/bgp/connection`,
	`/routing/bgp/template`,
	`/routing/filter/rule`,
)

const (
	requestTimeout = 10 * time.Second
	maxBody        = 16 << 20
)

// Reader is the routeros router check.
type Reader struct {
	plugin.Base
	base       string
	user, pass string
	http       *http.Client
}

// New validates the config. It does not connect.
func New(c plugin.Config, env plugin.Env) (plugin.RouterCheck, error) {
	var cfg Config
	if err := c.Decode(&cfg); err != nil {
		return nil, err
	}
	login, err := cfg.Login(env)
	if err != nil {
		return nil, err
	}
	return &Reader{
		base: login.Base, user: login.User, pass: login.Pass,
		// A redirect could lead to a path that is not on the allowlist.
		http: &http.Client{Timeout: requestTimeout, Transport: login.Transport, CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		}},
	}, nil
}

// get reads one allowlisted path. The method is always GET.
func (r *Reader) get(ctx context.Context, path string, out any) error {
	if err := allow.Check(path); err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, r.base+path, nil)
	if err != nil {
		return err
	}
	req.SetBasicAuth(r.user, r.pass)
	req.Header.Set("Accept", "application/json")
	resp, err := r.http.Do(req)
	if err != nil {
		var ue *url.Error
		if errors.As(err, &ue) {
			err = ue.Err
		}
		return fmt.Errorf("read %s: %w", path, err)
	}
	defer resp.Body.Close()
	data, err := io.ReadAll(io.LimitReader(resp.Body, maxBody+1))
	if err != nil {
		return fmt.Errorf("read %s: %w", path, err)
	}
	if len(data) > maxBody {
		return fmt.Errorf("read %s: reply too long", path)
	}
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("read %s: RouterOS answered %s", path, resp.Status)
	}
	if err := json.Unmarshal(data, out); err != nil {
		return fmt.Errorf("read %s: %w", path, err)
	}
	return nil
}

// row is one item as RouterOS lists it: every value is a string.
type row map[string]string

// CheckFilters reads the BGP connections, their templates, and the filter
// rules.
func (r *Reader) CheckFilters(ctx context.Context, q plugin.FilterQuery) ([]plugin.FilterFinding, error) {
	var conns, rules []row
	if err := r.get(ctx, "/routing/bgp/connection", &conns); err != nil {
		return nil, err
	}
	var templates []row
	for _, c := range conns {
		if c["templates"] != "" {
			if err := r.get(ctx, "/routing/bgp/template", &templates); err != nil {
				return nil, err
			}
			break
		}
	}
	if err := r.get(ctx, "/routing/filter/rule", &rules); err != nil {
		return nil, err
	}
	return check(conns, templates, rules, q), nil
}

// conn is one BGP connection with the values it inherits from its
// templates filled in.
type conn struct {
	name, role, in, out string
	remote              netip.Prefix
}

// resolve fills in the fields a connection does not set from the
// templates it names, first template first.
func resolve(c row, templates []row) conn {
	byName := map[string]row{}
	for _, t := range templates {
		byName[t["name"]] = t
	}
	field := func(k string) string {
		if v := c[k]; v != "" {
			return v
		}
		for _, name := range strings.Split(c["templates"], ",") {
			if v := byName[strings.TrimSpace(name)][k]; v != "" {
				return v
			}
		}
		return ""
	}
	return conn{
		name: c["name"], role: field("local.role"),
		in: field("input.filter"), out: field("output.filter-chain"),
		remote: remotePrefix(c["remote.address"]),
	}
}

// remotePrefix reads remote.address: an address, or a prefix the router
// accepts connections from.
func remotePrefix(s string) netip.Prefix {
	s, _, _ = strings.Cut(s, "%")
	if p, err := netip.ParsePrefix(s); err == nil {
		return p.Masked()
	}
	if a, err := netip.ParseAddr(s); err == nil {
		return netip.PrefixFrom(a.Unmap(), a.Unmap().BitLen())
	}
	return netip.Prefix{}
}

func check(conns, templates, rules []row, q plugin.FilterQuery) []plugin.FilterFinding {
	c := checker{q: q, chains: chains(rules), attr: "bgp-communities"}
	if strings.Count(q.Community, ":") == 2 {
		c.attr = "bgp-large-communities"
	}
	var out []plugin.FilterFinding
	found, ebgp := false, 0
	for _, raw := range conns {
		cn := resolve(raw, templates)
		switch {
		case cn.remote.IsValid() && cn.remote.Contains(q.Packeteer.Unmap()):
			found = true
			out = append(out, c.imports(cn))
		case strings.HasPrefix(cn.role, "ebgp"):
			ebgp++
			out = append(out, c.exports(cn))
		case cn.role == "":
			// It may be eBGP: an unknown role must not read as no eBGP.
			ebgp++
			out = append(out, plugin.FilterFinding{Verdict: plugin.VerdictUnknown, Detail: fmt.Sprintf("Connection %s: local.role is not set on the connection or its templates; read it by hand.", cn.name)})
		}
	}
	if !found {
		out = append(out, plugin.FilterFinding{
			Verdict: plugin.VerdictFail,
			Detail:  fmt.Sprintf("RouterOS has no BGP connection with remote.address %s (Packeteer).", q.Packeteer),
			Fix:     fmt.Sprintf("Add the connection for Packeteer from Router snippets: remote.address=%s local.role=ibgp input.filter=packeteer-in, with chain packeteer-in.", q.Packeteer),
		})
	}
	if ebgp == 0 {
		out = append(out, plugin.FilterFinding{Verdict: plugin.VerdictPass, Detail: "RouterOS has no eBGP connection."})
	}
	return out
}

// chainRule is one rule of a chain: its number in the chain (from 1, in
// print order) and its parsed statements. Disabled rules are not kept.
type chainRule struct {
	n     int
	stmts []stmt
	// invalid is set when RouterOS marks the rule invalid.
	invalid bool
}

// chains groups the enabled rules by chain. A chain whose rules are all
// disabled is still a key.
func chains(rules []row) map[string][]chainRule {
	out := map[string][]chainRule{}
	count := map[string]int{}
	for _, r := range rules {
		ch := r["chain"]
		count[ch]++
		rs := out[ch]
		if r["disabled"] != "true" {
			rs = append(rs, chainRule{n: count[ch], stmts: parseRule(r["rule"]), invalid: r["invalid"] == "true"})
		}
		out[ch] = rs
	}
	return out
}

type checker struct {
	q      plugin.FilterQuery
	chains map[string][]chainRule
	attr   string // bgp-communities or bgp-large-communities
}

// cond is the filter condition that matches the Packeteer community, as
// the mikrotik snippet writes it.
func (c checker) cond() string { return c.attr + " includes " + c.q.Community }

// ours reports whether a condition is exactly the community match.
func (c checker) ours(cond []string) bool {
	return strings.Join(cond, " ") == c.cond()
}

// mentions reports whether a condition reads communities at all.
func mentions(cond []string) bool {
	for _, t := range cond {
		if strings.Contains(t, "communities") {
			return true
		}
	}
	return false
}

func (c checker) imports(cn conn) plugin.FilterFinding {
	where := fmt.Sprintf("Import from Packeteer %s (connection %s)", c.q.Packeteer, cn.name)
	fix := fmt.Sprintf("Set input.filter=packeteer-in on connection %s, with chain packeteer-in from Router snippets (accept only %s, reject the rest).", cn.name, c.q.Community)
	switch {
	case cn.role == "":
		return plugin.FilterFinding{Verdict: plugin.VerdictUnknown, Detail: where + ": local.role is not set on the connection or its templates; read it by hand."}
	case !strings.HasPrefix(cn.role, "ibgp"):
		return plugin.FilterFinding{
			Verdict: plugin.VerdictFail,
			Detail:  fmt.Sprintf("%s: local.role is %s, not an iBGP session.", where, cn.role),
			Fix:     fmt.Sprintf("Set local.role=ibgp and remote.as to your own AS number on connection %s: Packeteer is an iBGP neighbor (Router snippets).", cn.name),
		}
	case cn.in == "":
		return plugin.FilterFinding{Verdict: plugin.VerdictFail, Detail: where + ": no input.filter, so every route from Packeteer is accepted.", Fix: fix}
	}
	rules, ok := c.chains[cn.in]
	if !ok {
		return plugin.FilterFinding{Verdict: plugin.VerdictFail, Detail: fmt.Sprintf("%s: input.filter names chain %s, which has no rules.", where, cn.in), Fix: fix}
	}
	if why := c.unreadable(cn.in, rules); why != "" {
		return plugin.FilterFinding{Verdict: plugin.VerdictUnknown, Detail: where + ": " + why}
	}
	// decided is set by the first if on the community: Packeteer's routes
	// end there, and later rules see only routes without it.
	accepts, decided := false, false
	for _, r := range rules {
		for _, s := range r.stmts {
			switch {
			case s.kind == "reject":
				return c.importEnd(where, cn.in, accepts, fix)
			case s.kind == "if" && s.action != "" && c.ours(s.cond):
				if !decided {
					accepts, decided = s.action == "accept", true
				}
			case s.kind == "accept":
				return plugin.FilterFinding{Verdict: plugin.VerdictFail, Detail: fmt.Sprintf("%s: chain %s accepts routes without %s (rule %d).", where, cn.in, c.q.Community, r.n), Fix: fix}
			case s.kind == "if" && s.action == "accept":
				switch {
				case mentions(s.cond):
					return plugin.FilterFinding{Verdict: plugin.VerdictUnknown, Detail: fmt.Sprintf("%s: chain %s rule %d accepts on a community condition the check does not read; read it by hand.", where, cn.in, r.n)}
				default:
					return plugin.FilterFinding{Verdict: plugin.VerdictFail, Detail: fmt.Sprintf("%s: chain %s accepts routes without %s (rule %d).", where, cn.in, c.q.Community, r.n), Fix: fix}
				}
			case s.kind == "if" && mentions(s.cond) && !c.ours(s.cond):
				// A reject on a community condition the check does not
				// parse can be what keeps a later accept correct.
				return c.unread(where, cn.in, r.n)
			case s.kind == "if" || s.kind == "set":
			default:
				return c.unread(where, cn.in, r.n)
			}
		}
	}
	return c.importEnd(where, cn.in, accepts, fix)
}

// importEnd is the import verdict once the chain rejects the rest, by a
// rule or by RouterOS's default at the end of a chain.
func (c checker) importEnd(where, chain string, accepts bool, fix string) plugin.FilterFinding {
	if !accepts {
		return plugin.FilterFinding{Verdict: plugin.VerdictFail, Detail: fmt.Sprintf("%s: chain %s never accepts %s, so Packeteer's routes are dropped.", where, chain, c.q.Community), Fix: fix}
	}
	return plugin.FilterFinding{Verdict: plugin.VerdictPass, Detail: fmt.Sprintf("%s: chain %s accepts only routes with %s.", where, chain, c.q.Community)}
}

func (c checker) exports(cn conn) plugin.FilterFinding {
	where := fmt.Sprintf("Export to eBGP connection %s", cn.name)
	if cn.out == "" {
		return plugin.FilterFinding{
			Verdict: plugin.VerdictFail,
			Detail:  fmt.Sprintf("%s: no output.filter-chain, so routes with %s are sent.", where, c.q.Community),
			Fix:     fmt.Sprintf("Set output.filter-chain=ebgp-out on connection %s, with the ebgp-out rule from Router snippets (if (%s) { reject } first).", cn.name, c.cond()),
		}
	}
	fix := fmt.Sprintf("Add the rule at the top of chain %s: /routing filter rule add chain=%s place-before=0 rule=\"if (%s) { reject }\" (Router snippets).", cn.out, cn.out, c.cond())
	rules, ok := c.chains[cn.out]
	if !ok {
		return plugin.FilterFinding{Verdict: plugin.VerdictFail, Detail: fmt.Sprintf("%s: output.filter-chain names chain %s, which has no rules.", where, cn.out), Fix: fix}
	}
	if why := c.unreadable(cn.out, rules); why != "" {
		return plugin.FilterFinding{Verdict: plugin.VerdictUnknown, Detail: where + ": " + why}
	}
	for _, r := range rules {
		for _, s := range r.stmts {
			switch {
			case s.kind == "reject":
				return plugin.FilterFinding{Verdict: plugin.VerdictPass, Detail: fmt.Sprintf("%s: chain %s rejects everything at rule %d.", where, cn.out, r.n)}
			case s.kind == "if" && s.action == "accept" && c.ours(s.cond):
				return plugin.FilterFinding{Verdict: plugin.VerdictFail, Detail: fmt.Sprintf("%s: chain %s accepts %s at rule %d.", where, cn.out, c.q.Community, r.n), Fix: fix}
			case s.kind == "if" && s.action == "reject" && c.ours(s.cond):
				return plugin.FilterFinding{Verdict: plugin.VerdictPass, Detail: fmt.Sprintf("%s: chain %s rejects %s at rule %d, before any accept.", where, cn.out, c.q.Community, r.n)}
			case s.kind == "if" && s.action != "accept", s.kind == "set":
			case s.kind == "accept" || s.kind == "if" && !mentions(s.cond):
				return plugin.FilterFinding{Verdict: plugin.VerdictFail, Detail: fmt.Sprintf("%s: chain %s accepts at rule %d before %s is rejected.", where, cn.out, r.n, c.q.Community), Fix: fix}
			default:
				return c.unread(where, cn.out, r.n)
			}
		}
	}
	return plugin.FilterFinding{Verdict: plugin.VerdictPass, Detail: fmt.Sprintf("%s: chain %s accepts nothing.", where, cn.out)}
}

// unreadable says why a chain cannot be followed: a rule RouterOS marks
// invalid.
func (c checker) unreadable(chain string, rules []chainRule) string {
	for _, r := range rules {
		if r.invalid {
			return fmt.Sprintf("chain %s rule %d is marked invalid by RouterOS; read it by hand.", chain, r.n)
		}
	}
	return ""
}

func (c checker) unread(where, chain string, n int) plugin.FilterFinding {
	return plugin.FilterFinding{Verdict: plugin.VerdictUnknown, Detail: fmt.Sprintf("%s: chain %s rule %d has a statement the check does not follow (jump, return, else, or a community change); read it by hand.", where, chain, n)}
}

// stmt is one statement of a rule. kind is accept, reject, set (a change
// that leaves the communities alone), if (a condition whose block holds
// such changes and at most one final accept or reject, in action), or
// other: anything the check does not follow.
type stmt struct {
	kind   string
	cond   []string
	action string
}

// parseRule splits a rule's text into statements.
func parseRule(text string) []stmt { return statements(lex(text)) }

func statements(toks []string) []stmt {
	var out []stmt
	for i := 0; i < len(toks); {
		s, next := statement(toks, i)
		if s.kind != "" {
			out = append(out, s)
		}
		i = next
	}
	return out
}

// lex splits rule text into words, quoted strings, and the characters
// ( ) { } ; on their own.
func lex(s string) []string {
	var out []string
	for i := 0; i < len(s); {
		switch c := s[i]; {
		case c == ' ' || c == '\t' || c == '\n' || c == '\r':
			i++
		case strings.IndexByte("(){};", c) >= 0:
			out = append(out, string(c))
			i++
		case c == '"':
			j := i + 1
			for j < len(s) && s[j] != '"' {
				if s[j] == '\\' {
					j++
				}
				j++
			}
			out = append(out, s[i:min(j+1, len(s))])
			i = j + 1
		default:
			j := i
			for j < len(s) && strings.IndexByte(" \t\r\n(){};\"", s[j]) < 0 {
				j++
			}
			out = append(out, s[i:j])
			i = j
		}
	}
	return out
}

// closing returns the index of the bracket that closes the one at open.
func closing(toks []string, open int) int {
	depth := 0
	for i := open; i < len(toks); i++ {
		switch toks[i] {
		case "(", "{":
			depth++
		case ")", "}":
			if depth--; depth == 0 {
				return i
			}
		}
	}
	return len(toks)
}

// statement parses the statement at i and returns the index after it. An
// empty statement (a lone ;) has no kind.
func statement(toks []string, i int) (stmt, int) {
	switch toks[i] {
	case ";":
		return stmt{}, i + 1
	case "accept", "reject":
		return stmt{kind: toks[i]}, endOf(toks, i)
	case "if":
		if i+1 >= len(toks) || toks[i+1] != "(" {
			return stmt{kind: "other"}, endOf(toks, i)
		}
		ce := closing(toks, i+1)
		if ce+1 >= len(toks) || toks[ce+1] != "{" {
			return stmt{kind: "other"}, endOf(toks, i)
		}
		be := closing(toks, ce+1)
		next := min(be+1, len(toks))
		if next < len(toks) && toks[next] == "else" {
			return stmt{kind: "other"}, endOf(toks, next)
		}
		action, ok := block(toks[ce+2 : min(be, len(toks))])
		if !ok {
			return stmt{kind: "other"}, next
		}
		return stmt{kind: "if", cond: unwrap(toks[i+2 : ce]), action: action}, next
	case "set", "append":
		end := endOf(toks, i)
		if i+1 < end && !strings.Contains(toks[i+1], "communities") {
			return stmt{kind: "set"}, end
		}
	}
	return stmt{kind: "other"}, endOf(toks, i)
}

// block reads the body of an if: changes that leave the communities alone
// and at most one accept or reject, last.
func block(toks []string) (action string, ok bool) {
	for _, s := range statements(toks) {
		switch {
		case action != "":
			return "", false
		case s.kind == "accept" || s.kind == "reject":
			action = s.kind
		case s.kind != "set":
			return "", false
		}
	}
	return action, true
}

// unwrap drops parentheses that enclose the whole condition.
func unwrap(cond []string) []string {
	for len(cond) >= 2 && cond[0] == "(" && closing(cond, 0) == len(cond)-1 {
		cond = cond[1 : len(cond)-1]
	}
	return cond
}

// endOf returns the index after the statement that starts at i: past the
// next ; outside brackets, or the end.
func endOf(toks []string, i int) int {
	for depth := 0; i < len(toks); i++ {
		switch toks[i] {
		case "(", "{":
			depth++
		case ")", "}":
			depth--
		case ";":
			if depth == 0 {
				return i + 1
			}
		}
	}
	return i
}
