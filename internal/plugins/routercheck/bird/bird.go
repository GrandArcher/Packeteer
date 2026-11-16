// Package bird is the BIRD 2 and 3 backend of the read-only router check
// (#626). It reads the protocols over BIRD's control socket in a restricted
// session and the bodies of the filters they use from the config file,
// since birdc does not print a filter. It sends only the commands on its
// allowlist and never reconfigures, reloads, or disables anything.
package bird

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"net/netip"
	"os"
	"strconv"
	"strings"

	"github.com/GrandArcher/Packeteer/internal/plugins/routercheck/readonly"
	"github.com/GrandArcher/Packeteer/pkg/plugin"
)

// TypeName is the router_check type.
const TypeName = "bird"

func init() { plugin.RouterChecks.Register(TypeName, New) }

// Config is preflight.router_check.config for type bird.
type Config struct {
	// SocketEnv names the environment variable that holds the path of
	// BIRD's control socket (bird.ctl).
	SocketEnv string `yaml:"socket_env"`
	// ConfigEnv names the environment variable that holds the path of the
	// bird.conf BIRD runs, mounted read-only.
	ConfigEnv string `yaml:"config_env"`
}

var allow = readonly.NewAllowlist(
	// restrict makes BIRD itself refuse every command that changes state
	// for the rest of the session; it is always sent first.
	`restrict`,
	`show protocols all`,
)

// Limits on what is read.
const (
	maxReply  = 16 << 20
	maxConfig = 4 << 20
)

// codeRestricted is BIRD's reply to restrict ("Access restricted").
const codeRestricted = 16

// Reader is the bird router check.
type Reader struct {
	plugin.Base
	socket, conf string
}

// New validates the config. It does not connect or read the file.
func New(c plugin.Config, env plugin.Env) (plugin.RouterCheck, error) {
	var cfg Config
	if err := c.Decode(&cfg); err != nil {
		return nil, err
	}
	sock, err := readonly.Path(env.Getenv, "socket_env", cfg.SocketEnv, env.CheckOnly)
	if err != nil {
		return nil, err
	}
	conf, err := readonly.Path(env.Getenv, "config_env", cfg.ConfigEnv, env.CheckOnly)
	if err != nil {
		return nil, err
	}
	return &Reader{socket: sock, conf: conf}, nil
}

// CheckFilters reads the protocols from BIRD and their filters from the
// config file.
func (r *Reader) CheckFilters(ctx context.Context, q plugin.FilterQuery) ([]plugin.FilterFinding, error) {
	text, err := readConfig(r.conf)
	if err != nil {
		return nil, err
	}
	conn, err := readonly.Dial(ctx, r.socket)
	if err != nil {
		return nil, err
	}
	defer conn.Close()
	s := &session{w: conn, r: bufio.NewReader(conn)}
	protos, err := s.protocols()
	if err != nil {
		return nil, err
	}
	return check(protos, parseConfig(text), q), nil
}

func readConfig(path string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", fmt.Errorf("read the BIRD config: %w", readonly.Scrub(err))
	}
	defer f.Close()
	b, err := io.ReadAll(io.LimitReader(f, maxConfig+1))
	if err != nil {
		return "", fmt.Errorf("read the BIRD config: %w", readonly.Scrub(err))
	}
	if len(b) > maxConfig {
		return "", errors.New("read the BIRD config: file too large")
	}
	return string(b), nil
}

// session is one connection to BIRD's control socket.
type session struct {
	w io.Writer
	r *bufio.Reader
}

type line struct {
	code int
	text string
}

// reply reads one reply: lines "DDDD-text" and " text" continue it, the
// line "DDDD text" ends it, and "+" lines are log echoes.
func (s *session) reply() ([]line, int, error) {
	var out []line
	size, last := 0, 0
	for {
		l, err := s.r.ReadString('\n')
		if err != nil {
			return nil, 0, fmt.Errorf("read from BIRD: %w", readonly.Scrub(err))
		}
		if size += len(l); size > maxReply {
			return nil, 0, errors.New("read from BIRD: reply too long")
		}
		l = strings.TrimRight(l, "\r\n")
		switch {
		case strings.HasPrefix(l, "+"):
		case strings.HasPrefix(l, " "):
			out = append(out, line{last, l[1:]})
		case len(l) >= 5 && (l[4] == '-' || l[4] == ' '):
			code, err := strconv.Atoi(l[:4])
			if err != nil {
				return nil, 0, errors.New("read from BIRD: malformed reply")
			}
			last = code
			if l[4] == ' ' {
				return out, code, nil
			}
			out = append(out, line{code, l[5:]})
		default:
			return nil, 0, errors.New("read from BIRD: malformed reply")
		}
	}
}

// run sends one allowlisted command and returns its reply.
func (s *session) run(cmd string) ([]line, int, error) {
	if err := allow.Check(cmd); err != nil {
		return nil, 0, err
	}
	if _, err := io.WriteString(s.w, cmd+"\n"); err != nil {
		return nil, 0, fmt.Errorf("send to BIRD: %w", readonly.Scrub(err))
	}
	return s.reply()
}

// protocols reads the greeting, restricts the session, and lists the
// protocols. Without the restriction nothing else is sent.
func (s *session) protocols() ([]proto, error) {
	if _, code, err := s.reply(); err != nil || code != 1 {
		return nil, errors.Join(err, errors.New("BIRD sent no greeting"))
	}
	if _, code, err := s.run("restrict"); err != nil || code != codeRestricted {
		return nil, errors.Join(err, fmt.Errorf("BIRD did not restrict the session (answered %d)", code))
	}
	lines, code, err := s.run("show protocols all")
	if err != nil {
		return nil, err
	}
	if code >= 8000 {
		return nil, fmt.Errorf("BIRD answered %d to show protocols all", code)
	}
	return parseProtocols(lines), nil
}

type proto struct {
	name, kind          string
	neighbor            netip.Addr
	neighborAS, localAS string
	channels            []channel
}

type channel struct{ name, in, out string }

func parseProtocols(lines []line) []proto {
	var out []proto
	for _, l := range lines {
		switch l.code {
		case 1002:
			if f := strings.Fields(l.text); len(f) >= 2 {
				out = append(out, proto{name: f[0], kind: f[1]})
			}
		case 1006:
			if len(out) == 0 {
				continue
			}
			p := &out[len(out)-1]
			t := strings.TrimSpace(l.text)
			if name, ok := strings.CutPrefix(t, "Channel "); ok {
				p.channels = append(p.channels, channel{name: name})
				continue
			}
			key, val, ok := strings.Cut(t, ":")
			if !ok {
				continue
			}
			val = strings.TrimSpace(val)
			switch key {
			case "Neighbor address":
				a, _, _ := strings.Cut(val, "%")
				p.neighbor, _ = netip.ParseAddr(a)
			case "Neighbor AS":
				p.neighborAS = val
			case "Local AS":
				p.localAS = val
			case "Input filter", "Output filter":
				if len(p.channels) == 0 {
					continue
				}
				c := &p.channels[len(p.channels)-1]
				if key == "Input filter" {
					c.in = val
				} else {
					c.out = val
				}
			}
		}
	}
	return out
}

// conf is what the check reads from bird.conf: each named filter as a list
// of top-level statements.
type conf struct {
	filters  map[string][]stmt
	includes bool
}

// stmt is one filter statement. kind is accept, reject, if (with a single
// statement and no else), or other: anything the check does not follow.
type stmt struct {
	kind string
	cond []string
	then *stmt
}

func parseConfig(text string) conf {
	toks := lex(text)
	c := conf{filters: map[string][]stmt{}}
	depth := 0
	for i := 0; i < len(toks); i++ {
		switch t := toks[i]; {
		case t == "{":
			depth++
		case t == "}":
			depth--
		case depth == 0 && t == "include":
			c.includes = true
		case depth == 0 && t == "filter" && i+2 < len(toks) && toks[i+2] == "{":
			end := closing(toks, i+2)
			c.filters[toks[i+1]] = statements(toks[i+3 : end])
			i = end
		}
	}
	return c
}

// lex splits BIRD config text into words, quoted strings, and single
// punctuation characters, dropping comments.
func lex(s string) []string {
	var out []string
	for i := 0; i < len(s); {
		c := s[i]
		switch {
		case c == ' ' || c == '\t' || c == '\n' || c == '\r':
			i++
		case c == '#':
			for i < len(s) && s[i] != '\n' {
				i++
			}
		case strings.HasPrefix(s[i:], "/*"):
			end := strings.Index(s[i+2:], "*/")
			if end < 0 {
				return out
			}
			i += end + 4
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
		case isWord(c):
			j := i
			for j < len(s) && isWord(s[j]) {
				j++
			}
			out = append(out, s[i:j])
			i = j
		default:
			out = append(out, string(c))
			i++
		}
	}
	return out
}

func isWord(c byte) bool {
	return c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '_' || c == '.' || c == ':'
}

// closing returns the index of the bracket that closes the one at open.
func closing(toks []string, open int) int {
	depth := 0
	for i := open; i < len(toks); i++ {
		switch toks[i] {
		case "{", "(", "[":
			depth++
		case "}", ")", "]":
			if depth--; depth == 0 {
				return i
			}
		}
	}
	return len(toks)
}

func statements(toks []string) []stmt {
	var out []stmt
	for i := 0; i < len(toks); {
		s, next := statement(toks, i)
		out = append(out, s)
		i = next
	}
	return out
}

// statement parses the statement at i and returns the index after it.
func statement(toks []string, i int) (stmt, int) {
	switch toks[i] {
	case "accept", "reject":
		return stmt{kind: toks[i]}, skipPast(toks, i)
	case "{":
		return stmt{kind: "other"}, closing(toks, i) + 1
	case "if":
		j := i + 1
		for j < len(toks) && toks[j] != "then" {
			j++
		}
		cond := toks[i+1 : j]
		if j+1 >= len(toks) {
			return stmt{kind: "other"}, len(toks)
		}
		then, next := statement(toks, j+1)
		if next < len(toks) && toks[next] == "else" {
			_, next = statement(toks, next+1)
			return stmt{kind: "other"}, next
		}
		if then.kind == "if" || then.kind == "other" {
			return stmt{kind: "other"}, next
		}
		return stmt{kind: "if", cond: cond, then: &then}, next
	}
	return stmt{kind: "other"}, skipPast(toks, i)
}

// skipPast returns the index after the ';' that ends the statement at i.
func skipPast(toks []string, i int) int {
	for depth := 0; i < len(toks); i++ {
		switch toks[i] {
		case "{", "(", "[":
			depth++
		case "}", ")", "]":
			depth--
		case ";":
			if depth == 0 {
				return i + 1
			}
		}
	}
	return i
}

// matcher recognizes the condition that matches the Packeteer community.
type matcher struct {
	forms []string
	// text is the condition as the bird snippet writes it, for fix text.
	text string
}

func newMatcher(community string) matcher {
	attr := "bgp_community"
	if strings.Count(community, ":") == 2 {
		attr = "bgp_large_community"
	}
	tuple := "(" + strings.ReplaceAll(community, ":", ",") + ")"
	return matcher{
		forms: []string{tuple + "~" + attr, attr + "~[" + tuple + "]"},
		text:  "(" + strings.ReplaceAll(community, ":", ", ") + ") ~ " + attr,
	}
}

// ours reports whether cond is exactly the community match.
func (m matcher) ours(cond []string) bool {
	s := strings.Join(cond, "")
	for _, f := range m.forms {
		if s == f || s == "("+f+")" {
			return true
		}
	}
	return false
}

// mentions reports whether cond reads communities at all.
func (m matcher) mentions(cond []string) bool {
	for _, t := range cond {
		if t == "bgp_community" || t == "bgp_large_community" {
			return true
		}
	}
	return false
}

func check(protos []proto, cf conf, q plugin.FilterQuery) []plugin.FilterFinding {
	c := checker{cf: cf, q: q, m: newMatcher(q.Community)}
	var out []plugin.FilterFinding
	found, ebgp := false, 0
	for _, p := range protos {
		if p.kind != "BGP" {
			continue
		}
		switch {
		case p.neighbor.IsValid() && p.neighbor.Unmap() == q.Packeteer.Unmap():
			found = true
			out = append(out, c.imports(p)...)
		case p.neighborAS != "" && p.neighborAS != p.localAS:
			ebgp++
			out = append(out, c.exports(p)...)
		}
	}
	if !found {
		out = append(out, plugin.FilterFinding{
			Verdict: plugin.VerdictFail,
			Detail:  fmt.Sprintf("BIRD has no BGP protocol with neighbor %s (Packeteer).", q.Packeteer),
			Fix:     "Add protocol bgp packeteer from Router snippets, with import filter packeteer_in, then run birdc configure.",
		})
	}
	if ebgp == 0 {
		out = append(out, plugin.FilterFinding{Verdict: plugin.VerdictPass, Detail: "BIRD has no eBGP protocol."})
	}
	return out
}

type checker struct {
	cf conf
	q  plugin.FilterQuery
	m  matcher
}

func unicast(c channel) bool { return c.name == "ipv4" || c.name == "ipv6" }

func (c checker) imports(p proto) []plugin.FilterFinding {
	if p.neighborAS != p.localAS {
		return []plugin.FilterFinding{{
			Verdict: plugin.VerdictFail,
			Detail:  fmt.Sprintf("Protocol %s (Packeteer) is not an iBGP session.", p.name),
			Fix:     fmt.Sprintf("In protocol %s, set the neighbor AS to your own AS number: Packeteer is an iBGP neighbor (Router snippets).", p.name),
		}}
	}
	var out []plugin.FilterFinding
	for _, ch := range p.channels {
		if !unicast(ch) {
			continue
		}
		where := fmt.Sprintf("Import from Packeteer (protocol %s, %s)", p.name, ch.name)
		fix := fmt.Sprintf("In protocol %s, channel %s: import filter packeteer_in, with packeteer_in from Router snippets (accept only %s, reject the rest), then run birdc configure.", p.name, ch.name, c.q.Community)
		switch ch.in {
		case "ACCEPT":
			out = append(out, plugin.FilterFinding{Verdict: plugin.VerdictFail, Detail: where + ": import all, so every route from Packeteer is accepted.", Fix: fix})
		case "REJECT":
			out = append(out, plugin.FilterFinding{Verdict: plugin.VerdictFail, Detail: where + ": import none, so Packeteer's routes are dropped.", Fix: fix})
		default:
			out = append(out, c.importFilter(where, ch.in, fix))
		}
	}
	if len(out) == 0 {
		out = append(out, plugin.FilterFinding{Verdict: plugin.VerdictUnknown, Detail: fmt.Sprintf("Protocol %s (Packeteer) has no ipv4 or ipv6 channel.", p.name)})
	}
	return out
}

func (c checker) importFilter(where, name, fix string) plugin.FilterFinding {
	body, why := c.filter(name)
	if why != "" {
		return plugin.FilterFinding{Verdict: plugin.VerdictUnknown, Detail: where + ": " + why}
	}
	accepts := false
loop:
	for i, s := range body {
		switch {
		case s.kind == "reject":
			break loop
		case s.kind == "accept":
			return plugin.FilterFinding{Verdict: plugin.VerdictFail, Detail: fmt.Sprintf("%s: filter %s accepts routes without %s (statement %d).", where, name, c.q.Community, i+1), Fix: fix}
		case s.kind == "if" && s.then.kind == "accept":
			switch {
			case c.m.ours(s.cond):
				accepts = true
			case c.m.mentions(s.cond):
				return plugin.FilterFinding{Verdict: plugin.VerdictUnknown, Detail: fmt.Sprintf("%s: filter %s statement %d accepts on a community condition the check does not read; read it by hand.", where, name, i+1)}
			default:
				return plugin.FilterFinding{Verdict: plugin.VerdictFail, Detail: fmt.Sprintf("%s: filter %s accepts routes without %s (statement %d).", where, name, c.q.Community, i+1), Fix: fix}
			}
		case s.kind == "if":
		default:
			return plugin.FilterFinding{Verdict: plugin.VerdictUnknown, Detail: fmt.Sprintf("%s: filter %s statement %d is not one the check reads; read it by hand.", where, name, i+1)}
		}
	}
	if !accepts {
		return plugin.FilterFinding{Verdict: plugin.VerdictFail, Detail: fmt.Sprintf("%s: filter %s never accepts %s, so Packeteer's routes are dropped.", where, name, c.q.Community), Fix: fix}
	}
	return plugin.FilterFinding{Verdict: plugin.VerdictPass, Detail: fmt.Sprintf("%s: filter %s accepts only routes with %s (body read from the config file).", where, name, c.q.Community)}
}

func (c checker) exports(p proto) []plugin.FilterFinding {
	var out []plugin.FilterFinding
	for _, ch := range p.channels {
		if !unicast(ch) {
			continue
		}
		where := fmt.Sprintf("Export to eBGP protocol %s (%s)", p.name, ch.name)
		switch ch.out {
		case "ACCEPT":
			out = append(out, plugin.FilterFinding{
				Verdict: plugin.VerdictFail,
				Detail:  fmt.Sprintf("%s: export all, so routes with %s are sent.", where, c.q.Community),
				Fix:     fmt.Sprintf("In protocol %s, channel %s: export filter ebgp_out, with ebgp_out from Router snippets (if %s then reject; first), then run birdc configure.", p.name, ch.name, c.m.text),
			})
		case "REJECT":
			out = append(out, plugin.FilterFinding{Verdict: plugin.VerdictPass, Detail: where + ": export none."})
		default:
			out = append(out, c.exportFilter(where, ch.out))
		}
	}
	return out
}

func (c checker) exportFilter(where, name string) plugin.FilterFinding {
	body, why := c.filter(name)
	if why != "" {
		return plugin.FilterFinding{Verdict: plugin.VerdictUnknown, Detail: where + ": " + why}
	}
	fix := fmt.Sprintf("Make the first statement of filter %s: if %s then reject; (Router snippets), then run birdc configure.", name, c.m.text)
	for i, s := range body {
		switch {
		case s.kind == "reject":
			return plugin.FilterFinding{Verdict: plugin.VerdictPass, Detail: fmt.Sprintf("%s: filter %s rejects everything (statement %d).", where, name, i+1)}
		case s.kind == "if" && s.then.kind == "reject" && c.m.ours(s.cond):
			return plugin.FilterFinding{Verdict: plugin.VerdictPass, Detail: fmt.Sprintf("%s: filter %s rejects %s at statement %d, before any accept (body read from the config file).", where, name, c.q.Community, i+1)}
		case s.kind == "if" && s.then.kind == "reject":
		case s.kind == "accept" || s.kind == "if" && !c.m.mentions(s.cond):
			return plugin.FilterFinding{Verdict: plugin.VerdictFail, Detail: fmt.Sprintf("%s: filter %s accepts at statement %d before %s is rejected.", where, name, i+1, c.q.Community), Fix: fix}
		default:
			return plugin.FilterFinding{Verdict: plugin.VerdictUnknown, Detail: fmt.Sprintf("%s: filter %s statement %d is not one the check reads; read it by hand.", where, name, i+1)}
		}
	}
	return plugin.FilterFinding{Verdict: plugin.VerdictPass, Detail: fmt.Sprintf("%s: filter %s accepts nothing.", where, name)}
}

// filter returns a named filter's statements, or why it cannot be read.
func (c checker) filter(name string) ([]stmt, string) {
	if name == "(unnamed)" {
		return nil, "an unnamed (inline) filter is not read; use a named filter."
	}
	body, ok := c.cf.filters[name]
	if !ok && c.cf.includes {
		return nil, "filter " + name + " is not in the config file (included files are not read)."
	}
	if !ok {
		return nil, "filter " + name + " is not in the config file."
	}
	return body, ""
}
