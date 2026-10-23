package whois

import (
	"bufio"
	"context"
	"fmt"
	"net"
	"net/netip"
	"os"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"gopkg.in/yaml.v3"

	"github.com/GrandArcher/Packeteer/pkg/plugin"
)

func fixture(t *testing.T, name string) string {
	t.Helper()
	b, err := os.ReadFile("testdata/" + name)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

// irrdServer answers IRRd whois queries with the port 43 framing: !! and
// !s are taken first, then the query is answered from answers ("C", "D",
// "F <msg>", or a body sent as A<length> ... C).
type irrdServer struct {
	ln      net.Listener
	answers map[string]string
	mu      sync.Mutex
	seen    []string
}

func newIRRd(t *testing.T, answers map[string]string) *irrdServer {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	s := &irrdServer{ln: ln, answers: answers}
	t.Cleanup(func() { ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go s.serve(c)
		}
	}()
	return s
}

func frame(answer string) string {
	switch {
	case answer == "C" || answer == "D" || strings.HasPrefix(answer, "F "):
		return answer + "\n"
	}
	body := strings.TrimRight(answer, "\n")
	return fmt.Sprintf("A%d\n%s\nC\n", len(body)+1, body)
}

func (s *irrdServer) serve(c net.Conn) {
	defer c.Close()
	br := bufio.NewReader(c)
	for {
		line, err := br.ReadString('\n')
		if err != nil {
			return
		}
		line = strings.TrimRight(line, "\n")
		s.mu.Lock()
		s.seen = append(s.seen, line)
		s.mu.Unlock()
		switch {
		case line == "!!":
		case strings.HasPrefix(line, "!s"):
			if line == "!sNOPE" {
				_, _ = c.Write([]byte(frame("F One or more selected sources are unavailable.")))
				return
			}
			_, _ = c.Write([]byte("C\n"))
		default:
			a, ok := s.answers[line]
			if !ok {
				a = "C"
			}
			_, _ = c.Write([]byte(frame(a)))
		}
	}
}

// queries is every line received, in order. A lookup's lines are all
// read before its answer is written.
func (s *irrdServer) queries() []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return slices.Clone(s.seen)
}

func newClient(t *testing.T, cfg string) *Client {
	t.Helper()
	var node yaml.Node
	if err := yaml.Unmarshal([]byte(cfg), &node); err != nil {
		t.Fatal(err)
	}
	p, err := New(plugin.NewConfig(node.Content[0]), plugin.Env{Name: "test"})
	if err != nil {
		t.Fatal(err)
	}
	return p.(*Client)
}

// #214: route/route6, as-set, and aut-num lookups against an IRRd server
// with the recorded answer shapes. The databases are selected with !s in
// order and the matching objects come back in that order; the RPKI
// pseudo-source is not IRR data.
func TestIRRdLookups(t *testing.T) {
	srv := newIRRd(t, map[string]string{
		"!r198.51.100.0/24": fixture(t, "irrd-route.txt"),
		"!r2001:db8::/32":   fixture(t, "irrd-route6.txt"),
		"!iAS-EXAMPLE,1":    fixture(t, "irrd-as-set.txt"),
		"!maut-num,AS64496": fixture(t, "irrd-aut-num.txt"),
		"!iAS-NOTHERE,1":    "D",
		"!maut-num,AS64511": "D",
		"!r203.0.113.0/24":  "C",
		"!r192.0.2.0/24":    "F Invalid input for route search: 192.0.2.0/24",
	})
	c := newClient(t, "{address: \""+srv.ln.Addr().String()+"\", databases: [radb, ripe], rate_per_minute: 600}")
	ctx := context.Background()
	before := time.Now()

	routes, at, err := c.Routes(ctx, netip.MustParsePrefix("198.51.100.0/24"))
	if err != nil {
		t.Fatal(err)
	}
	want := []plugin.IRRRoute{
		{Prefix: netip.MustParsePrefix("198.51.100.0/24"), Origin: 64497, Database: "RADB"},
		{Prefix: netip.MustParsePrefix("198.51.100.0/24"), Origin: 64496, Database: "RIPE"},
	}
	if !slices.Equal(routes, want) {
		t.Fatalf("routes = %+v, want %+v (RADB first, no RPKI object)", routes, want)
	}
	if at.Before(before) {
		t.Fatalf("data time %s is not the query time", at)
	}
	if q := srv.queries(); !slices.Equal(q, []string{"!!", "!sRADB,RIPE", "!r198.51.100.0/24"}) {
		t.Fatalf("sent %q", q)
	}
	routes, _, err = c.Routes(ctx, netip.MustParsePrefix("2001:db8::/32"))
	if err != nil || len(routes) != 1 || routes[0].Origin != 64496 || routes[0].Database != "RIPE" {
		t.Fatalf("route6 = %+v %v", routes, err)
	}
	if routes, _, err = c.Routes(ctx, netip.MustParsePrefix("203.0.113.0/24")); err != nil || len(routes) != 0 {
		t.Fatalf("no objects = %+v %v", routes, err)
	}
	if _, _, err = c.Routes(ctx, netip.MustParsePrefix("192.0.2.0/24")); err == nil || !strings.Contains(err.Error(), "server error: Invalid input for route search") {
		t.Fatalf("F answer err = %v", err)
	}

	members, _, err := c.ASSetMembers(ctx, "AS-EXAMPLE")
	if err != nil || !slices.Equal(members, []uint32{64496, 64497, 64499}) {
		t.Fatalf("as-set = %v %v", members, err)
	}
	if members, _, err = c.ASSetMembers(ctx, "AS-NOTHERE"); err != nil || len(members) != 0 {
		t.Fatalf("missing as-set = %v %v", members, err)
	}
	if _, _, err = c.ASSetMembers(ctx, "not a set"); err == nil {
		t.Fatal("a bad as-set name was sent")
	}
	name, _, err := c.ASName(ctx, 64496)
	if err != nil || name != "EXAMPLE-NET-AS" {
		t.Fatalf("as-name = %q %v", name, err)
	}
	if name, _, err = c.ASName(ctx, 64511); err != nil || name != "" {
		t.Fatalf("missing aut-num = %q %v", name, err)
	}
}

// A database the server does not have fails the lookup, so the cache
// treats the source as not answering.
func TestIRRdUnknownDatabase(t *testing.T) {
	srv := newIRRd(t, nil)
	c := newClient(t, "{address: \""+srv.ln.Addr().String()+"\", databases: [nope]}")
	if _, _, err := c.Routes(context.Background(), netip.MustParsePrefix("198.51.100.0/24")); err == nil || !strings.Contains(err.Error(), "One or more selected sources are unavailable.") {
		t.Fatalf("err = %v", err)
	}
}

// ripeServer answers one RIPE-style query per connection and closes.
func ripeServer(t *testing.T, answers map[string]string) (string, func() []string) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	var mu sync.Mutex
	var seen []string
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				defer c.Close()
				line, err := bufio.NewReader(c).ReadString('\n')
				if err != nil {
					return
				}
				line = strings.TrimRight(line, "\n")
				mu.Lock()
				seen = append(seen, line)
				mu.Unlock()
				_, _ = c.Write([]byte(answers[line]))
			}()
		}
	}()
	return ln.Addr().String(), func() []string { mu.Lock(); defer mu.Unlock(); return slices.Clone(seen) }
}

// #214: the RIPE dialect sends -r and -s with each query, reads the
// objects until the server closes, treats ERROR:101 as nothing found and
// another ERROR as a failure, and expands as-sets set by set, visiting a
// loop once.
func TestRIPELookups(t *testing.T) {
	noEntries := fixture(t, "ripe-no-entries.txt")
	addr, seen := ripeServer(t, map[string]string{
		"-r -s RIPE -x -T route,route6 203.0.113.0/24":  fixture(t, "ripe-route.txt"),
		"-r -s RIPE -x -T route,route6 198.51.100.0/24": noEntries,
		"-r -s RIPE -x -T route,route6 192.0.2.0/24":    fixture(t, "ripe-access-denied.txt"),
		"-r -s RIPE -T as-set AS-EXAMPLE":               fixture(t, "ripe-as-set.txt"),
		"-r -s RIPE -T as-set AS64500:AS-CUSTOMERS":     fixture(t, "ripe-as-set-nested.txt"),
		"-r -s RIPE -T aut-num AS64500":                 fixture(t, "ripe-aut-num.txt"),
		"-r -s RIPE -T aut-num AS64511":                 noEntries,
	})
	c := newClient(t, "{address: \""+addr+"\", dialect: ripe, databases: [RIPE], rate_per_minute: 600}")
	ctx := context.Background()

	routes, _, err := c.Routes(ctx, netip.MustParsePrefix("203.0.113.0/24"))
	if err != nil || !slices.Equal(routes, []plugin.IRRRoute{{Prefix: netip.MustParsePrefix("203.0.113.0/24"), Origin: 64500, Database: "RIPE"}}) {
		t.Fatalf("routes = %+v %v", routes, err)
	}
	if routes, _, err = c.Routes(ctx, netip.MustParsePrefix("198.51.100.0/24")); err != nil || len(routes) != 0 {
		t.Fatalf("no entries = %+v %v", routes, err)
	}
	if _, _, err = c.Routes(ctx, netip.MustParsePrefix("192.0.2.0/24")); err == nil || !strings.Contains(err.Error(), "ERROR:201: access denied") {
		t.Fatalf("access denied err = %v", err)
	}
	members, _, err := c.ASSetMembers(ctx, "AS-EXAMPLE")
	if err != nil || !slices.Equal(members, []uint32{64500, 64501, 64502, 64503}) {
		t.Fatalf("as-set = %v %v", members, err)
	}
	name, _, err := c.ASName(ctx, 64500)
	if err != nil || name != "EXAMPLE-AS" {
		t.Fatalf("as-name = %q %v", name, err)
	}
	if name, _, err = c.ASName(ctx, 64511); err != nil || name != "" {
		t.Fatalf("missing aut-num = %q %v", name, err)
	}
	asked := 0
	for _, q := range seen() {
		if strings.Contains(q, "-T as-set") {
			asked++
		}
	}
	if asked != 2 {
		t.Fatalf("as-set queries = %d, want 2 (the loop back to AS-EXAMPLE is not asked again)", asked)
	}
}

// A server that never answers fails at the timeout, and ending the
// context closes the connection at once.
func TestTimeoutAndCancel(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			defer c.Close()
		}
	}()
	c := newClient(t, "{address: \""+ln.Addr().String()+"\", timeout: 1s, rate_per_minute: 600}")
	start := time.Now()
	if _, _, err := c.Routes(context.Background(), netip.MustParsePrefix("198.51.100.0/24")); err == nil {
		t.Fatal("silent server answered")
	}
	if d := time.Since(start); d > 3*time.Second {
		t.Fatalf("timeout took %s", d)
	}
	ctx, cancel := context.WithCancel(context.Background())
	time.AfterFunc(50*time.Millisecond, cancel)
	start = time.Now()
	if _, _, err := c.Routes(ctx, netip.MustParsePrefix("198.51.100.0/24")); err == nil {
		t.Fatal("cancelled lookup answered")
	}
	if d := time.Since(start); d > 900*time.Millisecond {
		t.Fatalf("cancel took %s", d)
	}
}

func TestConfigValidation(t *testing.T) {
	for cfg, want := range map[string]string{
		"{}":                           `address "" must be host:port`,
		"{address: whois.example.net}": `must be host:port`,
		"{address: \"whois.example.net:43\", dialect: rpsl}":           `dialect "rpsl" must be irrd or ripe`,
		"{address: \"whois.example.net:43\", databases: [radb, RADB]}": `databases[1] RADB is listed twice`,
		"{address: \"whois.example.net:43\", databases: [\"ra db\"]}":  `is not a database name`,
		"{address: \"whois.example.net:43\", timeout: 2m}":             `timeout 2m0s must be between`,
		"{address: \"whois.example.net:43\", rate_per_minute: 601}":    `rate_per_minute 601 must be between 1 and 600`,
		"{address: \"whois.example.net:43\", bogus: 1}":                `bogus`,
	} {
		var node yaml.Node
		if err := yaml.Unmarshal([]byte(cfg), &node); err != nil {
			t.Fatal(err)
		}
		if _, err := New(plugin.NewConfig(node.Content[0]), plugin.Env{}); err == nil || !strings.Contains(err.Error(), want) {
			t.Errorf("%s: err %v, want %q", cfg, err, want)
		}
	}
	c := newClient(t, "{address: \"whois.example.net:43\", databases: [ ripe , radb]}")
	if c.cfg.Dialect != DialectIRRd || !slices.Equal(c.cfg.Databases, []string{"RIPE", "RADB"}) || c.cfg.Timeout != DefaultTimeout || c.cfg.RatePerMinute != DefaultRatePerMinute {
		t.Fatalf("defaults = %+v", c.cfg)
	}
}
