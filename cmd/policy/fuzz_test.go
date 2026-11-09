package main

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"github.com/GrandArcher/Packeteer/internal/extpolicy"
)

// Every line a daemon can be given, per output. Comment lines are inert.
var (
	exaLine = regexp.MustCompile(`^(withdraw route [0-9a-f.:]+/\d+|announce route [0-9a-f.:]+/\d+ next-hop [0-9a-f.:]+ local-preference \d+` +
		`( as-path \[\d+( \d+)*\])?( community \[(\d+:\d+|no-export)( (\d+:\d+|no-export))*\])?( large-community \[\d+:\d+:\d+( \d+:\d+:\d+)*\])?)$`)
	birdLine = regexp.MustCompile(`^(|#.*|template bgp packeteer_feed_session \{|\tgraceful restart off;|\tlong lived graceful restart off;|\}|` +
		`protocol static packeteer_feed[46] \{|\tipv[46];|\troute [0-9a-f.:]+/\d+ via [0-9a-f.:]+ \{|\t\tbgp_local_pref = \d+;|` +
		`\t\tbgp_community\.add\(\(\d+, \d+\)\);|\t\tbgp_large_community\.add\(\(\d+, \d+, \d+\)\);|\t\};)$`)
	openbgpdLine = regexp.MustCompile(`^(|#.*|network [0-9a-f.:]+/\d+ set \{ nexthop [0-9a-f.:]+ localpref \d+( community (\d+:\d+|NO_EXPORT)| large-community \d+:\d+:\d+)* \})$`)
)

// Whatever the feed sends, the ExaBGP API lines and the rendered BIRD and
// OpenBGPD files hold only the lines above: no injected newline, command,
// or config directive gets through, and only a route that passed the check
// is written.
func FuzzDaemonOutput(f *testing.F) {
	f.Add("198.51.100.0/24", "192.0.2.22", "64512:1", "64512:1:2", uint32(250), uint32(64497), "rtt 80ms -> 10ms")
	f.Add("2001:db8:100::/48", "2001:db8::22", "64512:1", "65535:65281", uint32(250), uint32(64500), "")
	f.Add("198.51.100.0/24", "192.0.2.22", "64512:1\nannounce route 192.0.2.0/24 next-hop self", "1:2:3", uint32(1), uint32(1), "")
	f.Add("198.51.100.0/24", "192.0.2.22", "64512:1)); }; protocol static evil { ipv4; route 0.0.0.0/0 blackhole; } x ((1", "1:2", uint32(1), uint32(1), "")
	f.Add("198.51.100.0/24", "192.0.2.22", "64512:1 }\nnetwork 0.0.0.0/0", "1:2", uint32(1), uint32(1), "")
	f.Add("2001:db8:100::/48", "fe80::1%eth0\nprotocol", "64512:1", "1:2", uint32(1), uint32(1), "")
	f.Add("198.51.100.7/24", "192.0.2.22", "64512:1", "1:2", uint32(1), uint32(1), "}\nprotocol static evil {")
	f.Fuzz(func(t *testing.T, prefix, nextHop, comm, comm2 string, localPref, asn uint32, text string) {
		var r extpolicy.Route
		// As the JSON decoder builds them; a field it would refuse stays zero.
		_ = r.Prefix.UnmarshalText([]byte(prefix))
		_ = r.NextHop.UnmarshalText([]byte(nextHop))
		r.LocalPref, r.ASPath = localPref, []uint32{asn}
		r.Communities = []string{"64512:666", comm, comm2, extpolicy.NoExport}
		r.Provider, r.Cause, r.Reason = text, text, text
		var kept []extpolicy.Route
		if v, err := labCheck.route(r); err == nil {
			kept = append(kept, v)
		}

		var exa bytes.Buffer
		e := &exabgp{w: &exa}
		if err := e.apply(context.Background(), kept); err != nil {
			t.Fatal(err)
		}
		if err := e.apply(context.Background(), nil); err != nil {
			t.Fatal(err)
		}
		checkLines(t, "ExaBGP", exa.String(), exaLine, "announce ", len(kept))

		for _, c := range []struct {
			tmpl, word string
			line       *regexp.Regexp
		}{{"bird.conf.tmpl", "\troute ", birdLine}, {"openbgpd.conf.tmpl", "network ", openbgpdLine}} {
			rd, err := newRenderer(filepath.Join("..", "..", "examples", "external-policy", c.tmpl), "", "")
			if err != nil {
				t.Fatal(err)
			}
			var out bytes.Buffer
			if err := rd.tmpl.Execute(&out, struct{ Routes []extpolicy.Route }{kept}); err != nil {
				t.Fatal(err)
			}
			checkLines(t, c.tmpl, out.String(), c.line, c.word, len(kept))
		}
	})
}

func checkLines(t *testing.T, name, out string, line *regexp.Regexp, word string, routes int) {
	t.Helper()
	n := 0
	for l := range strings.Lines(out) {
		l = strings.TrimSuffix(l, "\n")
		if !line.MatchString(l) {
			t.Fatalf("%s: line %q is not allowed in\n%s", name, l, out)
		}
		if strings.HasPrefix(l, word) {
			n++
		}
	}
	if n != routes {
		t.Fatalf("%s: %d routes written, %d passed the check:\n%s", name, n, routes, out)
	}
}

// Graceful restart is off in every example: the routes must go with the
// daemon's session.
func TestExamplesGracefulRestartOff(t *testing.T) {
	for file, want := range map[string]string{
		"bird.conf.tmpl":     "template bgp packeteer_feed_session {\n\tgraceful restart off;\n\tlong lived graceful restart off;\n}",
		"openbgpd.conf.tmpl": `"announce restart no"`,
		"exabgp.conf":        "capability {\n\t\tgraceful-restart disable;\n\t}",
	} {
		b, err := os.ReadFile(filepath.Join("..", "..", "examples", "external-policy", file))
		if err != nil {
			t.Fatal(err)
		}
		if !strings.Contains(string(b), want) {
			t.Errorf("%s lacks %q", file, want)
		}
	}
	for _, routes := range [][]extpolicy.Route{nil, {route4}} {
		if got := render(t, "bird.conf.tmpl", routes); !strings.Contains(got, "template bgp packeteer_feed_session {\n\tgraceful restart off;\n\tlong lived graceful restart off;\n}") {
			t.Errorf("rendered BIRD file without graceful restart off:\n%s", got)
		}
	}
}
