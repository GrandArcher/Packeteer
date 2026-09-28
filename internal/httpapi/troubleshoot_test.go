package httpapi

import (
	"context"
	"encoding/json"
	"net/http"
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/GrandArcher/Packeteer/internal/probe"
	"github.com/GrandArcher/Packeteer/internal/rib"
	"github.com/GrandArcher/Packeteer/internal/troubleshoot"
	"github.com/GrandArcher/Packeteer/pkg/plugin"
)

type tsRIB struct{ r rib.Route }

func (f tsRIB) Ready() bool { return true }
func (f tsRIB) Exact(p netip.Prefix) (rib.Route, bool) {
	return f.r, p.Masked() == f.r.Prefix
}
func (f tsRIB) Covering(p netip.Prefix) (rib.Route, bool) {
	return f.r, f.r.Prefix.Bits() <= p.Bits() && f.r.Prefix.Contains(p.Addr())
}
func (f tsRIB) Routes() []rib.Route { return []rib.Route{f.r} }

type tsProber struct {
	plugin.Base
	n int
}

func (p *tsProber) Probe(_ context.Context, r plugin.ProbeRequest) (plugin.ProbeResult, error) {
	p.n++
	return plugin.ProbeResult{Sent: r.Count, RTTs: []time.Duration{5 * time.Millisecond, 5 * time.Millisecond}}, nil
}

type tsWhois struct{ plugin.Base }

func (tsWhois) Lookup(_ context.Context, q string) (plugin.WhoisResult, error) {
	return plugin.WhoisResult{Query: q, Kind: "asn", Name: "DOC-ASN"}, nil
}

type tsLimit struct{ n int }

func (l *tsLimit) Allow() bool { l.n--; return l.n >= 0 }

func toolServer(t *testing.T, enabled bool, lim troubleshoot.Limiter) (http.Handler, *tsProber) {
	t.Helper()
	pr := &tsProber{}
	tools := troubleshoot.New(troubleshoot.Options{
		Enabled:   enabled,
		Providers: []probe.Provider{{Name: "transit-a", Source: netip.MustParseAddr("192.0.2.10")}},
		Probers:   []probe.NamedProber{{Name: "fake", Prober: pr}},
		Packets:   2,
		Hop: func(_ context.Context, _, dst netip.Addr, ttl, _ int, _ time.Duration) (netip.Addr, bool, error) {
			if ttl == 2 {
				return dst, true, nil
			}
			return netip.MustParseAddr("192.0.2.1"), false, nil
		},
		Whois:   tsWhois{},
		Limiter: lim,
	})
	tools.SetRIB(tsRIB{r: rib.Route{Prefix: netip.MustParsePrefix("198.51.100.0/24"), NextHop: netip.MustParseAddr("192.0.2.1"), Provider: "transit-a", ASPath: []uint32{64496}}})
	s, err := New(Options{Tools: tools, Snapshot: func() Snapshot { return Assemble(sampleInput()) }})
	if err != nil {
		t.Fatal(err)
	}
	return s.Handler(), pr
}

func TestToolStatusAndLookingGlass(t *testing.T) {
	h, _ := toolServer(t, false, nil)
	rec := mdo(h, "GET", "/api/troubleshoot", "", "", false)
	if rec.Code != 200 || !strings.Contains(rec.Body.String(), `"looking_glass":true`) || !strings.Contains(rec.Body.String(), `"probe":false`) {
		t.Fatalf("status: %d %s", rec.Code, rec.Body)
	}
	rec = mdo(h, "GET", "/api/troubleshoot/lookingglass?prefix=198.51.100.9", "", "", false)
	var g troubleshoot.Glass
	if err := json.Unmarshal(rec.Body.Bytes(), &g); err != nil || rec.Code != 200 || g.Covering == nil || g.Covering.Provider != "transit-a" || g.Exact != nil {
		t.Fatalf("glass: %d %s", rec.Code, rec.Body)
	}
	rec = mdo(h, "GET", "/api/troubleshoot/lookingglass?prefix=198.51.100.0/24", "", "", false)
	if !strings.Contains(rec.Body.String(), `"exact"`) {
		t.Fatalf("exact: %s", rec.Body)
	}
	if rec := mdo(h, "GET", "/api/troubleshoot/lookingglass?prefix=nope", "", "", false); rec.Code != 400 {
		t.Fatalf("bad prefix: %d", rec.Code)
	}
	// No tools at all: the looking glass says so.
	s, _ := New(Options{})
	if rec := mdo(s.Handler(), "GET", "/api/troubleshoot/lookingglass?prefix=198.51.100.0/24", "", "", false); rec.Code != 404 {
		t.Fatalf("no tools: %d", rec.Code)
	}
	if rec := mdo(s.Handler(), "POST", "/api/troubleshoot/probe", "application/json", `{"target":"198.51.100.1"}`, false); rec.Code != 403 {
		t.Fatalf("no tools probe: %d", rec.Code)
	}
}

func TestToolsDisabled(t *testing.T) {
	h, pr := toolServer(t, false, nil)
	for _, path := range []string{"/api/troubleshoot/probe", "/api/troubleshoot/traceroute"} {
		if rec := mdo(h, "POST", path, "application/json", `{"target":"198.51.100.1"}`, false); rec.Code != 403 {
			t.Fatalf("%s: %d %s", path, rec.Code, rec.Body)
		}
	}
	if rec := mdo(h, "POST", "/api/troubleshoot/whois", "application/json", `{"query":"AS64496"}`, false); rec.Code != 403 {
		t.Fatalf("whois: %d", rec.Code)
	}
	if pr.n != 0 {
		t.Fatal("probe sent while disabled")
	}
}

func TestToolProbeTraceWhois(t *testing.T) {
	h, pr := toolServer(t, true, nil)
	rec := mdo(h, "POST", "/api/troubleshoot/probe", "application/json", `{"target":"198.51.100.1"}`, false)
	var ans troubleshoot.ProbeAnswer
	if err := json.Unmarshal(rec.Body.Bytes(), &ans); err != nil || rec.Code != 200 || len(ans.Results) != 1 || ans.Results[0].Stats.LossPct != 0 || ans.Route == nil || pr.n != 1 {
		t.Fatalf("probe: %d %s", rec.Code, rec.Body)
	}
	rec = mdo(h, "POST", "/api/troubleshoot/traceroute", "application/json", `{"target":"203.0.113.5","provider":"transit-a"}`, false)
	var tr troubleshoot.TraceAnswer
	if err := json.Unmarshal(rec.Body.Bytes(), &tr); err != nil || rec.Code != 200 || len(tr.Traces) != 1 || !tr.Traces[0].Reached || len(tr.Traces[0].Hops) != 2 {
		t.Fatalf("trace: %d %s", rec.Code, rec.Body)
	}
	rec = mdo(h, "POST", "/api/troubleshoot/whois", "application/json", `{"query":"AS64496"}`, false)
	if rec.Code != 200 || !strings.Contains(rec.Body.String(), "DOC-ASN") {
		t.Fatalf("whois: %d %s", rec.Code, rec.Body)
	}
}

func TestToolRequestValidation(t *testing.T) {
	h, pr := toolServer(t, true, nil)
	cases := []struct {
		path, ctype, body string
		code              int
	}{
		{"/api/troubleshoot/probe", "text/plain", `{"target":"198.51.100.1"}`, 415},
		{"/api/troubleshoot/probe", "application/x-www-form-urlencoded", `target=198.51.100.1`, 415},
		{"/api/troubleshoot/probe", "application/json", `{"target":"127.0.0.1"}`, 400},
		{"/api/troubleshoot/probe", "application/json", `{"target":"example.com"}`, 400},
		{"/api/troubleshoot/probe", "application/json", `{"target":"198.51.100.1","extra":1}`, 400},
		{"/api/troubleshoot/traceroute", "application/json", `{"target":"198.51.100.1","provider":"nope"}`, 400},
		{"/api/troubleshoot/whois", "application/json", `{"query":"https://rdap.example/"}`, 400},
	}
	for _, c := range cases {
		if rec := mdo(h, "POST", c.path, c.ctype, c.body, false); rec.Code != c.code {
			t.Errorf("%s %s: got %d want %d (%s)", c.path, c.body, rec.Code, c.code, rec.Body)
		}
	}
	if rec := mdo(h, "GET", "/api/troubleshoot/probe?target=198.51.100.1", "", "", false); rec.Code == 200 {
		t.Fatal("GET triggered a probe")
	}
	if pr.n != 0 {
		t.Fatalf("invalid requests sent %d probes", pr.n)
	}
}

func TestToolRateLimit(t *testing.T) {
	h, _ := toolServer(t, true, &tsLimit{n: 1})
	if rec := mdo(h, "POST", "/api/troubleshoot/probe", "application/json", `{"target":"198.51.100.1"}`, false); rec.Code != 200 {
		t.Fatalf("first: %d", rec.Code)
	}
	rec := mdo(h, "POST", "/api/troubleshoot/probe", "application/json", `{"target":"198.51.100.1"}`, false)
	if rec.Code != 429 || rec.Header().Get("Retry-After") == "" {
		t.Fatalf("second: %d", rec.Code)
	}
}

func TestToolsNeedAuthWhenSet(t *testing.T) {
	tools := troubleshoot.New(troubleshoot.Options{Enabled: true})
	s, err := New(Options{User: "ops", Password: "secret", Tools: tools})
	if err != nil {
		t.Fatal(err)
	}
	if rec := mdo(s.Handler(), "POST", "/api/troubleshoot/whois", "application/json", `{"query":"AS64496"}`, false); rec.Code != 401 {
		t.Fatalf("unauthenticated: %d", rec.Code)
	}
	if rec := mdo(s.Handler(), "POST", "/api/troubleshoot/whois", "application/json", `{"query":"AS64496"}`, true); rec.Code != 404 {
		t.Fatalf("authenticated, no whois plugin: %d %s", rec.Code, rec.Body)
	}
}
