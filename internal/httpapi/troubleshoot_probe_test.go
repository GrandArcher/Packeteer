package httpapi

import (
	"encoding/json"
	"errors"
	"net/http"
	"net/netip"
	"strings"
	"testing"

	"github.com/GrandArcher/Packeteer/internal/auth"
	"github.com/GrandArcher/Packeteer/internal/probe"
	"github.com/GrandArcher/Packeteer/internal/rib"
	"github.com/GrandArcher/Packeteer/internal/troubleshoot"
	"github.com/GrandArcher/Packeteer/pkg/plugin"
)

func TestToolProbeHostname(t *testing.T) {
	h, pr, _ := toolServerQ(t, true, nil)
	rec := mdo(h, "POST", "/api/troubleshoot/probe", "application/json", `{"target":"Host.Example.Net"}`, false)
	var ans troubleshoot.ProbeAnswer
	if err := json.Unmarshal(rec.Body.Bytes(), &ans); err != nil || rec.Code != 200 {
		t.Fatalf("probe: %d %s", rec.Code, rec.Body)
	}
	if ans.Host != "host.example.net" || ans.Target.String() != "198.51.100.9" || len(ans.Addresses) != 1 || ans.Addresses[0] != ans.Target {
		t.Fatalf("which address was used: %+v", ans)
	}
	if ans.Current != "transit-a" || ans.Best != "transit-a" || ans.Route == nil || ans.Route.Prefix.String() != "198.51.100.0/24" || pr.n != 1 {
		t.Fatalf("current/best/covering: %+v probes %d", ans, pr.n)
	}
}

func TestToolProbeAndOptimizeRejectInvalidInput(t *testing.T) {
	h, pr, q := toolServerQ(t, true, nil)
	for _, target := range []string{"", "bad host!", "127.1", "127.0.0.1", "::1", "http://host.example.net", "gone.example.net", "-x.example", "198.51.100.0/24"} {
		body, _ := json.Marshal(map[string]string{"target": target})
		for _, path := range []string{"/api/troubleshoot/probe", "/api/troubleshoot/optimize"} {
			if rec := mdo(h, "POST", path, "application/json", string(body), false); rec.Code != 400 {
				t.Errorf("%s %q: got %d (%s)", path, target, rec.Code, rec.Body)
			}
		}
	}
	for _, c := range []struct{ ctype, body string }{
		{"text/plain", `{"target":"198.51.100.9"}`},
		{"application/x-www-form-urlencoded", `target=198.51.100.9`},
	} {
		if rec := mdo(h, "POST", "/api/troubleshoot/optimize", c.ctype, c.body, false); rec.Code != 415 {
			t.Errorf("optimize %s: %d", c.ctype, rec.Code)
		}
	}
	if rec := mdo(h, "POST", "/api/troubleshoot/optimize", "application/json", `{"target":"198.51.100.9","extra":1}`, false); rec.Code != 400 {
		t.Errorf("unknown field: %d", rec.Code)
	}
	if rec := mdo(h, "GET", "/api/troubleshoot/optimize?target=198.51.100.9", "", "", false); rec.Code == 200 {
		t.Error("GET queued a prefix")
	}
	if pr.n != 0 || len(q.got) != 0 {
		t.Fatalf("invalid input sent %d probes and queued %v", pr.n, q.got)
	}
}

func TestToolOptimize(t *testing.T) {
	h, _, q := toolServerQ(t, true, nil)
	rec := mdo(h, "POST", "/api/troubleshoot/optimize", "application/json", `{"target":"host.example.net"}`, false)
	var ans troubleshoot.OptimizeAnswer
	if err := json.Unmarshal(rec.Body.Bytes(), &ans); err != nil || rec.Code != 200 {
		t.Fatalf("optimize: %d %s", rec.Code, rec.Body)
	}
	if ans.Prefix.String() != "198.51.100.0/24" || ans.Target.String() != "198.51.100.9" || ans.Host != "host.example.net" || ans.Expires.IsZero() {
		t.Fatalf("answer %+v", ans)
	}
	if len(q.got) != 1 || q.got[0].String() != "198.51.100.0/24" || q.ttl != troubleshoot.OptimizeTTL {
		t.Fatalf("queued %v for %v", q.got, q.ttl)
	}

	// No learned prefix covers the address: nothing is queued.
	if rec := mdo(h, "POST", "/api/troubleshoot/optimize", "application/json", `{"target":"203.0.113.9"}`, false); rec.Code != 400 || !strings.Contains(rec.Body.String(), "no learned prefix") {
		t.Fatalf("uncovered: %d %s", rec.Code, rec.Body)
	}
	if len(q.got) != 1 {
		t.Fatalf("queued %v", q.got)
	}

	q.err = probe.ErrManualFull
	if rec := mdo(h, "POST", "/api/troubleshoot/optimize", "application/json", `{"target":"198.51.100.9"}`, false); rec.Code != http.StatusConflict {
		t.Fatalf("full queue: %d %s", rec.Code, rec.Body)
	}
	q.err = errors.New("other")
	if rec := mdo(h, "POST", "/api/troubleshoot/optimize", "application/json", `{"target":"198.51.100.9"}`, false); rec.Code != 400 {
		t.Fatalf("queue error: %d", rec.Code)
	}
}

func TestToolOptimizeDisabledAndRateLimited(t *testing.T) {
	h, _, q := toolServerQ(t, false, nil)
	if rec := mdo(h, "POST", "/api/troubleshoot/optimize", "application/json", `{"target":"198.51.100.9"}`, false); rec.Code != 403 {
		t.Fatalf("disabled: %d %s", rec.Code, rec.Body)
	}
	h, _, q2 := toolServerQ(t, true, &tsLimit{n: 1})
	if rec := mdo(h, "POST", "/api/troubleshoot/optimize", "application/json", `{"target":"198.51.100.9"}`, false); rec.Code != 200 {
		t.Fatalf("first: %d", rec.Code)
	}
	rec := mdo(h, "POST", "/api/troubleshoot/optimize", "application/json", `{"target":"198.51.100.9"}`, false)
	if rec.Code != 429 || rec.Header().Get("Retry-After") == "" {
		t.Fatalf("second: %d", rec.Code)
	}
	// Probe and optimize share one limit.
	h, _, q3 := toolServerQ(t, true, &tsLimit{n: 1})
	if rec := mdo(h, "POST", "/api/troubleshoot/probe", "application/json", `{"target":"198.51.100.9"}`, false); rec.Code != 200 {
		t.Fatalf("probe: %d", rec.Code)
	}
	if rec := mdo(h, "POST", "/api/troubleshoot/optimize", "application/json", `{"target":"198.51.100.9"}`, false); rec.Code != 429 {
		t.Fatalf("optimize after probe: %d", rec.Code)
	}
	if len(q.got) != 0 || len(q2.got) != 1 || len(q3.got) != 0 {
		t.Fatalf("queued %v %v %v", q.got, q2.got, q3.got)
	}
}

func TestToolOptimizeRolesAndAudit(t *testing.T) {
	e := newRBAC(t, nil)
	pr, queue := &tsProber{}, &tsQueue{}
	tools := troubleshoot.New(troubleshoot.Options{
		Enabled: true, Resolver: tsResolver{}, Packets: 1,
		Providers: []probe.Provider{{Name: "transit-a", Source: netip.MustParseAddr("192.0.2.10")}},
		Probers:   []probe.NamedProber{{Name: "fake", Prober: pr}},
	})
	tools.SetRIB(tsRIB{r: rib.Route{Prefix: netip.MustParsePrefix("198.51.100.0/24"), NextHop: netip.MustParseAddr("192.0.2.1"), Provider: "transit-a", ASPath: []uint32{64496}}})
	tools.SetQueue(queue)
	e.srv.tools = tools

	body := `{"target":"198.51.100.9"}`
	for _, path := range []string{"/api/troubleshoot/probe", "/api/troubleshoot/optimize"} {
		if rec := e.do("POST", path, "", body); rec.Code != http.StatusUnauthorized {
			t.Errorf("%s anonymous: %d", path, rec.Code)
		}
		if rec := e.do("POST", path, e.tokens[plugin.RoleViewer], body); !needsRole(rec) {
			t.Errorf("%s viewer: %d %s", path, rec.Code, rec.Body)
		}
	}
	if len(queue.got) != 0 || pr.n != 0 {
		t.Fatalf("a viewer queued %v and sent %d probes", queue.got, pr.n)
	}
	for _, r := range []plugin.Role{plugin.RoleOperator, plugin.RoleAdmin} {
		if rec := e.do("POST", "/api/troubleshoot/optimize", e.tokens[r], body); rec.Code != 200 {
			t.Errorf("%s: %d %s", r, rec.Code, rec.Body)
		}
	}
	if len(queue.got) != 2 {
		t.Fatalf("queued %v", queue.got)
	}
	var found bool
	for _, r := range e.store.Records() {
		if r.Action == "POST /api/troubleshoot/optimize" && r.Actor == "operator-user" && r.Result == auth.ResultOK && r.Target == "198.51.100.0/24" {
			found = true
		}
		if r.Action == "POST /api/troubleshoot/optimize" && r.Actor == "viewer-user" && r.Result != auth.ResultDenied {
			t.Errorf("viewer record %+v", r)
		}
	}
	if !found {
		t.Fatalf("no audit record for the operator's queue request: %+v", e.store.Records())
	}
}
