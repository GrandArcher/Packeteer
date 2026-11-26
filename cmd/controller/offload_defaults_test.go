package main

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/GrandArcher/Packeteer/internal/config"
	"github.com/GrandArcher/Packeteer/internal/offload/mikrotik"
	"github.com/GrandArcher/Packeteer/internal/plugins/routercheck/routeros"
	"github.com/GrandArcher/Packeteer/pkg/plugin"
)

// fakeRouterOS is a RouterOS REST API with a switch chip and two static
// defaults, with documentation addresses. It records every request.
type fakeRouterOS struct {
	mu   sync.Mutex
	seen []string
}

func (f *fakeRouterOS) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	body, _ := io.ReadAll(r.Body)
	f.mu.Lock()
	f.seen = append(f.seen, r.Method+" "+r.URL.RequestURI()+" "+string(body))
	f.mu.Unlock()
	sw := "/interface/ethernet/switch"
	bodies := map[string]string{
		"GET /system/resource":                           `{"version":"7.24.2 (stable)"}`,
		"GET " + sw:                                      `[{"name":"switch1","l3-hw-offloading":"true"}]`,
		"GET " + sw + "/l3hw-settings":                   `{"ipv6-hw":"true","autorestart":"true"}`,
		"POST " + sw + "/l3hw-settings/monitor":          `[{"state":"ok","ipv4-routes-total":"90000","ipv4-routes-hw":"90000","nexthop-cap":"8192","nexthop-usage":"93"}]`,
		"POST " + sw + "/l3hw-settings/advanced/monitor": `[{"error-code":"0","lpm-cap":"200000","lpm-usage":"60000"}]`,
		"GET " + sw + "/l3hw-settings/advanced":          `{"route-index-delay-min":"50ms","route-index-delay-max":"1s","route-queue-limit-high":"100000","route-queue-limit-low":"50000","shwp-reset-counter":"6"}`,
		"GET " + sw + "/port":                            `[{"name":"sfp-sfpplus1","l3-hw-offloading":"true"}]`,
		"GET /interface/bridge":                          `[{"name":"bridge1","disabled":"false","l3-hw-offloading":"true"}]`,
		"GET /interface/vlan":                            `[]`,
		"GET /interface/bonding":                         `[]`,
		"GET /interface/vrrp":                            `[]`,
		"GET /routing/rule":                              `[]`,
		"GET /ip/vrf":                                    `[{"name":"main"}]`,
		"GET /ip/firewall/mangle":                        `[]`,
		"GET /ip/firewall/filter":                        `[]`,
		"GET /ip/firewall/nat":                           `[]`,
		"GET /ip/route?dst-address=0.0.0.0/0": `[
			{"dst-address":"0.0.0.0/0","gateway":"192.0.2.1","distance":"1","belongs-to":"Static route","active":"true","suppress-hw-offload":"true"},
			{"dst-address":"0.0.0.0/0","gateway":"192.0.2.2","distance":"2","belongs-to":"Static route","inactive":"true","suppress-hw-offload":"true"}]`,
		"GET /ipv6/route?dst-address=::/0": `[]`,
	}
	out, ok := bodies[r.Method+" "+strings.TrimPrefix(r.URL.RequestURI(), "/rest")]
	if !ok {
		w.WriteHeader(http.StatusNotFound)
		return
	}
	_, _ = io.WriteString(w, out)
}

// The report offers a snippet that sets distances on the defaults, and the
// only requests the router sees are GETs and monitor reads with once: the
// snippet is text for review, never sent.
func TestOffloadDefaultsNeverWriteToTheRouter(t *testing.T) {
	lab := startOffloadLab(t, config.ModeObserve, labL3HW())
	router := &fakeRouterOS{}
	srv := httptest.NewServer(router)
	t.Cleanup(srv.Close)
	rd, err := routeros.Open(mikrotik.RESTConfig(config.OffloadRouter{URL: srv.URL, UsernameEnv: "PK_L3HW_USER", PasswordEnv: "PK_L3HW_PASSWORD"}),
		plugin.Env{Getenv: func(k string) string {
			return map[string]string{"PK_L3HW_USER": "pk-reader", "PK_L3HW_PASSWORD": "lab-only"}[k]
		}})
	if err != nil {
		t.Fatal(err)
	}
	oa, r := lab.oa, lab.router
	r.read = rd.ReadL3HW
	oa.quality, oa.nextHops = lab.src.qualitySamples, lab.src.nextHops
	r.refresh(t.Context(), time.Minute, oa.now, oa.log)
	oa.at = time.Time{}

	d := oa.Report().Routers[0].Defaults
	if d == nil || d.Note != "" {
		t.Fatalf("defaults = %+v", d)
	}
	// transit-b measured 20 ms against transit-a's 80 ms: it ranks first.
	if len(d.Providers) != 2 || d.Providers[0].Provider != "transit-b" || !strings.Contains(d.Snippet, "gateway=192.0.2.2] distance=1 suppress-hw-offload=yes") ||
		!strings.Contains(d.Snippet, "gateway=192.0.2.1] distance=2 suppress-hw-offload=yes") {
		t.Fatalf("providers %+v snippet:\n%s", d.Providers, d.Snippet)
	}

	router.mu.Lock()
	defer router.mu.Unlock()
	if len(router.seen) == 0 {
		t.Fatal("the router was never read")
	}
	for _, req := range router.seen {
		method, rest, _ := strings.Cut(req, " ")
		switch {
		case method == http.MethodGet:
		case method == http.MethodPost && strings.Contains(rest, "/monitor ") && strings.HasSuffix(rest, `{"once":""}`):
		default:
			t.Errorf("request that is not a read: %s", req)
		}
	}
}
