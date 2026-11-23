package routeros

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/GrandArcher/Packeteer/internal/plugins/routercheck/readonly"
	"github.com/GrandArcher/Packeteer/pkg/plugin"
)

const (
	pathSwitch   = "/interface/ethernet/switch"
	pathSettings = pathSwitch + "/l3hw-settings"
	pathMonitor  = pathSettings + "/monitor"
	pathAdvMon   = pathSettings + "/advanced/monitor"
	pathAdvSet   = pathSettings + "/advanced"
	pathRoute4   = "/ip/route?dst-address=0.0.0.0/0"
	pathRoute6   = "/ipv6/route?dst-address=::/0"
)

// l3hwRouter serves JSON bodies by "METHOD path?query" and records every
// request as "METHOD uri body".
type l3hwRouter struct {
	mu     sync.Mutex
	bodies map[string]string
	status map[string]int
	seen   []string
	delay  time.Duration
}

func (f *l3hwRouter) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	b, _ := io.ReadAll(r.Body)
	f.mu.Lock()
	f.seen = append(f.seen, r.Method+" "+r.URL.RequestURI()+" "+string(b))
	f.mu.Unlock()
	if f.delay > 0 {
		time.Sleep(f.delay)
	}
	if u, p, ok := r.BasicAuth(); !ok || u != labUser || p != labPass {
		w.WriteHeader(http.StatusUnauthorized)
		return
	}
	key := r.Method + " " + strings.TrimPrefix(r.URL.RequestURI(), "/rest")
	if code := f.status[key]; code != 0 {
		w.WriteHeader(code)
		_, _ = io.WriteString(w, `{"error":`+http.StatusText(code)+`}`)
		return
	}
	body, ok := f.bodies[key]
	if !ok {
		w.WriteHeader(http.StatusNotFound)
		return
	}
	_, _ = io.WriteString(w, body)
}

func (f *l3hwRouter) requests() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]string(nil), f.seen...)
}

func (f *l3hwRouter) reader(t *testing.T) *Reader {
	t.Helper()
	srv := httptest.NewServer(f)
	t.Cleanup(srv.Close)
	rc, err := New(cfg(t, "{url: "+srv.URL+", username_env: PACKETEER_ROUTER_READ_USER, password_env: PACKETEER_ROUTER_READ_PASSWORD}"), plugin.Env{Getenv: labEnv})
	if err != nil {
		t.Fatal(err)
	}
	return rc.(*Reader)
}

// chip is a router with a switch chip: the REST answers of a CCR2216-like
// router with documentation addresses. Tests replace single entries.
func chip(version, monitor, advanced string) *l3hwRouter {
	return &l3hwRouter{status: map[string]int{}, bodies: map[string]string{
		"GET /system/resource":        `{"version":"` + version + ` (stable)","board-name":"CCR2216-1G-12XS-2XQ"}`,
		"GET " + pathSwitch:           `[{".id":"*0","name":"switch1","l3-hw-offloading":"true"}]`,
		"GET " + pathSettings:         `{"autorestart":"true","fasttrack-hw":"false","ipv6-hw":"true","hw-supports-fasttrack":"true"}`,
		"GET " + pathAdvSet:           `{"shwp-reset-counter":"6","route-index-delay-min":"50ms","route-index-delay-max":"1s","route-queue-limit-high":"100000","route-queue-limit-low":"50000"}`,
		"POST " + pathMonitor:         monitor,
		"POST " + pathAdvMon:          advanced,
		"GET " + pathSwitch + "/port": `[{"name":"sfp-sfpplus1","l3-hw-offloading":"true"},{"name":"qsfp28-1-1","l3-hw-offloading":"false"}]`,
		"GET /interface/bridge":       `[{"name":"bridge1","disabled":"false","l3-hw-offloading":"true"}]`,
		"GET /interface/vlan":         `[{"name":"vlan100","disabled":"false","l3-hw-offloading":"true","interface":"bridge1"},{"name":"vlan200","disabled":"true"}]`,
		"GET /interface/bonding":      `[{"name":"bond1","disabled":"false","mode":"802.3ad"}]`,
		"GET /interface/vrrp":         `[{"name":"vrrp1"}]`,
		"GET /routing/rule":           `[{"action":"lookup","table":"isp-b","disabled":"false"},{"action":"lookup","table":"old","disabled":"true"}]`,
		"GET /ip/vrf":                 `[{"name":"mgmt"}]`,
		"GET /ip/firewall/mangle":     `[{"chain":"prerouting","action":"mark-routing","disabled":"false"},{"chain":"prerouting","action":"mark-routing","disabled":"true"},{"chain":"forward","action":"mark-connection","disabled":"false"}]`,
		"GET /ip/firewall/filter":     `[{"chain":"forward","action":"accept","disabled":"false"},{"chain":"input","action":"accept","disabled":"false"}]`,
		"GET /ip/firewall/nat":        `[{"chain":"srcnat","action":"masquerade","disabled":"false"},{"chain":"srcnat","action":"accept","disabled":"true"}]`,
		"GET " + pathRoute4: `[
			{"dst-address":"0.0.0.0/0","gateway":"192.0.2.1","distance":"20","belongs-to":"BGP","bgp-local-pref":"200","active":"true","inactive":"false","hw-offloaded":"true","suppress-hw-offload":"false"},
			{"dst-address":"0.0.0.0/0","gateway":"192.0.2.2","distance":"250","belongs-to":"Static route","active":"false","inactive":"true","hw-offloaded":"false","suppress-hw-offload":"true"},
			{"dst-address":"198.51.100.0/24","gateway":"192.0.2.1","distance":"20","belongs-to":"BGP"}]`,
		"GET " + pathRoute6: `[{"dst-address":"::/0","gateway":"2001:db8::1","distance":"20","belongs-to":"BGP","bgp-local-pref":"100","active":"true","hw-offloaded":"false"}]`,
	}}
}

// Monitor outputs: the two CCR2216 states from MikroTik's documentation and
// staff, and the exhausted next-hop table from a public forum report.
const (
	fullHW = `[{"state":"ok","ipv4-routes-total":"942338","ipv4-routes-hw":"942326","ipv4-routes-cpu":"12","ipv4-shortest-hw-prefix":"0","ipv4-hosts":"87","ipv6-routes-total":"15","ipv6-routes-hw":"11","ipv6-routes-cpu":"4","ipv6-shortest-hw-prefix":"0","nexthop-cap":"8192","nexthop-usage":"93"}]`
	shwp30 = `[{"state":"ok","ipv4-routes-total":"942338","ipv4-routes-hw":"37729","ipv4-routes-cpu":"904609","ipv4-shortest-hw-prefix":"30","ipv6-routes-total":"15","ipv6-routes-hw":"0","ipv6-routes-cpu":"15","nexthop-cap":"8192","nexthop-usage":"93"}]`
	nhFull = `[{"state":"ok","ipv4-routes-total":"174000","ipv4-routes-hw":"0","ipv4-routes-cpu":"174000","ipv4-shortest-hw-prefix":"24","ipv6-routes-total":"0","nexthop-cap":"8192","nexthop-usage":"8192"}]`
	advLPM = `[{"state":"ok","error-code":"0","lpm-cap":"27200","lpm-usage":"27200","lpm-bank-cap":"1360"}]`
)

func TestFullHardwareTable(t *testing.T) {
	f := chip("7.24.2", fullHW, advLPM)
	got, err := f.reader(t).ReadL3HW(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if !got.Applicable || got.Version != "7.24.2" {
		t.Fatalf("applicable/version = %v %q", got.Applicable, got.Version)
	}
	m := got.Monitor
	if m.IPv4RoutesTotal != 942338 || m.IPv4RoutesHW != 942326 || m.IPv4RoutesCPU != 12 || m.IPv4ShortestHWPrefix != 0 || m.State != "ok" {
		t.Errorf("monitor = %+v", m)
	}
	if !m.Partial() {
		t.Error("12 routes on the CPU is a partial offload")
	}
	if m.NexthopExhausted() {
		t.Error("93 of 8192 next hops is not exhausted")
	}
	if got.Advanced == nil || !got.Advanced.HasLPM || got.Advanced.LPMCap != 27200 || got.Advanced.ErrorCode != "0" {
		t.Errorf("advanced = %+v", got.Advanced)
	}
	if want := (Settings{IPv6HW: true, Autorestart: true}); got.Settings != want {
		t.Errorf("settings = %+v", got.Settings)
	}
	if got.Tuning == nil || got.Tuning.SHWPResetCounter != 6 || got.Tuning.RouteIndexDelayMin != "50ms" || got.Tuning.RouteIndexDelayMax != "1s" || got.Tuning.RouteQueueLimitHigh != 100000 || got.Tuning.RouteQueueLimitLow != 50000 {
		t.Errorf("tuning = %+v", got.Tuning)
	}
	wantPorts := []Port{{"sfp-sfpplus1", true}, {"qsfp28-1-1", false}}
	if !slices.Equal(got.Ports, wantPorts) {
		t.Errorf("ports = %+v", got.Ports)
	}
	if !slices.Equal(got.Bridges, []Iface{{Name: "bridge1", L3HW: true}}) ||
		!slices.Equal(got.VLANs, []Iface{{Name: "vlan100", L3HW: true, Parent: "bridge1"}, {Name: "vlan200", Disabled: true}}) ||
		!slices.Equal(got.Bonds, []Iface{{Name: "bond1", Mode: "802.3ad"}}) {
		t.Errorf("interfaces = %+v %+v %+v", got.Bridges, got.VLANs, got.Bonds)
	}
	if got.RoutingRules != 1 || got.VRFs != 1 || got.MarkRoutingRules != 1 || got.MangleRules != 2 || got.ForwardFilterRules != 1 || got.NATRules != 1 || got.VRRPInterfaces != 1 {
		t.Errorf("policy counts = %+v", got)
	}
	if len(got.Unread) != 0 {
		t.Errorf("unread = %v", got.Unread)
	}
}

func TestDefaultRoutesActiveAndInactive(t *testing.T) {
	got, err := chip("7.24.2", fullHW, advLPM).reader(t).ReadL3HW(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	want := []DefaultRoute{
		{Family: "ipv4", Gateway: "192.0.2.1", Distance: 20, Protocol: "BGP", LocalPref: 200, Active: true, HFlag: true},
		{Family: "ipv4", Gateway: "192.0.2.2", Distance: 250, Protocol: "Static route", Inactive: true, SuppressHWOffload: true},
		{Family: "ipv6", Gateway: "2001:db8::1", Distance: 20, Protocol: "BGP", LocalPref: 100, Active: true},
	}
	if !slices.Equal(got.DefaultRoutes, want) {
		t.Errorf("default routes = %+v", got.DefaultRoutes)
	}
}

func TestShortestHWPrefix30IsPartial(t *testing.T) {
	f := chip("7.24.2", shwp30, advLPM)
	got, err := f.reader(t).ReadL3HW(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	m := got.Monitor
	if m.IPv4RoutesHW != 37729 || m.IPv4ShortestHWPrefix != 30 || m.IPv4RoutesCPU != 904609 || !m.Partial() {
		t.Errorf("monitor = %+v", m)
	}
	if got.Advanced.LPMCap != 27200 {
		t.Errorf("lpm-cap = %d", got.Advanced.LPMCap)
	}
}

func TestNexthopExhaustionWithNothingInHardware(t *testing.T) {
	got, err := chip("7.17.2", nhFull, `[{"state":"ok"}]`).reader(t).ReadL3HW(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	m := got.Monitor
	if m.IPv4RoutesTotal != 174000 || m.IPv4RoutesHW != 0 || m.IPv4ShortestHWPrefix != 24 || m.NexthopCap != 8192 || m.NexthopUsage != 8192 {
		t.Errorf("monitor = %+v", m)
	}
	if !m.NexthopExhausted() || !m.Partial() {
		t.Error("8192 of 8192 next hops with nothing in hardware must read exhausted and partial")
	}
	if got.Advanced == nil || got.Advanced.HasLPM {
		t.Errorf("a monitor without lpm-cap has no LPM reading: %+v", got.Advanced)
	}
}

func TestIPv6HWOffHasNoIPv6HardwareCounts(t *testing.T) {
	f := chip("7.24.2", `[{"state":"ok","ipv4-routes-total":"100","ipv4-routes-hw":"100","ipv6-routes-total":"15"}]`, advLPM)
	f.bodies["GET "+pathSettings] = `{"autorestart":"true","fasttrack-hw":"false","ipv6-hw":"false"}`
	got, err := f.reader(t).ReadL3HW(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if got.Settings.IPv6HW || got.Monitor.IPv6RoutesTotal != 15 || got.Monitor.IPv6RoutesHW != 0 {
		t.Errorf("settings %+v monitor %+v", got.Settings, got.Monitor)
	}
}

// The shape of an operator field report (CCR2216, RouterOS 7.24.2): the
// active default route carries the H flag while the monitor says no route is
// in hardware. The numbers are illustrative documentation values; only the
// shape is from the report. The H flag must not be read as proof of
// hardware.
const hFlagNoHW = `[{"state":"ok","ipv4-routes-total":"600000","ipv4-routes-hw":"0","ipv4-routes-cpu":"600000","ipv4-shortest-hw-prefix":"32","ipv6-routes-total":"20","ipv6-routes-hw":"0","ipv6-routes-cpu":"20","nexthop-cap":"8192","nexthop-usage":"120"}]`

func TestHFlagWithNothingInHardware(t *testing.T) {
	got, err := chip("7.24.2", hFlagNoHW, advLPM).reader(t).ReadL3HW(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	var def DefaultRoute
	for _, d := range got.DefaultRoutes {
		if d.Family == "ipv4" && d.Active {
			def = d
		}
	}
	if !def.HFlag || def.Gateway != "192.0.2.1" {
		t.Fatalf("default = %+v", def)
	}
	m := got.Monitor
	if m.IPv4RoutesHW != 0 || m.IPv4ShortestHWPrefix != 32 || !m.Partial() || m.NexthopExhausted() {
		t.Errorf("monitor = %+v: the counts, not the H flag, say what is in hardware", m)
	}
}

func TestAdvancedReadsNotPermittedAreUnreadNotErrors(t *testing.T) {
	f := chip("7.24.2", fullHW, advLPM)
	f.status["POST "+pathAdvMon] = http.StatusForbidden
	f.status["GET "+pathAdvSet] = http.StatusForbidden
	f.status["GET "+pathSwitch+"/port"] = http.StatusBadRequest
	got, err := f.reader(t).ReadL3HW(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if got.Advanced != nil || got.Tuning != nil || got.Ports != nil || !got.Applicable {
		t.Errorf("advanced %+v tuning %+v ports %+v", got.Advanced, got.Tuning, got.Ports)
	}
	want := []string{
		"advanced monitor: the account may not read it",
		"l3hw advanced settings: the account may not read it",
		"switch ports: RouterOS has no such menu or command",
	}
	if !slices.Equal(got.Unread, want) {
		t.Errorf("unread = %q", got.Unread)
	}
	if got.Monitor.IPv4RoutesHW != 942326 {
		t.Error("the basic monitor must still be read")
	}
}

func TestChrWithNoSwitchChipIsNotApplicable(t *testing.T) {
	for name, set := range map[string]func(*l3hwRouter){
		"no switch menu":  func(f *l3hwRouter) { f.status["GET "+pathSwitch] = http.StatusBadRequest },
		"no switch":       func(f *l3hwRouter) { f.bodies["GET "+pathSwitch] = `[]` },
		"no l3hw menu":    func(f *l3hwRouter) { f.status["GET "+pathSettings] = http.StatusNotFound },
		"no l3hw monitor": func(f *l3hwRouter) { f.status["POST "+pathMonitor] = http.StatusBadRequest },
	} {
		t.Run(name, func(t *testing.T) {
			f := chip("7.23.7", fullHW, advLPM)
			f.bodies["GET /system/resource"] = `{"version":"7.23.7 (long-term)","board-name":"CHR"}`
			set(f)
			got, err := f.reader(t).ReadL3HW(context.Background())
			if err != nil {
				t.Fatal(err)
			}
			if got.Applicable || got.Version != "7.23.7" || got.Monitor != (Monitor{}) || got.Settings != (Settings{}) || got.DefaultRoutes != nil {
				t.Errorf("got %+v, want not applicable with only the version", got)
			}
			for _, r := range f.requests() {
				if strings.Contains(r, "/ip/route") || strings.Contains(r, "advanced") {
					t.Errorf("a not-applicable router must not be read further: %s", r)
				}
			}
		})
	}
}

func TestAuthRefusedIsRedacted(t *testing.T) {
	f := chip("7.24.2", fullHW, advLPM)
	srv := httptest.NewServer(f)
	t.Cleanup(srv.Close)
	wrong := func(k string) string {
		return map[string]string{"PACKETEER_ROUTER_READ_USER": labUser, "PACKETEER_ROUTER_READ_PASSWORD": "wrong-lab-password"}[k]
	}
	rd, err := Open(Config{URL: srv.URL, UsernameEnv: "PACKETEER_ROUTER_READ_USER", PasswordEnv: "PACKETEER_ROUTER_READ_PASSWORD"}, plugin.Env{Getenv: wrong})
	if err != nil {
		t.Fatal(err)
	}
	_, err = rd.ReadL3HW(context.Background())
	if !errors.Is(err, ErrAuth) {
		t.Fatalf("err = %v, want ErrAuth", err)
	}
	for _, secret := range []string{"wrong-lab-password", labPass, labUser} {
		if strings.Contains(err.Error(), secret) {
			t.Errorf("error holds a credential: %v", err)
		}
	}
	if n := len(f.requests()); n != 1 {
		t.Errorf("%d requests after a refused login, want 1", n)
	}
}

func TestAccountWithoutRestAPIIsRefusedOnTheMonitor(t *testing.T) {
	f := chip("7.24.2", fullHW, advLPM)
	f.status["POST "+pathMonitor] = http.StatusForbidden
	_, err := f.reader(t).ReadL3HW(context.Background())
	var se *StatusError
	if !errors.Is(err, ErrAuth) || !errors.As(err, &se) || se.Code != http.StatusForbidden {
		t.Errorf("err = %v", err)
	}
}

func TestTimeout(t *testing.T) {
	f := chip("7.24.2", fullHW, advLPM)
	f.delay = 300 * time.Millisecond
	rd := f.reader(t)
	rd.http.Timeout = 50 * time.Millisecond
	_, err := rd.ReadL3HW(context.Background())
	var ne net.Error
	if !errors.As(err, &ne) || !ne.Timeout() {
		t.Fatalf("err = %v, want a timeout", err)
	}
	if strings.Contains(err.Error(), "http://") {
		t.Errorf("error names the URL: %v", err)
	}
}

func TestMalformedNumberIsAnError(t *testing.T) {
	f := chip("7.24.2", `[{"state":"ok","ipv4-routes-total":"lots"}]`, advLPM)
	_, err := f.reader(t).ReadL3HW(context.Background())
	if err == nil || !strings.Contains(err.Error(), "ipv4-routes-total is not a number") {
		t.Errorf("err = %v", err)
	}
}

// The reader sends GET requests and the two monitor reads with once, and
// nothing else, with the same body every time.
func TestOnlyGETsAndMonitorOncePOSTs(t *testing.T) {
	f := chip("7.24.2", fullHW, advLPM)
	if _, err := f.reader(t).ReadL3HW(context.Background()); err != nil {
		t.Fatal(err)
	}
	reqs := f.requests()
	var posts []string
	for _, r := range reqs {
		method, rest, _ := strings.Cut(r, " ")
		switch method {
		case "GET":
			if !strings.HasSuffix(rest, " ") {
				t.Errorf("GET with a body: %q", r)
			}
		case "POST":
			posts = append(posts, rest)
		default:
			t.Errorf("method %s sent: %q", method, r)
		}
	}
	want := []string{"/rest" + pathMonitor + ` {"once":""}`, "/rest" + pathAdvMon + ` {"once":""}`}
	if !slices.Equal(posts, want) {
		t.Errorf("POSTs = %q, want %q", posts, want)
	}
	if len(reqs) != 18 {
		t.Errorf("%d requests: %q", len(reqs), reqs)
	}
}

func TestRefusesAnythingOffTheL3HWLists(t *testing.T) {
	f := chip("7.24.2", fullHW, advLPM)
	rd := f.reader(t)
	ctx := context.Background()
	var out any
	for _, c := range []struct {
		method, path string
		list         readonly.Allowlist
	}{
		{http.MethodPost, "/ip/route", l3hwPost},
		{http.MethodPost, "/system/reboot", l3hwPost},
		{http.MethodPost, pathMonitor + "/../../../system/reboot", l3hwPost},
		{http.MethodPost, "/ip/address", l3hwGet},
		{http.MethodGet, "/ip/route", l3hwGet},
		{http.MethodGet, "/ip/route?dst-address=0.0.0.0/0&x=1", l3hwGet},
		{http.MethodGet, "/user", l3hwGet},
		{http.MethodGet, "/system/resource", l3hwPost},
	} {
		err := rd.do(ctx, c.method, c.path, onceBody, c.list, &out)
		if !errors.Is(err, readonly.ErrRefused) {
			t.Errorf("%s %s = %v, want ErrRefused", c.method, c.path, err)
		}
	}
	if reqs := f.requests(); len(reqs) != 0 {
		t.Errorf("refused requests reached the router: %q", reqs)
	}
}

func TestReadingIsJSONWithoutCredentials(t *testing.T) {
	got, err := chip("7.24.2", fullHW, advLPM).reader(t).ReadL3HW(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	b, err := json.Marshal(got)
	if err != nil {
		t.Fatal(err)
	}
	for _, secret := range []string{labPass, labUser} {
		if strings.Contains(string(b), secret) {
			t.Errorf("reading holds a credential: %s", b)
		}
	}
	if !strings.Contains(string(b), `"ipv4_routes_hw":942326`) {
		t.Errorf("json = %s", b)
	}
}
