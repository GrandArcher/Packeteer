package main

import (
	"context"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"gopkg.in/yaml.v3"

	"github.com/GrandArcher/Packeteer/internal/plugins/irr/whois"
	"github.com/GrandArcher/Packeteer/internal/plugins/registry/peeringdb"
	"github.com/GrandArcher/Packeteer/internal/plugins/registry/ripe"
	"github.com/GrandArcher/Packeteer/internal/plugins/rpki/vrpjson"
	"github.com/GrandArcher/Packeteer/internal/registry"
	"github.com/GrandArcher/Packeteer/internal/rpki"
	"github.com/GrandArcher/Packeteer/pkg/plugin"
)

const (
	labUser = "lab-ripe-user"
	labPass = "lab-ripe-password-not-a-secret"
	labKey  = "lab-peeringdb-key-not-a-secret"
)

var labEnv = map[string]string{
	ripeUserEnv: labUser, ripePasswordEnv: labPass, pdbKeyEnv: labKey,
	"PACKETEER_RIPE_USER": labUser, "PACKETEER_RIPE_PASSWORD": labPass, "PACKETEER_PEERINGDB_API_KEY": labKey,
}

func getenv(k string) string { return labEnv[k] }

type lab struct {
	s     *stub
	https *httptest.Server
	http  *httptest.Server
	whois string
}

// newLab starts the stand-in on loopback and makes its TLS certificate the
// only root the plugins trust, as the lab does with a mounted CA. It must be
// the first TLS client in the process: Go reads SSL_CERT_FILE once.
func newLab(t *testing.T) *lab {
	t.Helper()
	l := &lab{s: newStub(getenv, time.Now)}
	l.https = httptest.NewTLSServer(l.s.httpsHandler())
	l.http = httptest.NewServer(l.s.httpHandler())
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	go l.s.serveWhois(ln)
	l.whois = ln.Addr().String()
	t.Cleanup(func() { ln.Close(); l.https.Close(); l.http.Close() })
	ca := filepath.Join(t.TempDir(), "ca.pem")
	pemBytes := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: l.https.Certificate().Raw})
	if err := os.WriteFile(ca, pemBytes, 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("SSL_CERT_FILE", ca)
	return l
}

func cfg(t *testing.T, doc string) plugin.Config {
	t.Helper()
	var n yaml.Node
	if err := yaml.Unmarshal([]byte(doc), &n); err != nil {
		t.Fatal(err)
	}
	return plugin.NewConfig(n.Content[0])
}

// service is the registry service as the lab config builds it: the whois
// and VRP JSON sources, and the peeringdb and ripe registry sources, all
// pointed at the stand-in.
func (l *lab) service(t *testing.T, push bool, env func(string) string) *registry.Service {
	t.Helper()
	irrSrc, err := whois.New(cfg(t, fmt.Sprintf("{address: %q, dialect: ripe, databases: [TEST], rate_per_minute: 600}", l.whois)), plugin.Env{})
	if err != nil {
		t.Fatal(err)
	}
	vrp, err := vrpjson.New(cfg(t, fmt.Sprintf("{url: %q}", l.http.URL+"/json")), plugin.Env{})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	if err := vrp.Start(ctx); err != nil {
		t.Fatal(err)
	}
	set := rpki.NewSet([]plugin.RPKI{vrp})
	for end := time.Now().Add(5 * time.Second); set.Lookup(netip.MustParsePrefix("203.0.113.0/24"), 64501).State == plugin.RPKIUnknown; {
		if time.Now().After(end) {
			t.Fatal("the VRP JSON source never became fresh")
		}
		time.Sleep(50 * time.Millisecond)
	}
	pdb, err := peeringdb.New(cfg(t, fmt.Sprintf("{base_url: %q}", l.https.URL+"/peeringdb")), plugin.Env{Name: "peeringdb", Getenv: env})
	if err != nil {
		t.Fatal(err)
	}
	rip, err := ripe.New(cfg(t, fmt.Sprintf("{base_url: %q, source: TEST}", l.https.URL+"/ripe")), plugin.Env{Name: "ripe", Getenv: env})
	if err != nil {
		t.Fatal(err)
	}
	prefixes := map[netip.Prefix]uint32{netip.MustParsePrefix("203.0.113.0/24"): 64501, netip.MustParsePrefix("203.0.113.128/25"): 64501}
	origins := map[netip.Prefix]map[uint32]bool{}
	for p, o := range prefixes {
		origins[p] = map[uint32]bool{o: true}
	}
	return registry.New(registry.Config{ASNs: []uint32{64501}, IRRSource: "TEST", PushDB: "TEST", MntBy: "MAINT-LAB", Headroom: 20, PushEnabled: push}, registry.Deps{
		Observe: func() registry.Observed {
			return registry.Observed{Ready: true, Announced: prefixes, Origins: origins, Downstream: map[uint32]bool{},
				NoCone: "lab", Sessions: []plugin.RegistrySession{{Exchange: "ix-lab", IXID: 7, SpeedMbps: 10000, Addrs: []netip.Addr{netip.MustParseAddr("198.51.100.130")}}}}
		},
		IRR:      []registry.IRRSource{{Name: "lab-irr", Plugin: irrSrc}},
		RPKI:     set,
		Checkers: []registry.Checker{{Name: "peeringdb", Type: "peeringdb", Plugin: pdb}, {Name: "ripe", Type: "ripe", Plugin: rip}},
	})
}

func findings(r registry.Report) []string {
	var out []string
	for _, f := range r.Findings {
		out = append(out, f.Kind+" | "+f.Subject)
	}
	slices.Sort(out)
	return out
}

func find(t *testing.T, r registry.Report, kind string) registry.Finding {
	t.Helper()
	for _, f := range r.Findings {
		if f.Kind == kind {
			return f
		}
	}
	t.Fatalf("no %s finding in %v", kind, findings(r))
	return registry.Finding{}
}

func (l *lab) writes() (authorized, refused int) {
	for _, r := range l.s.state().Requests {
		if r.Method == http.MethodGet || r.Method == "QUERY" {
			continue
		}
		if r.Authorized {
			authorized++
		} else {
			refused++
		}
	}
	return authorized, refused
}

// #657: the real whois, vrpjson, peeringdb and ripe plugins and the scan
// find each documented drift on the stand-in, and the confirmed pushes land
// only on the stand-in, with the digest of the shown diff and the lab
// credentials from the environment.
func TestScanFindsTheDocumentedDriftAndPushesToTheStandIn(t *testing.T) {
	l := newLab(t)
	svc := l.service(t, true, getenv)
	ctx := context.Background()
	svc.Scan(ctx)
	r := svc.Report()

	want := []string{
		"irr_missing | 203.0.113.128/25 AS64501",
		"irr_stale | 192.0.2.0/24 AS64501 TEST",
		"pdb_ix_speed | AS64501 ix-lab 198.51.100.130 speed",
		"pdb_maxprefix | AS64501 info_prefixes4",
		"rpki_maxlength | 203.0.113.128/25 AS64501",
	}
	if got := findings(r); !slices.Equal(got, want) {
		t.Fatalf("findings\n got %q\nwant %q\nsections %+v", got, want, r.Sections)
	}
	for _, s := range r.Sections {
		// The lab sets no as-set: that part is skipped and says so.
		if s.Status != "ok" && s.Name != "as-set" {
			t.Errorf("section %+v", s)
		}
	}
	missing := find(t, r, "irr_missing")
	if !strings.Contains(missing.Diff, "+ route:") || !strings.Contains(missing.Diff, "203.0.113.128/25") || !strings.Contains(missing.Diff, "mnt-by:         MAINT-LAB") {
		t.Errorf("missing diff %q", missing.Diff)
	}
	stale := find(t, r, "irr_stale")
	if !strings.Contains(stale.Diff, "- route:          192.0.2.0/24") || stale.Change != nil || stale.Note == "" {
		t.Errorf("stale on the first sighting: diff %q change %v note %q", stale.Diff, stale.Change, stale.Note)
	}
	if d := find(t, r, "pdb_maxprefix").Diff; !strings.Contains(d, "- info_prefixes4: 1") || !strings.Contains(d, "+ info_prefixes4: 3") {
		t.Errorf("max-prefix diff %q", d)
	}
	if d := find(t, r, "pdb_ix_speed").Diff; !strings.Contains(d, "- speed: 1000") || !strings.Contains(d, "+ speed: 10000") {
		t.Errorf("speed diff %q", d)
	}
	rk := find(t, r, "rpki_maxlength")
	if !strings.Contains(rk.Message, "203.0.113.0/24") || rk.Change != nil {
		t.Errorf("ROA finding %+v", rk)
	}
	if a, _ := l.writes(); a != 0 {
		t.Fatalf("the scan wrote %d times", a)
	}

	// A digest that is not the shown one changes nothing.
	if _, err := svc.Push(ctx, missing.ID, "0000000000000000"); err == nil {
		t.Fatal("a wrong digest was accepted")
	}
	if a, _ := l.writes(); a != 0 {
		t.Fatalf("a refused push wrote %d times", a)
	}
	// The ROA gap is suggest-only.
	if _, err := svc.Push(ctx, rk.ID, rk.Digest); err == nil {
		t.Fatal("a ROA finding was pushed")
	}

	// The second scan shows the stale object again, so its delete is offered.
	svc.Scan(ctx)
	r = svc.Report()
	for _, kind := range []string{"irr_missing", "irr_stale", "pdb_maxprefix", "pdb_ix_speed"} {
		f := find(t, r, kind)
		if !f.Pushable || f.Digest == "" || f.Change == nil {
			t.Fatalf("%s is not pushable: %+v", kind, f)
		}
		if _, err := svc.Push(ctx, f.ID, f.Digest); err != nil {
			t.Fatalf("push %s: %v", kind, err)
		}
	}
	st := l.s.state()
	routes := strings.Join(st.Routes, "|")
	if !strings.Contains(routes, "203.0.113.128/25") || strings.Contains(routes, "192.0.2.0/24") {
		t.Errorf("the stand-in routes after the pushes: %q", routes)
	}
	if n := st.PDB["net/1"]["info_prefixes4"]; fmt.Sprint(n) != "3" {
		t.Errorf("info_prefixes4 = %v", n)
	}
	if n := st.PDB["netixlan/11"]["speed"]; fmt.Sprint(n) != "10000" {
		t.Errorf("speed = %v", n)
	}
	if a, refused := l.writes(); a != 4 || refused != 0 {
		t.Errorf("authorized writes %d, refused %d", a, refused)
	}
	if _, err := svc.Push(ctx, missing.ID, missing.Digest); err == nil {
		t.Error("the same change was pushed twice")
	}

	// What remains is the ROA gap, which no push fixes.
	svc.Scan(ctx)
	if got := findings(svc.Report()); !slices.Equal(got, []string{"rpki_maxlength | 203.0.113.128/25 AS64501"}) {
		t.Errorf("after the pushes: %q", got)
	}
}

// Push stays off unless push_enabled is set, and without the credentials in
// the environment a confirmed push does not reach the stand-in.
func TestPushOffAndWithoutCredentials(t *testing.T) {
	l := newLab(t)
	ctx := context.Background()

	off := l.service(t, false, getenv)
	off.Scan(ctx)
	f := find(t, off.Report(), "irr_missing")
	if f.Pushable || f.Change != nil {
		t.Fatalf("a finding is pushable with push_enabled off: %+v", f)
	}
	if _, err := off.Push(ctx, f.ID, f.Digest); err == nil {
		t.Fatal("push worked with push_enabled off")
	}

	bare := l.service(t, true, func(string) string { return "" })
	bare.Scan(ctx)
	for _, kind := range []string{"irr_missing", "pdb_maxprefix"} {
		f := find(t, bare.Report(), kind)
		if _, err := bare.Push(ctx, f.ID, f.Digest); err == nil || !strings.Contains(err.Error(), "needs") {
			t.Fatalf("push %s without credentials: %v", kind, err)
		}
	}
	if a, refused := l.writes(); a != 0 || refused != 0 {
		t.Errorf("writes reached the stand-in: %d authorized, %d refused", a, refused)
	}
}

// The stand-in refuses a write without the lab credentials and records it as
// refused, and records no credential.
func TestStandInRefusesWritesWithoutCredentials(t *testing.T) {
	l := newLab(t)
	cl := l.https.Client()
	do := func(method, path, body string, set func(*http.Request)) int {
		req, err := http.NewRequest(method, l.https.URL+path, strings.NewReader(body))
		if err != nil {
			t.Fatal(err)
		}
		set(req)
		resp, err := cl.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		_, _ = io.Copy(io.Discard, resp.Body)
		resp.Body.Close()
		return resp.StatusCode
	}
	none := func(*http.Request) {}
	if c := do(http.MethodDelete, "/ripe/test/route/192.0.2.0/24AS64501", "", none); c != http.StatusUnauthorized {
		t.Errorf("DELETE without credentials = %d", c)
	}
	if c := do(http.MethodDelete, "/ripe/test/route/192.0.2.0/24AS64501", "", func(r *http.Request) { r.SetBasicAuth(labUser, "wrong") }); c != http.StatusUnauthorized {
		t.Errorf("DELETE with a wrong password = %d", c)
	}
	if c := do(http.MethodPut, "/peeringdb/api/net/1", `{"info_prefixes4": 9}`, func(r *http.Request) { r.Header.Set("Authorization", "Api-Key wrong") }); c != http.StatusUnauthorized {
		t.Errorf("PUT with a wrong key = %d", c)
	}
	st := l.s.state()
	if len(st.Routes) != 2 || fmt.Sprint(st.PDB["net/1"]["info_prefixes4"]) != "1" {
		t.Errorf("a refused write changed the data: %v %v", st.Routes, st.PDB["net/1"])
	}
	if a, refused := l.writes(); a != 0 || refused != 3 {
		t.Errorf("writes: %d authorized, %d refused", a, refused)
	}
	raw := fmt.Sprint(st.Requests)
	for _, secret := range []string{labPass, labKey, "wrong"} {
		if strings.Contains(raw, secret) {
			t.Errorf("the request record holds a credential: %s", raw)
		}
	}
}

// #673: the delete is offered by the second scan only. A wrong digest is
// refused and leaves the object on the stand-in; the shown digest deletes
// exactly that object, with the lab credentials.
func TestStaleDeleteNeedsSecondScanAndShownDigest(t *testing.T) {
	l := newLab(t)
	svc := l.service(t, true, getenv)
	ctx := context.Background()
	svc.Scan(ctx)
	first := find(t, svc.Report(), "irr_stale")
	if first.Pushable || first.Digest != "" {
		t.Fatalf("the first sighting is offered: %+v", first)
	}
	if _, err := svc.Push(ctx, first.ID, ""); err == nil {
		t.Fatal("the delete was pushed on the first sighting")
	}

	svc.Scan(ctx)
	stale := find(t, svc.Report(), "irr_stale")
	if !stale.Pushable || stale.Change == nil || stale.Change.Op != "delete_object" || stale.Digest == "" || stale.Note != "" {
		t.Fatalf("the second sighting is not offered: %+v", stale)
	}
	if _, err := svc.Push(ctx, stale.ID, "0000000000000000"); !errors.Is(err, registry.ErrDigestChanged) {
		t.Fatalf("a wrong digest: err = %v, want ErrDigestChanged", err)
	}
	if got := strings.Join(l.s.state().Routes, "|"); !strings.Contains(got, "192.0.2.0/24") {
		t.Fatalf("a refused delete removed the object: %q", got)
	}
	if a, refused := l.writes(); a != 0 || refused != 0 {
		t.Fatalf("a refused delete reached the stand-in: authorized %d refused %d", a, refused)
	}

	if _, err := svc.Push(ctx, stale.ID, stale.Digest); err != nil {
		t.Fatal(err)
	}
	if got := strings.Join(l.s.state().Routes, "|"); strings.Contains(got, "192.0.2.0/24") || len(l.s.state().Routes) != 1 {
		t.Fatalf("routes after the delete: %q", got)
	}
	if a, refused := l.writes(); a != 1 || refused != 0 {
		t.Fatalf("authorized writes %d, refused %d", a, refused)
	}
}
