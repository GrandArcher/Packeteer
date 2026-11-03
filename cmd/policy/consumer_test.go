package main

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/netip"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/GrandArcher/Packeteer/internal/agentwire/pkitest"
	"github.com/GrandArcher/Packeteer/internal/extpolicy"
	"github.com/GrandArcher/Packeteer/internal/policy"
	"github.com/GrandArcher/Packeteer/pkg/plugin"
)

func quiet() *slog.Logger { return slog.New(slog.NewTextHandler(io.Discard, nil)) }

type recorder struct {
	sets [][]extpolicy.Route
	fail bool
}

func (r *recorder) apply(_ context.Context, routes []extpolicy.Route) error {
	if r.fail {
		return errors.New("reload failed")
	}
	r.sets = append(r.sets, routes)
	return nil
}

func (r *recorder) last() []extpolicy.Route { return r.sets[len(r.sets)-1] }

var labCheck = routeCheck{community: "64512:666"}

var (
	route4 = extpolicy.Route{Prefix: netip.MustParsePrefix("198.51.100.0/24"), Provider: "transit-b", NextHop: netip.MustParseAddr("192.0.2.22"),
		LocalPref: 250, Communities: []string{"64512:666", "64512:1:2", extpolicy.NoExport}, Cause: "performance"}
	route6 = extpolicy.Route{Prefix: netip.MustParsePrefix("2001:db8:100::/48"), Provider: "transit-b", NextHop: netip.MustParseAddr("2001:db8::22"),
		LocalPref: 250, Communities: []string{"64512:666", extpolicy.NoExport}, ASPath: []uint32{64497, 64500}, Cause: "cost"}
)

// The consumer starts from the empty set, applies the feed, keeps it while
// the feed is unreachable until the expiry, then drops it; an expired or
// off document drops at once; a failed apply is retried.
func TestConsumerKeepsUntilExpiry(t *testing.T) {
	now := time.Unix(1_800_000_000, 0)
	var doc extpolicy.Document
	var fetchErr error
	out := &recorder{}
	c := &consumer{
		fetch: func(context.Context, uint64, bool) (extpolicy.Document, error) { return doc, fetchErr },
		out:   out, check: labCheck, log: quiet(), now: func() time.Time { return now },
	}
	ctx := context.Background()
	fetchErr = errors.New("connection refused")
	_ = c.step(ctx)
	if len(out.sets) != 1 || len(out.last()) != 0 {
		t.Fatalf("start with the feed down: %v, want the empty set applied", out.sets)
	}
	fetchErr = nil
	doc = extpolicy.Document{Revision: 1, ExpiresInMS: 10_000, HeartbeatMS: 3000, Routes: []extpolicy.Route{route4}}
	_ = c.step(ctx)
	if len(out.sets) != 2 || len(out.last()) != 1 || c.pollEvery() != 3*time.Second {
		t.Fatalf("feed up: %v, poll %s", out.sets, c.pollEvery())
	}
	_ = c.step(ctx)
	if len(out.sets) != 2 {
		t.Fatal("the same routes were applied again")
	}
	fetchErr = errors.New("connection refused")
	now = now.Add(9 * time.Second)
	_ = c.step(ctx)
	if len(out.sets) != 2 {
		t.Fatal("routes dropped before the expiry")
	}
	now = now.Add(time.Second)
	_ = c.step(ctx)
	if len(out.sets) != 3 || len(out.last()) != 0 {
		t.Fatalf("at the expiry: %v, want the empty set", out.sets)
	}
	fetchErr = nil
	_ = c.step(ctx)
	out.fail = true
	doc.ExpiresInMS = 0
	_ = c.step(ctx)
	if len(c.applied) != 1 {
		t.Fatal("a failed apply was recorded as applied")
	}
	out.fail = false
	_ = c.step(ctx)
	if len(out.last()) != 0 || len(c.applied) != 0 {
		t.Fatalf("an off or expired document must drop every route: %v", out.last())
	}
}

// Stopping the consumer applies the empty set.
func TestConsumerRunDropsOnStop(t *testing.T) {
	out := &recorder{}
	waiting := make(chan struct{})
	var once sync.Once
	c := &consumer{
		fetch: func(ctx context.Context, _ uint64, wait bool) (extpolicy.Document, error) {
			if wait {
				once.Do(func() { close(waiting) })
				<-ctx.Done()
				return extpolicy.Document{}, ctx.Err()
			}
			return extpolicy.Document{ExpiresInMS: 60_000, HeartbeatMS: 1000, Routes: []extpolicy.Route{route4}}, nil
		},
		out: out, check: labCheck, log: quiet(), now: time.Now,
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { c.run(ctx); close(done) }()
	select {
	case <-waiting:
	case <-time.After(5 * time.Second):
		t.Fatal("the consumer never applied the document and waited")
	}
	cancel()
	<-done
	if len(out.sets) != 3 || len(out.sets[0]) != 0 || len(out.sets[1]) != 1 || len(out.last()) != 0 {
		t.Fatalf("sets %v: want the empty set at start, the route, then the empty set on stop", out.sets)
	}
}

// A fetch that hangs (a frozen controller, a lost path) cannot hold the
// routes past their expiry: the fetch ends at the expiry and the empty set
// is applied then, and a later step drops before it waits again.
func TestConsumerDropsAtExpiryWhileFetchHangs(t *testing.T) {
	out := &recorder{}
	hang := false
	c := &consumer{
		fetch: func(ctx context.Context, _ uint64, _ bool) (extpolicy.Document, error) {
			if hang {
				<-ctx.Done()
				return extpolicy.Document{}, ctx.Err()
			}
			return extpolicy.Document{ExpiresInMS: 300, HeartbeatMS: 10_000, Routes: []extpolicy.Route{route4}}, nil
		},
		out: out, check: labCheck, log: quiet(), now: time.Now,
	}
	ctx := context.Background()
	_ = c.step(ctx)
	if len(c.applied) != 1 {
		t.Fatalf("applied %v", c.applied)
	}
	hang = true
	start := time.Now()
	if err := c.step(ctx); err == nil {
		t.Fatal("hung fetch returned no error")
	}
	if took := time.Since(start); took > 2*time.Second || len(c.applied) != 0 {
		t.Fatalf("after %s the daemon still has %v; want the empty set at the 300ms expiry", took, c.applied)
	}
	c.applied, c.started = []extpolicy.Route{route4}, true
	c.deadline = time.Now().Add(-time.Millisecond)
	dropped := make(chan int, 1)
	c.out = applierFunc(func(routes []extpolicy.Route) { dropped <- len(routes) })
	sctx, cancel := context.WithCancel(ctx)
	done := make(chan struct{})
	go func() { _ = c.step(sctx); close(done) }()
	defer func() { cancel(); <-done }()
	select {
	case n := <-dropped:
		if n != 0 {
			t.Fatalf("applied %d routes past the expiry", n)
		}
	case <-time.After(time.Second):
		t.Fatal("an expired set was not dropped before the fetch")
	}
}

type applierFunc func([]extpolicy.Route)

func (f applierFunc) apply(_ context.Context, routes []extpolicy.Route) error { f(routes); return nil }

func render(t *testing.T, tmpl string, routes []extpolicy.Route) string {
	t.Helper()
	dir := t.TempDir()
	out := filepath.Join(dir, "routes.conf")
	flag := filepath.Join(dir, "reloaded")
	r, err := newRenderer(filepath.Join("..", "..", "examples", "external-policy", tmpl), out, "touch "+flag)
	if err != nil {
		t.Fatal(err)
	}
	if err := r.apply(context.Background(), routes); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(flag); err != nil {
		t.Fatal("reload command did not run")
	}
	b, err := os.ReadFile(out)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

func TestRenderBIRD(t *testing.T) {
	got := render(t, "bird.conf.tmpl", []extpolicy.Route{route4, route6})
	for _, want := range []string{
		"protocol static packeteer_feed4 {\n\tipv4;\n\troute 198.51.100.0/24 via 192.0.2.22 {\n\t\tbgp_local_pref = 250;\n\t\tbgp_community.add((64512, 666));\n\t\tbgp_large_community.add((64512, 1, 2));\n\t\tbgp_community.add((65535, 65281));\n\t};\n}",
		"protocol static packeteer_feed6 {\n\tipv6;\n\troute 2001:db8:100::/48 via 2001:db8::22 {\n\t\tbgp_local_pref = 250;\n\t\tbgp_community.add((64512, 666));\n\t\tbgp_community.add((65535, 65281));\n\t};\n}",
	} {
		if !strings.Contains(got, want) {
			t.Errorf("BIRD output lacks\n%s\ngot\n%s", want, got)
		}
	}
	empty := render(t, "bird.conf.tmpl", nil)
	if strings.Contains(empty, "route ") || !strings.Contains(empty, "protocol static packeteer_feed4 {\n\tipv4;\n}") {
		t.Errorf("empty set:\n%s", empty)
	}
}

func TestRenderOpenBGPD(t *testing.T) {
	got := render(t, "openbgpd.conf.tmpl", []extpolicy.Route{route4})
	want := "network 198.51.100.0/24 set { nexthop 192.0.2.22 localpref 250 community 64512:666 large-community 64512:1:2 community NO_EXPORT }"
	if !strings.Contains(got, want) {
		t.Errorf("OpenBGPD output lacks\n%s\ngot\n%s", want, got)
	}
}

func TestRenderReloadFailure(t *testing.T) {
	dir := t.TempDir()
	r, err := newRenderer(filepath.Join("..", "..", "examples", "external-policy", "bird.conf.tmpl"), filepath.Join(dir, "routes.conf"), "false")
	if err != nil {
		t.Fatal(err)
	}
	if err := r.apply(context.Background(), nil); err == nil || !strings.Contains(err.Error(), "reload") {
		t.Errorf("failed reload: %v", err)
	}
}

func TestExaBGP(t *testing.T) {
	var buf bytes.Buffer
	e := &exabgp{w: &buf}
	ctx := context.Background()
	if err := e.apply(ctx, []extpolicy.Route{route4, route6}); err != nil {
		t.Fatal(err)
	}
	want := "announce route 198.51.100.0/24 next-hop 192.0.2.22 local-preference 250 community [64512:666 no-export] large-community [64512:1:2]\n" +
		"announce route 2001:db8:100::/48 next-hop 2001:db8::22 local-preference 250 as-path [64497 64500] community [64512:666 no-export]\n"
	if buf.String() != want {
		t.Errorf("first apply:\n%s\nwant\n%s", buf.String(), want)
	}
	buf.Reset()
	moved := route4
	moved.NextHop = netip.MustParseAddr("192.0.2.21")
	if err := e.apply(ctx, []extpolicy.Route{moved}); err != nil {
		t.Fatal(err)
	}
	want = "announce route 198.51.100.0/24 next-hop 192.0.2.21 local-preference 250 community [64512:666 no-export] large-community [64512:1:2]\n" +
		"withdraw route 2001:db8:100::/48\n"
	if buf.String() != want {
		t.Errorf("second apply:\n%s\nwant\n%s", buf.String(), want)
	}
	buf.Reset()
	if err := e.apply(ctx, []extpolicy.Route{moved}); err != nil || buf.Len() != 0 {
		t.Errorf("unchanged set wrote %q (%v)", buf.String(), err)
	}
}

// End to end over TLS: the consumer reads the controller's feed with the
// token and renders what the announce path put on the wire.
func TestFetchFromServer(t *testing.T) {
	ca := pkitest.New(t)
	leaf := ca.Issue(t, "packeteer")
	feed := extpolicy.New(true, 30*time.Second, nil)
	m := extpolicy.NewMirror(nil, feed)
	if err := m.Bind(nil, "64512:666"); err != nil {
		t.Fatal(err)
	}
	if err := m.Announce(context.Background(), plugin.Route{Prefix: route4.Prefix, Provider: "transit-b", NextHop: route4.NextHop, LocalPref: 250, Communities: []string{"64512:666"}}); err != nil {
		t.Fatal(err)
	}
	feed.Touch(time.Now(), []policy.Improvement{{Prefix: route4.Prefix, Provider: "transit-b", Reason: "faster"}})
	srv, err := extpolicy.NewServer(feed, extpolicy.ServerConfig{Listen: "127.0.0.1:0", CertFile: leaf.CertFile, KeyFile: leaf.KeyFile, Token: "lab-only-token-0123456789"}, quiet())
	if err != nil {
		t.Fatal(err)
	}
	if err := srv.Start(); err != nil {
		t.Fatal(err)
	}
	defer func() { feed.Close(); _ = srv.Shutdown(context.Background()) }()
	pem, _ := os.ReadFile(ca.CAFile)
	pool := x509.NewCertPool()
	pool.AppendCertsFromPEM(pem)
	client := &http.Client{Transport: &http.Transport{TLSClientConfig: &tls.Config{RootCAs: pool, MinVersion: tls.VersionTLS12}}}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	fetch := httpFetch(client, "https://"+srv.Addr()+"/", "lab-only-token-0123456789")
	doc, err := fetch(ctx, 0, false)
	if err != nil {
		t.Fatal(err)
	}
	if len(doc.Routes) != 1 || doc.Routes[0].Reason != "faster" || doc.Routes[0].Communities[1] != extpolicy.NoExport {
		t.Fatalf("document %+v", doc)
	}
	// A long poll answers at the change, well before the 10s heartbeat.
	go func() {
		time.Sleep(200 * time.Millisecond)
		_ = m.Withdraw(context.Background(), route4.Prefix)
		feed.Touch(time.Now(), nil)
	}()
	start := time.Now()
	next, err := fetch(ctx, doc.Revision, true)
	if err != nil || len(next.Routes) != 0 || next.Revision == doc.Revision || time.Since(start) > 3*time.Second {
		t.Fatalf("long poll: %+v %v after %s", next, err, time.Since(start))
	}
	if _, err := httpFetch(client, "https://"+srv.Addr(), "wrong-token-0123456789")(ctx, 0, false); err == nil || !strings.Contains(err.Error(), "401") {
		t.Errorf("wrong token: %v", err)
	}
}

func TestRunUsage(t *testing.T) {
	env := func(k string) string {
		if k == "PACKETEER_POLICY_TOKEN" {
			return "lab-only-token-0123456789"
		}
		return ""
	}
	feed := []string{"-url", "https://192.0.2.10:9443", "-community", "64512:666"}
	missing := filepath.Join(t.TempDir(), "missing.tmpl")
	render := []string{"-template", missing, "-out", filepath.Join(t.TempDir(), "routes.conf")}
	for _, c := range []struct {
		args []string
		code int
		msg  string
	}{
		{nil, 2, "need -url"},
		{feed, 2, "need -url"},
		{append(slices.Clone(feed), "-exabgp", "-template", "x", "-out", "y"), 2, "need -url"},
		{append(slices.Clone(feed), "-template", "x"), 2, "need -url"},
		{append([]string{"-url", "https://192.0.2.10:9443"}, render...), 2, "-community"},
		// The token would cross the network in clear.
		{append([]string{"-url", "http://192.0.2.10:9443", "-community", "64512:666"}, render...), 2, "must be https"},
		{append([]string{"-url", "192.0.2.10:9443", "-community", "64512:666"}, render...), 2, "must be https"},
		{append(slices.Clone(feed), "-allow", "198.51.100.1/24", "-exabgp"), 2, "-allow"},
		{append(slices.Clone(feed[:2]), "-community", "65535:65281", "-exabgp"), 2, "NO_EXPORT"},
		{append(slices.Clone(feed[:2]), "-community", "64512", "-exabgp"), 2, "-community"},
		// Past the checks: the missing template is what fails.
		{append(slices.Clone(feed), render...), 1, "missing.tmpl"},
		{append([]string{"-url", "http://127.0.0.1:9443", "-community", "64512:666", "-allow", "198.51.100.0/24,2001:db8::/32"}, render...), 1, "missing.tmpl"},
		{append([]string{"-url", "http://localhost:9443", "-community", "64512:666"}, render...), 1, "missing.tmpl"},
	} {
		var stderr bytes.Buffer
		if code := run(c.args, env, io.Discard, &stderr); code != c.code || !strings.Contains(stderr.String(), c.msg) {
			t.Errorf("%v: exit %d %q, want %d and %q", c.args, code, stderr.String(), c.code, c.msg)
		}
	}
	if code := run(append(slices.Clone(feed), "-exabgp"), func(string) string { return "" }, io.Discard, io.Discard); code != 2 {
		t.Errorf("no token: exit %d, want 2", code)
	}
}

func TestParseCheck(t *testing.T) {
	rc, err := parseCheck("64512:0666", " 198.51.100.0/24, 2001:db8::/32")
	if err != nil || rc.community != "64512:666" || len(rc.allow) != 2 || rc.allow[1] != netip.MustParsePrefix("2001:db8::/32") {
		t.Fatalf("%+v %v", rc, err)
	}
	if rc, err := parseCheck("64512:1:2", ""); err != nil || rc.allow != nil {
		t.Fatalf("no -allow: %+v %v", rc, err)
	}
	for _, allow := range []string{"198.51.100.0", "198.51.100.1/24", "198.51.100.0/24,"} {
		if _, err := parseCheck("64512:666", allow); err == nil {
			t.Errorf("-allow %q accepted", allow)
		}
	}
}

// Each route is checked before it reaches the daemon; a route that fails
// is dropped and the rest are applied.
func TestRouteCheck(t *testing.T) {
	allow := routeCheck{community: "64512:666", allow: []netip.Prefix{netip.MustParsePrefix("198.51.100.0/24"), netip.MustParsePrefix("2001:db8::/32")}}
	with := func(f func(*extpolicy.Route)) extpolicy.Route {
		r := route4
		r.Communities = slices.Clone(r.Communities)
		f(&r)
		return r
	}
	got, err := allow.route(with(func(r *extpolicy.Route) {
		r.Reason = "x\n}\nprotocol static evil {"
		r.Communities = []string{"64512:666", "064512:01", extpolicy.NoExport}
	}))
	want := extpolicy.Route{Prefix: route4.Prefix, NextHop: route4.NextHop, LocalPref: 250, Communities: []string{"64512:666", "64512:1", extpolicy.NoExport}}
	if err != nil || !sameOnDaemon(got, want) || got.Provider != "" || got.Cause != "" || got.Reason != "" {
		t.Fatalf("good route: %+v %v, want %+v with no free text", got, err, want)
	}
	if _, err := allow.route(route6); err != nil {
		t.Errorf("IPv6 route inside -allow: %v", err)
	}
	for name, c := range map[string]struct {
		r   extpolicy.Route
		err string
	}{
		"no NO_EXPORT":      {with(func(r *extpolicy.Route) { r.Communities = []string{"64512:666", "64512:1:2"} }), "NO_EXPORT"},
		"no packeteer":      {with(func(r *extpolicy.Route) { r.Communities = []string{"64512:667", extpolicy.NoExport} }), "packeteer_community"},
		"newline":           {with(func(r *extpolicy.Route) { r.Communities[1] = "64512:1\nannounce route 192.0.2.0/24 next-hop self" }), "community"},
		"well-known":        {with(func(r *extpolicy.Route) { r.Communities[1] = "65535:666" }), "reserved"},
		"unmasked":          {with(func(r *extpolicy.Route) { r.Prefix = netip.MustParsePrefix("198.51.100.7/24") }), "masked"},
		"no prefix":         {with(func(r *extpolicy.Route) { r.Prefix = netip.Prefix{} }), "masked"},
		"outside -allow":    {with(func(r *extpolicy.Route) { r.Prefix = netip.MustParsePrefix("203.0.113.0/24") }), "-allow"},
		"wider than -allow": {with(func(r *extpolicy.Route) { r.Prefix = netip.MustParsePrefix("198.51.0.0/16") }), "-allow"},
		"zone": {with(func(r *extpolicy.Route) {
			r.Prefix, r.NextHop = route6.Prefix, netip.MustParseAddr("fe80::1%x;\nprotocol")
		}), "next hop"},
		"family":               {with(func(r *extpolicy.Route) { r.NextHop = netip.MustParseAddr("2001:db8::22") }), "next hop"},
		"unspecified next hop": {with(func(r *extpolicy.Route) { r.NextHop = netip.IPv4Unspecified() }), "next hop"},
		"no next hop":          {with(func(r *extpolicy.Route) { r.NextHop = netip.Addr{} }), "next hop"},
	} {
		if _, err := allow.route(c.r); err == nil || !strings.Contains(err.Error(), c.err) {
			t.Errorf("%s: %v, want %q", name, err, c.err)
		}
	}

	out := &recorder{}
	noExport := with(func(r *extpolicy.Route) {
		r.Prefix = netip.MustParsePrefix("198.51.100.128/25")
		r.Communities = []string{"64512:666"}
	})
	c := &consumer{
		fetch: func(context.Context, uint64, bool) (extpolicy.Document, error) {
			return extpolicy.Document{ExpiresInMS: 10_000, Routes: []extpolicy.Route{noExport, route4}}, nil
		},
		out: out, check: allow, log: quiet(), now: time.Now,
	}
	if err := c.step(context.Background()); err != nil {
		t.Fatal(err)
	}
	if len(out.last()) != 1 || out.last()[0].Prefix != route4.Prefix {
		t.Fatalf("applied %+v, want only %s: the route without NO_EXPORT is dropped", out.last(), route4.Prefix)
	}
}

// The expiry guard in render mode: the file left by a previous run is
// rendered empty before the feed is read, and a feed that goes stale is
// rendered empty at its expiry.
func TestRenderExpiryGuard(t *testing.T) {
	dir := t.TempDir()
	out := filepath.Join(dir, "routes.conf")
	r, err := newRenderer(filepath.Join("..", "..", "examples", "external-policy", "bird.conf.tmpl"), out, "")
	if err != nil {
		t.Fatal(err)
	}
	if err := r.apply(context.Background(), []extpolicy.Route{route4}); err != nil {
		t.Fatal(err)
	}
	routes := func() int {
		t.Helper()
		b, err := os.ReadFile(out)
		if err != nil {
			t.Fatal(err)
		}
		return strings.Count(string(b), "\troute ")
	}
	if routes() != 1 {
		t.Fatal("setup: the previous run's route is not in the file")
	}
	now := time.Unix(1_800_000_000, 0)
	reached := false
	fetchErr := errors.New("connection refused")
	c := &consumer{
		fetch: func(context.Context, uint64, bool) (extpolicy.Document, error) {
			reached = true
			if routes() != 0 {
				t.Error("the feed was read before the stale file was rendered empty")
			}
			return extpolicy.Document{ExpiresInMS: 5000, Routes: []extpolicy.Route{route4}}, fetchErr
		},
		out: r, check: labCheck, log: quiet(), now: func() time.Time { return now },
	}
	ctx := context.Background()
	_ = c.step(ctx)
	if !reached || routes() != 0 {
		t.Fatalf("start with the feed down: %d routes rendered", routes())
	}
	fetchErr = nil
	_ = c.step(ctx)
	if routes() != 1 {
		t.Fatal("the feed's route was not rendered")
	}
	c.fetch = func(context.Context, uint64, bool) (extpolicy.Document, error) {
		return extpolicy.Document{}, errors.New("timeout")
	}
	now = now.Add(4 * time.Second)
	_ = c.step(ctx)
	if routes() != 1 {
		t.Fatal("dropped before the expiry")
	}
	now = now.Add(time.Second)
	_ = c.step(ctx)
	if routes() != 0 {
		t.Fatalf("a stale feed left %d routes in the file after its expiry", routes())
	}
}

// A hung reload ends at the timeout, so the loop goes on to the expiry.
func TestRenderReloadTimeout(t *testing.T) {
	dir := t.TempDir()
	r, err := newRenderer(filepath.Join("..", "..", "examples", "external-policy", "bird.conf.tmpl"), filepath.Join(dir, "routes.conf"), "sleep 30")
	if err != nil {
		t.Fatal(err)
	}
	r.reloadTimeout = 100 * time.Millisecond
	start := time.Now()
	if err := r.apply(context.Background(), nil); err == nil || time.Since(start) > 5*time.Second {
		t.Fatalf("hung reload: %v after %s", err, time.Since(start))
	}
}
