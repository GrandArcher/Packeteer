package main

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/netip"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/metadata"
	"google.golang.org/protobuf/types/known/emptypb"
	"google.golang.org/protobuf/types/known/structpb"

	"github.com/GrandArcher/Packeteer/internal/agentwire/pkitest"
	"github.com/GrandArcher/Packeteer/internal/announce"
	"github.com/GrandArcher/Packeteer/internal/config"
	"github.com/GrandArcher/Packeteer/internal/extpolicy"
	"github.com/GrandArcher/Packeteer/internal/policy"
	"github.com/GrandArcher/Packeteer/pkg/plugin"
)

const feedToken = "lab-only-token-0123456789"

// feedLab is a feed listener with a throwaway CA.
type feedLab struct {
	addr  string
	block string
	tls   *tls.Config
}

func newFeedLab(t *testing.T, enabled bool) feedLab {
	t.Helper()
	ca := pkitest.New(t)
	leaf := ca.Issue(t, "packeteer")
	pem, err := os.ReadFile(ca.CAFile)
	if err != nil {
		t.Fatal(err)
	}
	pool := x509.NewCertPool()
	pool.AppendCertsFromPEM(pem)
	addr := fmt.Sprintf("127.0.0.1:%d", freePort(t))
	return feedLab{
		addr: addr,
		block: fmt.Sprintf("external_policy: {enabled: %t, listen: %q, cert_file: %q, key_file: %q, ttl: 3s}\n",
			enabled, addr, leaf.CertFile, leaf.KeyFile),
		tls: &tls.Config{RootCAs: pool, ServerName: "127.0.0.1", MinVersion: tls.VersionTLS12},
	}
}

func (f feedLab) doc(t *testing.T) (extpolicy.Document, error) {
	t.Helper()
	req, _ := http.NewRequest(http.MethodGet, "https://"+f.addr+extpolicy.DocumentPath, nil)
	req.Header.Set("Authorization", "Bearer "+feedToken)
	client := &http.Client{Transport: &http.Transport{TLSClientConfig: f.tls}, Timeout: 3 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return extpolicy.Document{}, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return extpolicy.Document{}, errors.New(resp.Status)
	}
	var d extpolicy.Document
	return d, json.NewDecoder(resp.Body).Decode(&d)
}

// waitDoc polls the feed until cond holds.
func (f feedLab) waitDoc(t *testing.T, d *ixDaemon, what string, cond func(extpolicy.Document) bool) extpolicy.Document {
	t.Helper()
	deadline := time.Now().Add(30 * time.Second)
	for {
		doc, err := f.doc(t)
		if err == nil && cond(doc) {
			return doc
		}
		if time.Now().After(deadline) {
			d.fatalf("timed out waiting for the feed: %s (last %+v, %v)", what, doc, err)
		}
		time.Sleep(100 * time.Millisecond)
	}
}

// watch opens the gRPC stream and returns a receive function.
func (f feedLab) watch(t *testing.T) func() (extpolicy.Document, error) {
	t.Helper()
	conn, err := grpc.NewClient(f.addr, grpc.WithTransportCredentials(credentials.NewTLS(f.tls)))
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	t.Cleanup(func() { cancel(); conn.Close() })
	ctx = metadata.AppendToOutgoingContext(ctx, "authorization", "Bearer "+feedToken)
	st, err := conn.NewStream(ctx, &grpc.StreamDesc{ServerStreams: true}, "/"+extpolicy.ServiceName+"/"+extpolicy.WatchMethod)
	if err != nil {
		t.Fatal(err)
	}
	if err := st.SendMsg(&emptypb.Empty{}); err != nil {
		t.Fatal(err)
	}
	_ = st.CloseSend()
	return func() (extpolicy.Document, error) {
		msg := new(structpb.Struct)
		if err := st.RecvMsg(msg); err != nil {
			return extpolicy.Document{}, err
		}
		b, _ := json.Marshal(msg.AsMap())
		var d extpolicy.Document
		return d, json.Unmarshal(b, &d)
	}
}

const feedSteer = `thresholds: {min_loss_delta_pct: 1, min_rtt_delta_ms: 15}
allowlist: {prefixes: ["203.0.113.0/24", "198.51.100.0/24"]}
sources:
  - type: static
    config: {targets: [{prefix: 203.0.113.0/24}, {prefix: 198.51.100.0/24}]}
probers:
  - type: fixed
    config: {paths: [{provider: transit-a, rtt_ms: 80}, {provider: transit-b, rtt_ms: 10}]}
`

// steeredOnly reports a feed with exactly the inject route for
// 203.0.113.0/24: 198.51.100.0/24 is allowlisted and probed but no
// neighbor advertises it, so it must never be listed.
func steeredOnly(d extpolicy.Document) bool {
	if d.ExpiresInMS <= 0 || len(d.Routes) != 1 {
		return false
	}
	r := d.Routes[0]
	return r.Prefix.String() == "203.0.113.0/24" && r.Provider == "transit-b" && r.NextHop.String() == ixSteered &&
		r.LocalPref == 250 && slices.Equal(r.Communities, []string{"64512:666", extpolicy.NoExport})
}

// Beside the embedded announcer the feed lists exactly the route on the
// edge, and on shutdown an open stream gets the empty, expired set.
func TestExternalPolicyBesideInject(t *testing.T) {
	edge := newMSEdge(t)
	edge.advertise("203.0.113.0/24")
	feed := newFeedLab(t, true)
	d := startIX(t, edge, feedSteer+feed.block)
	d.waitWire("the injected route", routeVia("203.0.113.0/24", ixSteered, ixCommunity, ixNoExport))
	feed.waitDoc(t, d, "the inject route", steeredOnly)
	if w := d.edge.wire(); len(w) != 1 || len(w["203.0.113.0/24"].Comms) != 2 {
		d.fatalf("edge wire %v, want the one route the feed lists with the same two communities", w)
	}
	d.waitLog("announce=gobgp+external_policy")

	recv := feed.watch(t)
	if first, err := recv(); err != nil || !steeredOnly(first) {
		d.fatalf("first stream message %+v, %v", first, err)
	}
	d.stop()
	for {
		doc, err := recv()
		if err != nil {
			d.fatalf("the stream ended without the empty set: %v", err)
		}
		if len(doc.Routes) == 0 {
			if doc.ExpiresInMS != 0 {
				d.fatalf("shutdown document has time left: %+v", doc)
			}
			break
		}
	}
	if _, err := recv(); !errors.Is(err, io.EOF) {
		t.Errorf("stream after shutdown: %v", err)
	}
}

// With the feed and no announcer the session only learns: nothing reaches
// the edge over BGP while the feed carries the route inject would send.
func TestExternalPolicyFeedOnly(t *testing.T) {
	edge := newMSEdge(t)
	edge.advertise("203.0.113.0/24")
	feed := newFeedLab(t, true)
	httpPort := freePort(t)
	d := runIX(t, edge, httpPort, fmt.Sprintf(`mode: inject
asn: 64512
router_id: 192.0.2.10
packeteer_community: "64512:666"
local_pref: 250
hold_time: 1s
http: {listen: "127.0.0.1:%d"}
providers:
  - {name: transit-a, source_ip: 192.0.2.11, next_hop: 192.0.2.1}
  - {name: transit-b, source_ip: 192.0.2.12, next_hop: 192.0.2.2}
probe: {interval: 1s, timeout: 200ms, packets: 1}
bgp:
  neighbors:
    - {address: 127.0.0.1, port: %d, local_address: 127.0.0.2}
`, httpPort, edge.port)+feedSteer+feed.block)
	feed.waitDoc(t, d, "the inject route", steeredOnly)
	d.holdWire("no route on the BGP session", 2*time.Second, func(w map[string]ixRoute) bool { return len(w) == 0 })
	d.waitLog("announce=external_policy")
	d.stop()
	if _, err := feed.doc(t); err == nil {
		t.Error("the feed still answers after shutdown")
	}
}

// The token comes from the environment; without one the controller refuses
// to start rather than serve an open feed.
func TestExternalPolicyNeedsToken(t *testing.T) {
	feed := newFeedLab(t, true)
	path := filepath.Join(t.TempDir(), "c.yaml")
	writeFile(t, path, `mode: inject
asn: 64512
router_id: 192.0.2.10
packeteer_community: "64512:666"
local_pref: 250
hold_time: 1m
http: {listen: ""}
probe: {interval: 1s, timeout: 200ms}
thresholds: {min_loss_delta_pct: 1, min_rtt_delta_ms: 15}
providers:
  - {name: transit-a, source_ip: 192.0.2.11, next_hop: 192.0.2.1}
allowlist: {prefixes: ["198.51.100.0/24"]}
bgp:
  neighbors:
    - {address: 127.0.0.1, port: 1, local_address: 127.0.0.2}
probers:
  - type: fixed
    config: {paths: [{provider: transit-a, rtt_ms: 1}]}
`+feed.block)
	var out, errOut bytes.Buffer
	if code := run(context.Background(), []string{"-check", "-config", path}, noEnv, &out, &errOut); code != 0 ||
		!strings.Contains(out.String(), "announce: external_policy local_pref=250") {
		t.Fatalf("check: exit %d\n%s%s", code, out.String(), errOut.String())
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	errOut.Reset()
	if code := run(ctx, []string{"-config", path}, noEnv, &out, &errOut); code != 1 || !strings.Contains(errOut.String(), "token must be at least") {
		t.Fatalf("no token: exit %d\n%s", code, errOut.String())
	}
}

// enabled and ttl reload online; the listener, certificate, and token, and
// the block itself, need a restart. A reload that turns the feed off
// publishes the empty, expired set at once.
func TestExternalPolicyReload(t *testing.T) {
	base := `mode: observe
asn: 64512
router_id: 192.0.2.10
providers:
  - {name: transit-a, source_ip: 192.0.2.11, next_hop: 192.0.2.1}
external_policy: {enabled: true, listen: "127.0.0.1:9443", cert_file: c.pem, key_file: k.pem, ttl: 2m}
`
	cur := mustParse(t, base)
	swap := func(a, b string) *config.Config {
		t.Helper()
		if !strings.Contains(base, a) {
			t.Fatalf("no %q in the test config", a)
		}
		return mustParse(t, strings.Replace(base, a, b, 1))
	}
	for _, tc := range []struct {
		name        string
		next        *config.Config
		restart, on []string
	}{
		{"enabled", swap("enabled: true", "enabled: false"), nil, []string{"external_policy.enabled"}},
		{"ttl", swap("ttl: 2m", "ttl: 3m"), nil, []string{"external_policy.ttl"}},
		{"listen", swap("127.0.0.1:9443", "127.0.0.1:9444"), []string{"external_policy"}, nil},
		{"token_env", swap("ttl: 2m", "ttl: 2m, token_env: OTHER_TOKEN"), []string{"external_policy"}, nil},
		{"removed", mustParse(t, base[:strings.Index(base, "external_policy")]), []string{"external_policy"}, nil},
	} {
		restart, online := classify(cur, tc.next)
		if !slices.Equal(restart, tc.restart) || !slices.Equal(online, tc.on) {
			t.Errorf("%s: restart %v online %v, want %v %v", tc.name, restart, online, tc.restart, tc.on)
		}
	}

	now := time.Now()
	feed := extpolicy.New(true, 2*time.Minute, func() time.Time { return now })
	m := extpolicy.NewMirror(nil, feed)
	if err := m.Bind(nil, "64512:666"); err != nil {
		t.Fatal(err)
	}
	if err := m.Announce(context.Background(), plugin.Route{Prefix: netip.MustParsePrefix("203.0.113.0/24"), Provider: "transit-b", NextHop: netip.MustParseAddr(ixSteered), LocalPref: 250, Communities: []string{"64512:666"}}); err != nil {
		t.Fatal(err)
	}
	feed.Touch(now, nil)
	setPolicyFeed(feed, swap("enabled: true", "enabled: false"), quietLogger())
	if d := feed.Document(); len(d.Routes) != 0 || d.ExpiresInMS != 0 {
		t.Fatalf("off by reload: %+v", d)
	}
	setPolicyFeed(feed, swap("ttl: 2m", "ttl: 3m"), quietLogger())
	if d := feed.Document(); len(d.Routes) != 1 || d.ExpiresInMS != 180_000 {
		t.Fatalf("on with a new ttl: %+v", d)
	}
}

// A standby withdraws what is on the wire, and the feed it keeps serving
// is empty with time left, not the routes of an earlier term.
func TestFeedEmptyOnHAStandby(t *testing.T) {
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	p := netip.MustParsePrefix("203.0.113.0/24")
	feed := extpolicy.New(true, time.Minute, nil)
	m := extpolicy.NewMirror(&memAnn{}, feed)
	var leader atomic.Bool
	leader.Store(true)
	ctl, err := announce.New(announce.Config{
		Mode: "inject", LocalPref: 250, Community: "64512:666", MaxImprovements: 5, Leader: leader.Load,
		Allowlist: []netip.Prefix{p},
		NextHops:  map[string]netip.Addr{"b": netip.MustParseAddr("192.0.2.2")},
	}, m, readyRIB{p}, log)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	imps := []policy.Improvement{{Prefix: p, Provider: "b", Native: "a", Since: now, Reason: "faster"}}
	if err := ctl.Sync(context.Background(), imps); err != nil {
		t.Fatal(err)
	}
	feed.Touch(now, imps)
	if feed.Routes() != 1 {
		t.Fatalf("leader feed has %d routes, want 1", feed.Routes())
	}

	leader.Store(false)
	if _, err := standbyRound(now, ctl, nil, nil, log); err != nil {
		t.Fatal(err)
	}
	feed.Touch(now, nil)
	doc := feed.Document()
	if len(doc.Routes) != 0 || doc.ExpiresInMS <= 0 {
		t.Fatalf("standby feed: %d routes, expires in %d ms", len(doc.Routes), doc.ExpiresInMS)
	}
}
