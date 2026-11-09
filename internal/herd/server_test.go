package herd

import (
	"crypto/tls"
	"encoding/json"
	"net"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/GrandArcher/Packeteer/internal/config"
)

func envelope(t *testing.T, b []byte) Envelope {
	t.Helper()
	var e Envelope
	if err := json.Unmarshal(b, &e); err != nil {
		t.Fatalf("envelope: %v\n%s", err, b)
	}
	return e
}

func TestServeSignedRecordsAndStatus(t *testing.T) {
	srv := newMember(t, 64501, nil)
	cli := testNode(t)
	srv.serve(cli)
	srv.seedN(3, 64510)
	c := client(cli, srv)

	code, _, body := get(t, c, srv.url()+PathRecords+"?origin_asn=64510&nonce=n1")
	if code != 200 {
		t.Fatalf("status %d: %s", code, body)
	}
	if err := verifyDocument(srv.node.pub, body); err != nil {
		t.Fatalf("response does not verify: %v", err)
	}
	env := envelope(t, body)
	if env.Member != srv.node.ID() || env.ASN != 64501 || env.Granularity != "origin_asn" || env.Query.Nonce != "n1" || env.Query.OriginASN != 64510 {
		t.Errorf("envelope = %+v", env)
	}
	if len(env.Records) != 3 {
		t.Fatalf("records = %d, want 3", len(env.Records))
	}
	// Ordered by prefix, provider ASN, then time: oldest first.
	if !env.Records[0].Time.Before(env.Records[2].Time) {
		t.Errorf("records not in time order: %v ... %v", env.Records[0].Time, env.Records[2].Time)
	}
	if env.Query.From == "" {
		t.Error("the effective from is not echoed")
	}

	code, _, body = get(t, c, srv.url()+PathStatus)
	if code != 200 || verifyDocument(srv.node.pub, body) != nil {
		t.Fatalf("status document: %d %s", code, body)
	}
	var st Status
	_ = json.Unmarshal(body, &st)
	if st.Granularity != "origin_asn" || st.Discovery != "query_only" || st.RetentionDays != 90 || st.Vantage != "US" || st.ASN != 64501 {
		t.Errorf("status = %+v", st)
	}

	// Every served response is audited with who asked and what.
	au := srv.auditLog()
	if len(au) != 1 || au[0].Puller != cli.ID() || au[0].Records != 3 || !strings.Contains(au[0].Query, "origin_asn=64510") {
		t.Errorf("audit = %+v", au)
	}
}

func TestQueryOnlyRefusesAnUnnamedList(t *testing.T) {
	srv := newMember(t, 64501, nil)
	cli := testNode(t)
	srv.serve(cli)
	srv.seedN(2, 64510)
	c := client(cli, srv)
	if code, _, _ := get(t, c, srv.url()+PathRecords); code != 400 {
		t.Errorf("query_only list: status %d, want 400", code)
	}

	listing := newMember(t, 64501, func(h *config.Herd) { h.Share.Discovery = config.HerdListing })
	listing.serve(cli)
	listing.seedN(2, 64510)
	code, _, body := get(t, client(cli, listing), listing.url()+PathRecords)
	if code != 200 || len(envelope(t, body).Records) != 2 {
		t.Errorf("listing: %d %s", code, body)
	}
}

func TestStrictParserRefusesBadRequests(t *testing.T) {
	srv := newMember(t, 64501, nil)
	cli := testNode(t)
	srv.serve(cli)
	c := client(cli, srv)
	for _, q := range []string{
		"origin_asn=64510&bogus=1",
		"origin_asn=64510&origin_asn=64511",
		"origin_asn=abc",
		"origin_asn=0",
		"prefix=198.51.100.7/24",
		"origin_asn=64510&match=covering",
		"origin_asn=64510&from=yesterday",
		"origin_asn=64510&limit=0",
		"origin_asn=64510&cursor=!!!",
		"origin_asn=64510&nonce=" + strings.Repeat("a", 65),
		"origin_asn=64510&nonce=" + strings.Repeat("a", 5000),
	} {
		if code, _, _ := get(t, c, srv.url()+PathRecords+"?"+q); code != 400 {
			t.Errorf("%.60q: status %d, want 400", q, code)
		}
	}
	if code, _, _ := get(t, c, srv.url()+PathStatus+"?x=1"); code != 400 {
		t.Errorf("status with a parameter: %d", code)
	}
	if code, _, _ := get(t, c, srv.url()+"/herd/v1/other"); code != 404 {
		t.Errorf("unknown path: %d", code)
	}
}

func TestUnpinnedClientIsRefusedInTheHandshake(t *testing.T) {
	srv := newMember(t, 64501, nil)
	known := testNode(t)
	srv.serve(known)
	stranger := testNode(t)
	c := client(stranger, srv)
	if _, err := c.Get(srv.url() + PathStatus); err == nil {
		t.Fatal("a client whose key is not pinned was served")
	}
	// A client with no certificate at all is refused too.
	bare := &http.Client{Timeout: 3 * time.Second, Transport: &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true, MinVersion: tls.VersionTLS13}}}
	if _, err := bare.Get(srv.url() + PathStatus); err == nil {
		t.Fatal("a client with no certificate was served")
	}
	if n := tripCount(srv.trips, "handshake_refused"); n < 1 {
		t.Errorf("handshake_refused trips = %d", n)
	}
	// The pinned client still works.
	if code, _, _ := get(t, client(known, srv), srv.url()+PathStatus); code != 200 {
		t.Errorf("pinned client: %d", code)
	}
}

func tripCount(t *Trips, limit string) uint64 {
	var n uint64
	for _, c := range t.Snapshot() {
		if c.Limit == limit {
			n += c.Count
		}
	}
	return n
}

func TestRateLimitsAnswer429WithRetryAfter(t *testing.T) {
	srv := newMember(t, 64501, func(h *config.Herd) {
		h.Limits.RatePerIdentity = 5
	})
	cli := testNode(t)
	srv.serve(cli)
	c := client(cli, srv)
	// The bucket holds five requests (the connection check on the way in
	// is the per-address bucket, which is larger).
	for i := range 5 {
		if code, _, _ := get(t, c, srv.url()+PathStatus); code != 200 {
			t.Fatalf("request %d: status %d", i, code)
		}
	}
	code, hdr, _ := get(t, c, srv.url()+PathStatus)
	if code != 429 || hdr.Get("Retry-After") == "" {
		t.Fatalf("over the identity rate: status %d Retry-After %q", code, hdr.Get("Retry-After"))
	}
	if tripCount(srv.trips, "rate_per_identity") != 1 {
		t.Errorf("trips = %+v", srv.trips.Snapshot())
	}
	// Time passes and the bucket refills.
	srv.setClock(t0.Add(30 * time.Second))
	if code, _, _ := get(t, c, srv.url()+PathStatus); code != 200 {
		t.Errorf("after the bucket refilled: %d", code)
	}
}

func TestCoveringQueriesCostMoreThanExactOnes(t *testing.T) {
	srv := newMember(t, 64501, func(h *config.Herd) {
		h.Share.Granularity = config.HerdRoute
		h.Limits.RatePerIdentity = 8
	})
	cli := testNode(t)
	srv.serve(cli)
	c := client(cli, srv)
	exact := srv.url() + PathRecords + "?prefix=198.51.100.0/24"
	wide := srv.url() + PathRecords + "?prefix=198.51.100.0/24&match=covering"
	// Eight tokens: two covering queries (4 each) use them all, where
	// exact ones would have allowed eight.
	for i := range 2 {
		if code, _, _ := get(t, c, wide); code != 200 {
			t.Fatalf("covering %d: %d", i, code)
		}
	}
	if code, _, _ := get(t, c, exact); code != 429 {
		t.Errorf("exact after two covering queries: %d, want 429", code)
	}
}

func TestGlobalRateAndPerAddressRate(t *testing.T) {
	srv := newMember(t, 64501, func(h *config.Herd) { h.Limits.RateGlobal = 4 })
	a, b := testNode(t), testNode(t)
	srv.serve(a, b)
	got := map[int]int{}
	for i := range 6 {
		node := a
		if i%2 == 1 {
			node = b
		}
		code, _, _ := get(t, client(node, srv), srv.url()+PathStatus)
		got[code]++
	}
	if got[200] != 4 || got[429] != 2 {
		t.Errorf("global rate 4 across two peers: %v", got)
	}
	if tripCount(srv.trips, "rate_global") != 2 {
		t.Errorf("trips = %+v", srv.trips.Snapshot())
	}

	// One address can only open so many connections: past the per-address
	// budget the connection is closed before the TLS handshake.
	addr := newMember(t, 64501, func(h *config.Herd) { h.Limits.RatePerAddress = 4 })
	addr.serve(a)
	refused := 0
	for range 8 {
		if _, err := client(a, addr).Get(addr.url() + PathStatus); err != nil {
			refused++
		}
	}
	if refused == 0 || tripCount(addr.trips, "rate_per_address") == 0 {
		t.Errorf("refused %d, trips %+v", refused, addr.trips.Snapshot())
	}
}

func TestConnectionCaps(t *testing.T) {
	srv := newMember(t, 64501, func(h *config.Herd) {
		h.Limits.MaxConnsPerPeer = 2
		h.Limits.MaxConns = 3
		h.Limits.RatePerAddress = 1000
	})
	a, b := testNode(t), testNode(t)
	srv.serve(a, b)
	open := func(n *Node) *tls.Conn {
		t.Helper()
		c, err := tls.Dial("tcp", srv.srv.Addr().String(), &tls.Config{MinVersion: tls.VersionTLS13, Certificates: []tls.Certificate{n.cert}, InsecureSkipVerify: true})
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = c.Close() })
		return c
	}
	closed := func(c *tls.Conn) bool {
		_ = c.SetReadDeadline(time.Now().Add(300 * time.Millisecond))
		_, err := c.Read(make([]byte, 1))
		ne, ok := err.(net.Error)
		return err != nil && !(ok && ne.Timeout())
	}
	// Server handshakes run concurrently and a TLS 1.3 client returns before
	// the server finishes, so wait until c1 and c2 are counted; otherwise c3
	// can win the race and one of them is the connection closed.
	c1, c2 := open(a), open(a)
	waitFor(t, func() bool {
		srv.srv.mu.Lock()
		defer srv.srv.mu.Unlock()
		return srv.srv.perID[KeyID(a.pub)] == 2
	})
	c3 := open(a) // over the per-peer cap: accepted by TLS 1.3 client, then closed
	if !closed(c3) {
		t.Error("third connection of one peer stayed open")
	}
	if tripCount(srv.trips, "max_conns_per_peer") != 1 {
		t.Errorf("trips = %+v", srv.trips.Snapshot())
	}
	c4 := open(b)
	if closed(c1) || closed(c2) || closed(c4) {
		t.Error("a connection within the caps was closed")
	}
	// Three are open (the cap): the next one is closed before the handshake.
	if _, err := tls.Dial("tcp", srv.srv.Addr().String(), &tls.Config{MinVersion: tls.VersionTLS13, Certificates: []tls.Certificate{b.cert}, InsecureSkipVerify: true}); err == nil {
		t.Error("a connection over max_conns completed")
	}
	if tripCount(srv.trips, "max_conns") == 0 {
		t.Errorf("trips = %+v", srv.trips.Snapshot())
	}
}

func TestRequestsPerConnectionAndSizeCaps(t *testing.T) {
	srv := newMember(t, 64501, func(h *config.Herd) {
		h.Limits.MaxRequestsPerConn = 2
		h.Limits.MaxRequestBytes = 512
	})
	cli := testNode(t)
	srv.serve(cli)
	c := &http.Client{Timeout: 5 * time.Second, Transport: &http.Transport{TLSClientConfig: &tls.Config{
		MinVersion: tls.VersionTLS13, Certificates: []tls.Certificate{cli.cert}, InsecureSkipVerify: true,
	}}}
	codes := []int{}
	for range 3 {
		code, _, _ := get(t, c, srv.url()+PathStatus)
		codes = append(codes, code)
	}
	if codes[0] != 200 || codes[1] != 200 || codes[2] != 429 {
		t.Errorf("codes on one connection = %v, want 200 200 429", codes)
	}
	// A query over max_request_bytes is refused before it is parsed.
	long := srv.url() + PathRecords + "?origin_asn=1&nonce=" + strings.Repeat("a", 600)
	if code, _, _ := get(t, client(cli, srv), long); code != http.StatusBadRequest {
		t.Errorf("oversized request: status %d, want 400", code)
	}
}

func TestSlowClientsAreCutOff(t *testing.T) {
	srv := newMember(t, 64501, func(h *config.Herd) { h.Limits.Timeout = time.Second })
	cli := testNode(t)
	srv.serve(cli)
	// Connects and never speaks: the handshake timeout closes it.
	raw, err := net.Dial("tcp", srv.srv.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer raw.Close()
	start := time.Now()
	_ = raw.SetReadDeadline(time.Now().Add(5 * time.Second))
	if _, err := raw.Read(make([]byte, 1)); err == nil {
		t.Fatal("read succeeded on a silent connection")
	}
	if d := time.Since(start); d > 3*time.Second {
		t.Errorf("silent connection held for %s with a 1s timeout", d)
	}

	// Handshakes complete, then the client sends half a request.
	c, err := tls.Dial("tcp", srv.srv.Addr().String(), &tls.Config{MinVersion: tls.VersionTLS13, Certificates: []tls.Certificate{cli.cert}, InsecureSkipVerify: true})
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	_, _ = c.Write([]byte("GET /herd/v1/status HTTP/1.1\r\nHost: x\r\n"))
	start = time.Now()
	_ = c.SetReadDeadline(time.Now().Add(5 * time.Second))
	_, _ = c.Read(make([]byte, 512))
	if d := time.Since(start); d > 3*time.Second {
		t.Errorf("half-sent request held for %s with a 1s timeout", d)
	}
}

func TestStandbyNodeServesNothing(t *testing.T) {
	srv := newMember(t, 64501, nil)
	cli := testNode(t)
	srv.serve(cli)
	srv.mu.Lock()
	srv.active = false
	srv.mu.Unlock()
	if code, _, _ := get(t, client(cli, srv), srv.url()+PathStatus); code != 503 {
		t.Errorf("standby status = %d, want 503", code)
	}
}

// The RIB view is checked when a record is served, not only when it is
// stored: a record whose route has left the view, or has no path through
// its provider any more, is neither previewed nor pulled.
func TestRecordIsServedOnlyWhileItsRouteIsLearned(t *testing.T) {
	a := newMember(t, 64501, nil)
	b := newMember(t, 64502, nil)
	a.rules.ASNs[64599] = true
	a.serve(b.node)
	rt := route("198.51.100.0/24", 64501, 64500, 64510)
	a.seed(a.mkRecord("r1", 64510, 64501, "198.51.100.0/24", t0.Add(-time.Minute), 10), rt)
	served := func() (previewed, pulled int) {
		t.Helper()
		code, body := a.srv.Preview("origin_asn=64510")
		if code != 200 {
			t.Fatalf("preview: %d %s", code, body)
		}
		gc, _, gb := get(t, client(b.node, a), a.url()+PathRecords+"?origin_asn=64510")
		if gc != 200 {
			t.Fatalf("pull: %d %s", gc, gb)
		}
		return len(envelope(t, body).Records), len(envelope(t, gb).Records)
	}
	set := func(f func(*fakeRIB)) {
		a.rib.mu.Lock()
		f(a.rib)
		a.rib.mu.Unlock()
	}
	if p, g := served(); p != 1 || g != 1 {
		t.Fatalf("route in the RIB view: previewed %d, pulled %d, want 1 and 1", p, g)
	}

	set(func(r *fakeRIB) { r.down = rt.Provider })
	if p, g := served(); p != 0 || g != 0 {
		t.Errorf("no path through the provider: previewed %d, pulled %d, want none", p, g)
	}
	set(func(r *fakeRIB) { r.down, r.ready = "", false })
	if p, g := served(); p != 0 || g != 0 {
		t.Errorf("RIB view not ready: previewed %d, pulled %d, want none", p, g)
	}
	set(func(r *fakeRIB) { r.ready = true; delete(r.paths, rt.Prefix) })
	if p, g := served(); p != 0 || g != 0 {
		t.Errorf("route left the RIB view: previewed %d, pulled %d, want none", p, g)
	}
	set(func(r *fakeRIB) { r.paths[rt.Prefix] = []uint32{64501, 64599, 64510} })
	if p, g := served(); p != 0 || g != 0 {
		t.Errorf("current path through an excluded ASN: previewed %d, pulled %d, want none", p, g)
	}
	set(func(r *fakeRIB) { r.paths[rt.Prefix] = rt.Path })
	if p, g := served(); p != 1 || g != 1 {
		t.Errorf("route learned again: previewed %d, pulled %d, want 1 and 1", p, g)
	}
}
