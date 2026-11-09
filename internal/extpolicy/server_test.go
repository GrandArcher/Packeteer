package extpolicy

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptrace"
	"net/netip"
	"os"
	"strconv"
	"strings"
	"testing"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/emptypb"
	"google.golang.org/protobuf/types/known/structpb"

	"github.com/GrandArcher/Packeteer/internal/agentwire/pkitest"
	"github.com/GrandArcher/Packeteer/pkg/plugin"
)

const testToken = "lab-only-token-0123456789"

var loopback = netip.MustParseAddr("127.0.0.1")

func startServer(t *testing.T, feed *Feed) (*Server, *tls.Config) {
	t.Helper()
	return startServerAuthWait(t, feed, authDeadline)
}

func startServerAuthWait(t *testing.T, feed *Feed, authWait time.Duration) (*Server, *tls.Config) {
	t.Helper()
	ca := pkitest.New(t)
	leaf := ca.Issue(t, "packeteer")
	srv, err := NewServer(feed, ServerConfig{Listen: "127.0.0.1:0", CertFile: leaf.CertFile, KeyFile: leaf.KeyFile, Token: testToken}, quiet())
	if err != nil {
		t.Fatal(err)
	}
	srv.authWait = authWait
	if err := srv.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = srv.Shutdown(ctx)
	})
	pem, err := os.ReadFile(ca.CAFile)
	if err != nil {
		t.Fatal(err)
	}
	pool := x509.NewCertPool()
	pool.AppendCertsFromPEM(pem)
	return srv, &tls.Config{RootCAs: pool, ServerName: "127.0.0.1", MinVersion: tls.VersionTLS12}
}

func TestServerConfigChecks(t *testing.T) {
	ca := pkitest.New(t)
	leaf := ca.Issue(t, "packeteer")
	if _, err := NewServer(New(true, time.Minute, nil), ServerConfig{Listen: "127.0.0.1:0", CertFile: leaf.CertFile, KeyFile: leaf.KeyFile, Token: "short"}, quiet()); err == nil || !strings.Contains(err.Error(), "at least") {
		t.Errorf("short token: %v", err)
	}
	if _, err := NewServer(New(true, time.Minute, nil), ServerConfig{Listen: "127.0.0.1:0", CertFile: leaf.CertFile, KeyFile: "/nonexistent", Token: testToken}, quiet()); err == nil {
		t.Error("missing key file accepted")
	}
}

// The JSON document is served over TLS behind the token and is read-only.
func TestServerJSON(t *testing.T) {
	feed := New(true, 30*time.Second, nil)
	feed.set(plugin.Route{Prefix: pA, Provider: "transit-b", NextHop: nhB, LocalPref: 250, Communities: []string{"64512:666"}})
	feed.Touch(time.Now(), nil)
	srv, tlsCfg := startServer(t, feed)
	client := &http.Client{Transport: &http.Transport{TLSClientConfig: tlsCfg}, Timeout: 5 * time.Second}
	url := "https://" + srv.Addr() + DocumentPath
	do := func(method, token string) *http.Response {
		t.Helper()
		req, _ := http.NewRequest(method, url, nil)
		if token != "" {
			req.Header.Set("Authorization", "Bearer "+token)
		}
		resp, err := client.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { resp.Body.Close() })
		return resp
	}
	if resp := do(http.MethodGet, "wrong-token-0123456789"); resp.StatusCode != http.StatusUnauthorized || !resp.Close {
		t.Errorf("wrong token: status %d, connection kept %v", resp.StatusCode, !resp.Close)
	}
	// The wrong token started a backoff: even the right token is refused
	// until it ends, without being compared.
	if resp := do(http.MethodGet, testToken); resp.StatusCode != http.StatusTooManyRequests || resp.Header.Get("Retry-After") != "1" || !resp.Close {
		t.Errorf("right token during the backoff: status %d, Retry-After %q", resp.StatusCode, resp.Header.Get("Retry-After"))
	}
	srv.bad.ok(loopback)
	if resp := do(http.MethodGet, ""); resp.StatusCode != http.StatusUnauthorized {
		t.Errorf("no token: status %d", resp.StatusCode)
	}
	srv.bad.ok(loopback)
	if resp := do(http.MethodPost, testToken); resp.StatusCode != http.StatusMethodNotAllowed {
		t.Errorf("POST: status %d", resp.StatusCode)
	}
	resp := do(http.MethodGet, testToken)
	var doc Document
	if err := json.NewDecoder(resp.Body).Decode(&doc); err != nil || resp.StatusCode != http.StatusOK {
		t.Fatalf("GET: %d %v", resp.StatusCode, err)
	}
	if len(doc.Routes) != 1 || doc.Routes[0].Prefix != pA || doc.Routes[0].NextHop != nhB || doc.ExpiresInMS <= 0 {
		t.Fatalf("document %+v", doc)
	}
	if plain, err := client.Get("http://" + srv.Addr() + DocumentPath); err == nil {
		body, _ := io.ReadAll(plain.Body)
		plain.Body.Close()
		if plain.StatusCode != http.StatusBadRequest || strings.Contains(string(body), "routes") {
			t.Errorf("plain HTTP: status %d %q", plain.StatusCode, body)
		}
	}
}

func watch(t *testing.T, srv *Server, tlsCfg *tls.Config, token string) (grpc.ClientStream, func()) {
	t.Helper()
	conn, err := grpc.NewClient(srv.Addr(), grpc.WithTransportCredentials(credentials.NewTLS(tlsCfg)))
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	ctx = metadata.AppendToOutgoingContext(ctx, "authorization", "Bearer "+token)
	st, err := conn.NewStream(ctx, &grpc.StreamDesc{ServerStreams: true}, "/"+ServiceName+"/"+WatchMethod)
	if err != nil {
		t.Fatal(err)
	}
	if err := st.SendMsg(&emptypb.Empty{}); err != nil {
		t.Fatal(err)
	}
	if err := st.CloseSend(); err != nil {
		t.Fatal(err)
	}
	return st, func() { cancel(); conn.Close() }
}

func recvDoc(t *testing.T, st grpc.ClientStream) (Document, error) {
	t.Helper()
	msg := new(structpb.Struct)
	if err := st.RecvMsg(msg); err != nil {
		return Document{}, err
	}
	b, err := json.Marshal(msg.AsMap())
	if err != nil {
		t.Fatal(err)
	}
	var d Document
	if err := json.Unmarshal(b, &d); err != nil {
		t.Fatal(err)
	}
	return d, nil
}

// The stream sends the document at once and on every change, and the
// empty, expired set when the feed closes, then ends.
func TestServerWatch(t *testing.T) {
	feed := New(true, 30*time.Second, nil)
	feed.Touch(time.Now(), nil)
	srv, tlsCfg := startServer(t, feed)

	st, stop := watch(t, srv, tlsCfg, "wrong-token-0123456789")
	if _, err := recvDoc(t, st); status.Code(err) != codes.Unauthenticated {
		t.Errorf("wrong token: %v", err)
	}
	stop()
	srv.bad.ok(loopback)

	st, stop = watch(t, srv, tlsCfg, testToken)
	defer stop()
	d, err := recvDoc(t, st)
	if err != nil || len(d.Routes) != 0 || d.ExpiresInMS <= 0 {
		t.Fatalf("first message %+v, %v", d, err)
	}
	feed.set(plugin.Route{Prefix: pA, Provider: "transit-b", NextHop: nhB, LocalPref: 250, Communities: []string{"64512:666"}})
	feed.Touch(time.Now(), nil)
	d, err = recvDoc(t, st)
	if err != nil || len(d.Routes) != 1 || d.Routes[0].Prefix != pA || d.Revision != 1 {
		t.Fatalf("after a change %+v, %v", d, err)
	}
	feed.Close()
	d, err = recvDoc(t, st)
	if err != nil || len(d.Routes) != 0 || d.ExpiresInMS != 0 {
		t.Fatalf("after close %+v, %v", d, err)
	}
	if _, err := recvDoc(t, st); !errors.Is(err, io.EOF) {
		t.Errorf("stream did not end after close: %v", err)
	}
}

// Between changes the stream resends the document every heartbeat, so a
// consumer sees the renewed expiry.
func TestServerWatchHeartbeat(t *testing.T) {
	feed := New(true, 3*time.Second, nil)
	feed.Touch(time.Now(), nil)
	srv, tlsCfg := startServer(t, feed)
	st, stop := watch(t, srv, tlsCfg, testToken)
	defer stop()
	if _, err := recvDoc(t, st); err != nil {
		t.Fatal(err)
	}
	start := time.Now()
	d, err := recvDoc(t, st)
	if err != nil {
		t.Fatal(err)
	}
	if gap := time.Since(start); gap < 500*time.Millisecond || d.HeartbeatMS != 1000 {
		t.Errorf("heartbeat after %s, heartbeat_ms %d", gap, d.HeartbeatMS)
	}
}

// ?wait=N answers as soon as the revision is not N, and after a heartbeat
// when nothing changes.
func TestServerLongPoll(t *testing.T) {
	feed := New(true, 3*time.Second, nil)
	feed.Touch(time.Now(), nil)
	srv, tlsCfg := startServer(t, feed)
	client := &http.Client{Transport: &http.Transport{TLSClientConfig: tlsCfg}, Timeout: 30 * time.Second}
	get := func(query string) (Document, int, time.Duration) {
		t.Helper()
		req, _ := http.NewRequest(http.MethodGet, "https://"+srv.Addr()+DocumentPath+query, nil)
		req.Header.Set("Authorization", "Bearer "+testToken)
		start := time.Now()
		resp, err := client.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		var d Document
		_ = json.NewDecoder(resp.Body).Decode(&d)
		return d, resp.StatusCode, time.Since(start)
	}
	if _, code, _ := get("?wait=x"); code != http.StatusBadRequest {
		t.Errorf("bad wait: status %d", code)
	}
	if d, _, took := get("?wait=99"); d.Revision != 0 || took > time.Second {
		t.Errorf("other revision: %+v after %s, want an answer at once", d, took)
	}
	if _, _, took := get("?wait=0"); took < 800*time.Millisecond {
		t.Errorf("no change answered after %s, want the 1s heartbeat", took)
	}
	// A longer heartbeat, so the change below must beat it by a wide margin.
	feed.SetRuntime(true, 30*time.Second)
	go func() {
		time.Sleep(200 * time.Millisecond)
		feed.set(plugin.Route{Prefix: pA, Provider: "transit-b", NextHop: nhB, LocalPref: 250, Communities: []string{"64512:666"}})
		feed.Touch(time.Now(), nil)
	}()
	feedNow := feed.Document().Revision
	d, _, took := get("?wait=" + strconv.FormatUint(feedNow, 10))
	if len(d.Routes) != 1 || d.Revision == feedNow || took > 5*time.Second {
		t.Errorf("change: %+v after %s, want the new route before the heartbeat", d, took)
	}
}

// Each wrong token in a row doubles the time an address is refused, up to
// backoffMax; a right token clears it; an address is forgotten after
// backoffForget; the table stays bounded. IPv6 addresses share their /64.
func TestBackoff(t *testing.T) {
	now := time.Unix(1_800_000_000, 0)
	b := newBackoff(func() time.Time { return now })
	a := netip.MustParseAddr("192.0.2.1")
	if b.wait(a) != 0 {
		t.Fatal("a new address backs off")
	}
	if !b.fail(a) || b.wait(a) != time.Second {
		t.Fatalf("first failure: wait %s, want 1s and a log", b.wait(a))
	}
	if b.fail(a) || b.wait(a) != 2*time.Second {
		t.Fatalf("second failure: wait %s, want 2s and no second log", b.wait(a))
	}
	for range 10 {
		b.fail(a)
	}
	if b.wait(a) != backoffMax {
		t.Fatalf("wait %s, want the %s cap", b.wait(a), backoffMax)
	}
	now = now.Add(backoffMax)
	if b.wait(a) != 0 {
		t.Fatal("still refused after the backoff")
	}
	b.fail(a)
	if b.wait(a) != backoffMax {
		t.Fatalf("a failure soon after keeps the count: wait %s", b.wait(a))
	}
	b.ok(a)
	if b.wait(a) != 0 || !b.fail(a) || b.wait(a) != time.Second {
		t.Fatal("a right token did not clear the count")
	}
	now = now.Add(backoffForget)
	if !b.fail(a) || b.wait(a) != time.Second {
		t.Fatal("an address idle for backoffForget was not forgotten")
	}

	v6 := netip.MustParseAddr("2001:db8:1:2::1")
	b.fail(v6)
	if b.wait(netip.MustParseAddr("2001:db8:1:2::99")) != time.Second || b.wait(netip.MustParseAddr("2001:db8:1:3::1")) != 0 {
		t.Error("IPv6 backoff is not per /64")
	}

	b = newBackoff(func() time.Time { return now })
	for i := range maxBackoffKeys {
		b.fail(netip.AddrFrom4([4]byte{10, byte(i >> 16), byte(i >> 8), byte(i)}))
	}
	extra := netip.MustParseAddr("198.51.100.1")
	if b.fail(extra) || b.wait(extra) != 0 || len(b.fails) != maxBackoffKeys {
		t.Fatalf("a full table tracked a new address: %d entries", len(b.fails))
	}
	now = now.Add(backoffForget)
	if !b.fail(extra) || len(b.fails) != 1 {
		t.Fatalf("forgotten entries were not pruned: %d entries", len(b.fails))
	}
}

// dialFrom opens a TCP connection to addr from the loopback address
// 127.0.0.<host>, so tests can act as several clients.
func dialFrom(t *testing.T, host byte, addr string) net.Conn {
	t.Helper()
	d := net.Dialer{LocalAddr: &net.TCPAddr{IP: net.IPv4(127, 0, 0, host)}, Timeout: 5 * time.Second}
	c, err := d.Dial("tcp", addr)
	if err != nil {
		t.Skipf("dial from 127.0.0.%d (needs all of 127.0.0.0/8 on loopback): %v", host, err)
	}
	return c
}

// getFrom sends an authorized GET from 127.0.0.<host>.
func getFrom(srv *Server, tlsCfg *tls.Config, host byte, timeout time.Duration, query string) (int, error) {
	d := &net.Dialer{LocalAddr: &net.TCPAddr{IP: net.IPv4(127, 0, 0, host)}}
	client := &http.Client{Transport: &http.Transport{TLSClientConfig: tlsCfg, DialContext: d.DialContext}, Timeout: timeout}
	defer client.CloseIdleConnections()
	req, _ := http.NewRequest(http.MethodGet, "https://"+srv.Addr()+DocumentPath+query, nil)
	req.Header.Set("Authorization", "Bearer "+testToken)
	resp, err := client.Do(req)
	if err != nil {
		return 0, err
	}
	defer resp.Body.Close()
	return resp.StatusCode, nil
}

// closedByServer reports whether the server closes c within d.
func closedByServer(c net.Conn, d time.Duration) bool {
	_ = c.SetReadDeadline(time.Now().Add(d))
	_, err := c.Read(make([]byte, 1))
	var ne net.Error
	return err != nil && !(errors.As(err, &ne) && ne.Timeout())
}

// waitOpen waits up to 3s for ok to hold for the per-address counts.
func waitOpen(t *testing.T, srv *Server, ok func(map[netip.Prefix]int) bool) {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for {
		srv.ln.mu.Lock()
		done := ok(srv.ln.open)
		open := fmt.Sprint(srv.ln.open)
		srv.ln.mu.Unlock()
		if done {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("connection counts %s, %d slots taken", open, len(srv.ln.sem))
		}
		time.Sleep(10 * time.Millisecond)
	}
}

// The listener holds at most maxConns connections; one more waits until a
// connection closes. An authorized long poll is not cut by a timeout.
func TestServerConnCap(t *testing.T) {
	feed := New(true, 6*time.Second, nil)
	feed.Touch(time.Now(), nil)
	srv, tlsCfg := startServerAuthWait(t, feed, time.Minute)
	if srv.srv.IdleTimeout != idleTimeout || srv.srv.ReadTimeout != 0 || srv.srv.WriteTimeout != 0 {
		t.Errorf("timeouts: idle %s, read %s, write %s", srv.srv.IdleTimeout, srv.srv.ReadTimeout, srv.srv.WriteTimeout)
	}
	var held []net.Conn
	defer func() {
		for _, c := range held {
			c.Close()
		}
	}()
	for i := range maxConns {
		held = append(held, dialFrom(t, byte(2+i/maxConnsPerAddr), srv.Addr()))
	}
	if code, err := getFrom(srv, tlsCfg, 100, 500*time.Millisecond, ""); err == nil {
		t.Fatalf("connection %d was served (status %d)", maxConns+1, code)
	}
	held[0].Close()
	held = held[1:]
	if code, err := getFrom(srv, tlsCfg, 100, 5*time.Second, ""); err != nil || code != http.StatusOK {
		t.Fatalf("after a connection closed: %d %v", code, err)
	}
	for _, c := range held {
		c.Close()
	}
	held = nil
	start := time.Now()
	if code, err := getFrom(srv, tlsCfg, 1, 10*time.Second, "?wait="+strconv.FormatUint(feed.Document().Revision, 10)); err != nil || code != http.StatusOK || time.Since(start) < 1500*time.Millisecond {
		t.Errorf("long poll: %d %v after %s, want the 2s heartbeat", code, err, time.Since(start))
	}
}

// One address holds at most maxConnsPerAddr connections that have not
// carried a right token. One more from it is closed at once and takes no
// slot, so another address is still served. Authorized connections do not
// count against their address.
func TestServerConnPerAddr(t *testing.T) {
	feed := New(true, 6*time.Second, nil)
	feed.Touch(time.Now(), nil)
	srv, tlsCfg := startServerAuthWait(t, feed, time.Minute)
	var held []net.Conn
	defer func() {
		for _, c := range held {
			c.Close()
		}
	}()
	for range maxConnsPerAddr {
		held = append(held, dialFrom(t, 2, srv.Addr()))
	}
	extra := dialFrom(t, 2, srv.Addr())
	defer extra.Close()
	if !closedByServer(extra, 2*time.Second) {
		t.Fatal("a connection over the per-address cap stayed open")
	}
	if code, err := getFrom(srv, tlsCfg, 2, 2*time.Second, ""); err == nil {
		t.Fatalf("the full address was served (status %d)", code)
	}
	// Each client leaves its authorized connection open and idle.
	for i := range maxConnsPerAddr + 1 {
		d := &net.Dialer{LocalAddr: &net.TCPAddr{IP: net.IPv4(127, 0, 0, 3)}}
		tr := &http.Transport{TLSClientConfig: tlsCfg, DialContext: d.DialContext}
		defer tr.CloseIdleConnections()
		req, _ := http.NewRequest(http.MethodGet, "https://"+srv.Addr()+DocumentPath, nil)
		req.Header.Set("Authorization", "Bearer "+testToken)
		resp, err := (&http.Client{Transport: tr, Timeout: 5 * time.Second}).Do(req)
		if err != nil {
			t.Fatalf("authorized connection %d from another address: %v", i+1, err)
		}
		_, _ = io.Copy(io.Discard, resp.Body)
		resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("authorized connection %d from another address: status %d", i+1, resp.StatusCode)
		}
	}
	srv.ln.mu.Lock()
	n := srv.ln.open[netip.MustParsePrefix("127.0.0.3/32")]
	srv.ln.mu.Unlock()
	if n != 0 {
		t.Errorf("%d authorized connections count against their address", n)
	}
	held[0].Close()
	held = held[1:]
	waitOpen(t, srv, func(open map[netip.Prefix]int) bool {
		return open[netip.MustParsePrefix("127.0.0.2/32")] < maxConnsPerAddr
	})
	if code, err := getFrom(srv, tlsCfg, 2, 5*time.Second, ""); err != nil || code != http.StatusOK {
		t.Fatalf("after one of its connections closed: %d %v", code, err)
	}
}

// A connection without a right token is closed after authWait, whether it
// stalls before TLS or idles after the handshake, and gives its slot back.
// A connection that carried a right token stays: an HTTP/1 keep-alive is
// reused and a gRPC stream keeps sending heartbeats.
func TestServerAuthDeadline(t *testing.T) {
	const wait = 300 * time.Millisecond
	feed := New(true, 3*time.Second, nil)
	feed.Touch(time.Now(), nil)
	srv, tlsCfg := startServerAuthWait(t, feed, wait)

	raw := dialFrom(t, 2, srv.Addr())
	defer raw.Close()
	h2 := tlsCfg.Clone()
	h2.NextProtos = []string{"h2"}
	tc, err := tls.Dial("tcp", srv.Addr(), h2)
	if err != nil {
		t.Fatal(err)
	}
	defer tc.Close()
	if _, err := tc.Write([]byte("PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n")); err != nil {
		t.Fatal(err)
	}
	start := time.Now()
	if !closedByServer(raw, 3*time.Second) {
		t.Error("a silent TCP connection stayed open")
	}
	if took := time.Since(start); took > 2*time.Second {
		t.Errorf("silent TCP connection closed after %s, want about %s", took, wait)
	}
	_ = tc.SetReadDeadline(time.Now().Add(3 * time.Second))
	if _, err := io.Copy(io.Discard, tc); err != nil {
		var ne net.Error
		if errors.As(err, &ne) && ne.Timeout() {
			t.Error("an HTTP/2 connection without a request stayed open")
		}
	}
	// The one slot left is the one Accept holds while it waits.
	waitOpen(t, srv, func(open map[netip.Prefix]int) bool { return len(open) == 0 && len(srv.ln.sem) <= 1 })

	var reused []bool
	client := &http.Client{Transport: &http.Transport{TLSClientConfig: tlsCfg}, Timeout: 5 * time.Second}
	defer client.CloseIdleConnections()
	for range 2 {
		req, _ := http.NewRequest(http.MethodGet, "https://"+srv.Addr()+DocumentPath, nil)
		req.Header.Set("Authorization", "Bearer "+testToken)
		req = req.WithContext(httptrace.WithClientTrace(req.Context(), &httptrace.ClientTrace{GotConn: func(i httptrace.GotConnInfo) { reused = append(reused, i.Reused) }}))
		resp, err := client.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		_, _ = io.Copy(io.Discard, resp.Body)
		resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("authorized GET: status %d", resp.StatusCode)
		}
		time.Sleep(2 * wait)
	}
	if len(reused) != 2 || !reused[1] {
		t.Errorf("authorized keep-alive connection not reused after the deadline: %v", reused)
	}

	// The earlier steps outlast the 3s TTL on a slow runner, and an expired
	// feed ends the stream.
	feed.Touch(time.Now(), nil)
	st, stop := watch(t, srv, tlsCfg, testToken)
	defer stop()
	for i := range 2 {
		if _, err := recvDoc(t, st); err != nil {
			t.Fatalf("authorized stream message %d: %v", i, err)
		}
	}
}
