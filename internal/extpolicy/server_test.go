package extpolicy

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
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
	ca := pkitest.New(t)
	leaf := ca.Issue(t, "packeteer")
	srv, err := NewServer(feed, ServerConfig{Listen: "127.0.0.1:0", CertFile: leaf.CertFile, KeyFile: leaf.KeyFile, Token: testToken}, quiet())
	if err != nil {
		t.Fatal(err)
	}
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
	if resp := do(http.MethodGet, "wrong-token-0123456789"); resp.StatusCode != http.StatusUnauthorized {
		t.Errorf("wrong token: status %d", resp.StatusCode)
	}
	// The wrong token started a backoff: even the right token is refused
	// until it ends, without being compared.
	if resp := do(http.MethodGet, testToken); resp.StatusCode != http.StatusTooManyRequests || resp.Header.Get("Retry-After") != "1" {
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

// The listener holds at most maxConns connections; one more waits until a
// connection closes. An authorized long poll is not cut by a timeout.
func TestServerConnCap(t *testing.T) {
	feed := New(true, 6*time.Second, nil)
	feed.Touch(time.Now(), nil)
	srv, tlsCfg := startServer(t, feed)
	if srv.srv.IdleTimeout != idleTimeout || srv.srv.ReadTimeout != 0 || srv.srv.WriteTimeout != 0 {
		t.Errorf("timeouts: idle %s, read %s, write %s", srv.srv.IdleTimeout, srv.srv.ReadTimeout, srv.srv.WriteTimeout)
	}
	var held []net.Conn
	defer func() {
		for _, c := range held {
			c.Close()
		}
	}()
	for range maxConns {
		c, err := net.Dial("tcp", srv.Addr())
		if err != nil {
			t.Fatal(err)
		}
		held = append(held, c)
	}
	get := func(timeout time.Duration, query string) (int, error) {
		client := &http.Client{Transport: &http.Transport{TLSClientConfig: tlsCfg}, Timeout: timeout}
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
	if code, err := get(500*time.Millisecond, ""); err == nil {
		t.Fatalf("connection %d was served (status %d)", maxConns+1, code)
	}
	held[0].Close()
	held = held[1:]
	if code, err := get(5*time.Second, ""); err != nil || code != http.StatusOK {
		t.Fatalf("after a connection closed: %d %v", code, err)
	}
	for _, c := range held {
		c.Close()
	}
	held = nil
	start := time.Now()
	if code, err := get(10*time.Second, "?wait="+strconv.FormatUint(feed.Document().Revision, 10)); err != nil || code != http.StatusOK || time.Since(start) < 1500*time.Millisecond {
		t.Errorf("long poll: %d %v after %s, want the 2s heartbeat", code, err, time.Since(start))
	}
}
