package extpolicy

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"io"
	"net/http"
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
	for _, tok := range []string{"", "wrong-token-0123456789"} {
		if resp := do(http.MethodGet, tok); resp.StatusCode != http.StatusUnauthorized {
			t.Errorf("token %q: status %d", tok, resp.StatusCode)
		}
	}
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
