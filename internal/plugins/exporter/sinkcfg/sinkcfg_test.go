package sinkcfg

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestTLS(t *testing.T) {
	if c, err := TLS(false, ""); c != nil || err != nil {
		t.Fatalf("off: %v %v", c, err)
	}
	if _, err := TLS(false, "/x.pem"); err == nil {
		t.Fatal("ca_file without tls must fail")
	}
	c, err := TLS(true, "")
	if err != nil || c == nil || c.RootCAs != nil {
		t.Fatalf("system roots: %v %v", c, err)
	}
	if _, err := TLS(true, "rel.pem"); err == nil || !strings.Contains(err.Error(), "absolute") {
		t.Fatalf("relative path: %v", err)
	}
	bad := filepath.Join(t.TempDir(), "bad.pem")
	if err := os.WriteFile(bad, []byte("not a cert"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := TLS(true, bad); err == nil || !strings.Contains(err.Error(), "no PEM") {
		t.Fatalf("junk PEM: %v", err)
	}
	if _, err := TLS(true, filepath.Join(t.TempDir(), "missing.pem")); err == nil {
		t.Fatal("missing file must fail")
	}
}

func TestCredentials(t *testing.T) {
	env := map[string]string{"U": "alice", "P": "pw"}
	get := func(k string) string { return env[k] }
	u, p, err := Credentials(get, "U", "P")
	if err != nil || u != "alice" || p != "pw" {
		t.Fatalf("got %q %q %v", u, p, err)
	}
	if u, p, err = Credentials(get, "", ""); err != nil || u != "" || p != "" {
		t.Fatalf("neither: %q %q %v", u, p, err)
	}
	for _, c := range [][2]string{{"U", ""}, {"", "P"}, {"U", "MISSING"}, {"bad name", "P"}} {
		if _, _, err := Credentials(get, c[0], c[1]); err == nil {
			t.Fatalf("%v must fail", c)
		}
	}
}

func TestHTTPURL(t *testing.T) {
	if u, err := HTTPURL("https://sink.example.net:8086/base"); err != nil || u.Host != "sink.example.net:8086" {
		t.Fatalf("valid: %v %v", u, err)
	}
	for _, raw := range []string{"", "grpc://c:4317", "http://", "http://u:p@c", "http://c/?a=b", "http://c/#f", "c:4318"} {
		if _, err := HTTPURL(raw); err == nil {
			t.Errorf("%q must fail", raw)
		}
	}
}

func TestPost(t *testing.T) {
	var got, ctype string
	status := http.StatusNoContent
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		got, ctype = string(b), r.Header.Get("Content-Type")
		w.WriteHeader(status)
		_, _ = w.Write([]byte("secret-prefix-echo"))
	}))
	defer srv.Close()
	h := http.Header{"Content-Type": {"text/plain"}}
	if err := Post(context.Background(), srv.Client(), srv.URL, h, []byte("a b=1")); err != nil || got != "a b=1" || ctype != "text/plain" {
		t.Fatalf("204: err %v body %q type %q", err, got, ctype)
	}
	status = http.StatusBadRequest
	err := Post(context.Background(), srv.Client(), srv.URL, h, nil)
	if err == nil || !strings.Contains(err.Error(), "400") || strings.Contains(err.Error(), "echo") {
		t.Fatalf("a 400 must be an error that does not carry the response body: %v", err)
	}
	srv.Close()
	if err := Post(context.Background(), srv.Client(), srv.URL, h, nil); err == nil {
		t.Fatal("a closed sink must be an error")
	}
}
