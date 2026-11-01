package geoip

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/GrandArcher/Packeteer/internal/config"
	"github.com/GrandArcher/Packeteer/internal/geoip/geoiptest"
)

var quiet = slog.New(slog.NewTextHandler(io.Discard, nil))

func labDB() []byte {
	return geoiptest.Build(map[string]string{"203.0.113.0/24": "XA", "2001:db8::/32": "XB"})
}

func gz(b []byte) []byte {
	var out bytes.Buffer
	w := gzip.NewWriter(&out)
	w.Write(b)
	w.Close()
	return out.Bytes()
}

func tgz(t *testing.T, files map[string][]byte, order ...string) []byte {
	t.Helper()
	var out bytes.Buffer
	zw := gzip.NewWriter(&out)
	tw := tar.NewWriter(zw)
	for _, name := range order {
		if err := tw.WriteHeader(&tar.Header{Name: name, Mode: 0o644, Size: int64(len(files[name])), Typeflag: tar.TypeReg}); err != nil {
			t.Fatal(err)
		}
		tw.Write(files[name])
	}
	tw.Close()
	zw.Close()
	return out.Bytes()
}

func newFetcher(t *testing.T, srvURL, user, key string) (*Fetcher, string) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "country.mmdb")
	f, err := NewFetcher(config.GeoIP{Path: path, URL: srvURL, Refresh: time.Hour}, user, key, quiet)
	if err != nil {
		t.Fatal(err)
	}
	return f, path
}

func networks(t *testing.T, path, cc string) []string {
	t.Helper()
	d, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	var out []string
	for _, v4 := range []bool{true, false} {
		ps, _ := d.Networks(cc, v4)
		for _, p := range ps {
			out = append(out, p.String())
		}
	}
	return out
}

func TestRefreshFormats(t *testing.T) {
	raw := labDB()
	archive := tgz(t, map[string][]byte{"GeoLite2-Country_20260101/COPYRIGHT.txt": []byte("x"), "GeoLite2-Country_20260101/GeoLite2-Country.mmdb": raw},
		"GeoLite2-Country_20260101/COPYRIGHT.txt", "GeoLite2-Country_20260101/GeoLite2-Country.mmdb")
	for name, body := range map[string][]byte{"raw": raw, "gzip": gz(raw), "tar.gz": archive} {
		t.Run(name, func(t *testing.T) {
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.Write(body) }))
			defer srv.Close()
			f, path := newFetcher(t, srv.URL, "", "")
			if err := f.Refresh(context.Background()); err != nil {
				t.Fatal(err)
			}
			if got := networks(t, path, "XA"); len(got) != 1 || got[0] != "203.0.113.0/24" {
				t.Fatalf("XA networks = %v", got)
			}
			if got := networks(t, path, "XB"); len(got) != 1 || got[0] != "2001:db8::/32" {
				t.Fatalf("XB networks = %v", got)
			}
			if st := f.Status(); st.LastError != "" || st.LastCheck.IsZero() {
				t.Fatalf("status = %+v", st)
			}
			if left, _ := filepath.Glob(filepath.Join(filepath.Dir(path), ".geoip-*")); len(left) != 0 {
				t.Fatalf("temp files left: %v", left)
			}
		})
	}
}

func TestRefreshBasicAuthAndConditional(t *testing.T) {
	modified := time.Date(2026, 10, 1, 12, 0, 0, 0, time.UTC)
	var calls atomic.Int32
	var lastIMS, lastUser, lastKey string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		lastUser, lastKey, _ = r.BasicAuth()
		lastIMS = r.Header.Get("If-Modified-Since")
		if lastIMS == modified.Format(http.TimeFormat) {
			w.WriteHeader(http.StatusNotModified)
			return
		}
		w.Header().Set("Last-Modified", modified.Format(http.TimeFormat))
		w.Write(labDB())
	}))
	defer srv.Close()
	f, path := newFetcher(t, srv.URL, "100001", "fake-key-not-real")
	if err := f.Refresh(context.Background()); err != nil {
		t.Fatal(err)
	}
	if lastUser != "100001" || lastKey != "fake-key-not-real" || lastIMS != "" {
		t.Fatalf("first request: user=%q key=%q ims=%q", lastUser, lastKey, lastIMS)
	}
	fi, _ := os.Stat(path)
	if !fi.ModTime().Equal(modified) {
		t.Fatalf("mtime = %s, want the server's Last-Modified", fi.ModTime())
	}
	before, _ := os.ReadFile(path)
	if err := f.Refresh(context.Background()); err != nil {
		t.Fatal(err)
	}
	if lastIMS != modified.Format(http.TimeFormat) {
		t.Fatalf("second request If-Modified-Since = %q", lastIMS)
	}
	if after, _ := os.ReadFile(path); !bytes.Equal(before, after) {
		t.Fatal("a 304 changed the file")
	}
	if calls.Load() != 2 {
		t.Fatalf("server calls = %d, want 2", calls.Load())
	}
	if f.Status().LastError != "" {
		t.Fatalf("status after 304 = %+v", f.Status())
	}
}

func TestRefreshNoAccountSendsNoAuth(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "" {
			t.Error("Authorization sent without an account")
		}
		w.Write(labDB())
	}))
	defer srv.Close()
	f, _ := newFetcher(t, srv.URL, "", "")
	if err := f.Refresh(context.Background()); err != nil {
		t.Fatal(err)
	}
}

func TestNewFetcherNeedsBothOrNeither(t *testing.T) {
	for _, c := range [][2]string{{"100001", ""}, {"", "fake-key-not-real"}} {
		if _, err := NewFetcher(config.GeoIP{}, c[0], c[1], quiet); err == nil || !strings.Contains(err.Error(), KeyEnv) {
			t.Fatalf("user=%q key=%q: err = %v", c[0], c[1], err)
		}
	}
}

func TestRefreshFailureKeepsFile(t *testing.T) {
	cases := map[string]http.HandlerFunc{
		"not a database": func(w http.ResponseWriter, r *http.Request) { w.Write([]byte("<html>login</html>")) },
		"server error":   func(w http.ResponseWriter, r *http.Request) { http.Error(w, "boom", http.StatusInternalServerError) },
		"unauthorized":   func(w http.ResponseWriter, r *http.Request) { http.Error(w, "no", http.StatusUnauthorized) },
		"archive without a database": func(w http.ResponseWriter, r *http.Request) {
			w.Write(tgz(t, map[string][]byte{"README.txt": []byte("x")}, "README.txt"))
		},
		"database with no countries": func(w http.ResponseWriter, r *http.Request) { w.Write(geoiptest.Build(map[string]string{})) },
	}
	for name, h := range cases {
		t.Run(name, func(t *testing.T) {
			srv := httptest.NewServer(h)
			defer srv.Close()
			f, path := newFetcher(t, srv.URL+"/db?license_key=fake-key-not-real", "100001", "fake-key-not-real")
			good := labDB()
			if err := os.WriteFile(path, good, 0o644); err != nil {
				t.Fatal(err)
			}
			err := f.Refresh(context.Background())
			if err == nil {
				t.Fatal("want an error")
			}
			if strings.Contains(err.Error(), "fake-key-not-real") {
				t.Fatalf("error leaks the key: %v", err)
			}
			if got, _ := os.ReadFile(path); !bytes.Equal(got, good) {
				t.Fatal("the existing file was changed")
			}
			if left, _ := filepath.Glob(filepath.Join(filepath.Dir(path), ".geoip-*")); len(left) != 0 {
				t.Fatalf("temp files left: %v", left)
			}
			if st := f.Status(); st.LastError == "" || st.LastCheck.IsZero() {
				t.Fatalf("status = %+v", st)
			}
		})
	}
}

func TestRefreshRefusesInsecureRedirect(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "http://192.0.2.1/db", http.StatusFound)
	}))
	defer srv.Close()
	f, path := newFetcher(t, srv.URL, "100001", "fake-key-not-real")
	err := f.Refresh(context.Background())
	if err == nil || !strings.Contains(err.Error(), "non-https") {
		t.Fatalf("err = %v", err)
	}
	if _, serr := os.Stat(path); serr == nil {
		t.Fatal("a file was written")
	}
}

func TestRefreshRefusesAccountOverPlainHTTP(t *testing.T) {
	f, _ := newFetcher(t, "http://192.0.2.1/db", "100001", "fake-key-not-real")
	if err := f.Refresh(context.Background()); err == nil || !strings.Contains(err.Error(), "plain http") {
		t.Fatalf("err = %v", err)
	}
}

func TestStart(t *testing.T) {
	var calls atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		w.Write(labDB())
	}))
	defer srv.Close()
	f, path := newFetcher(t, srv.URL, "", "")
	ctx := context.Background()
	if err := f.Start(ctx); err != nil || calls.Load() != 1 {
		t.Fatalf("missing file: err=%v calls=%d", err, calls.Load())
	}
	f.Refresh(ctx)
	calls.Store(0)
	if err := f.Start(ctx); err != nil || calls.Load() != 0 {
		t.Fatalf("fresh file: err=%v calls=%d", err, calls.Load())
	}
	old := time.Now().Add(-2 * time.Hour)
	os.Chtimes(path, old, old)
	if err := f.Start(ctx); err != nil || calls.Load() != 1 {
		t.Fatalf("stale file: err=%v calls=%d", err, calls.Load())
	}
}

func TestRunRefreshesUntilCancelled(t *testing.T) {
	var calls atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		w.Write(labDB())
	}))
	defer srv.Close()
	f, _ := newFetcher(t, srv.URL, "", "")
	f.cfg.Refresh = 10 * time.Millisecond
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { f.Run(ctx); close(done) }()
	deadline := time.Now().Add(5 * time.Second)
	for calls.Load() < 2 && time.Now().Before(deadline) {
		time.Sleep(5 * time.Millisecond)
	}
	cancel()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("Run did not stop")
	}
	if calls.Load() < 2 {
		t.Fatalf("calls = %d, want at least 2", calls.Load())
	}
}
