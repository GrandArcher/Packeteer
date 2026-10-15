package ixf

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func TestFetchAllowlist(t *testing.T) {
	var paths []string
	var methods []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			t.Errorf("method %s", r.Method)
		}
		methods = append(methods, r.Method)
		paths = append(paths, r.URL.RequestURI())
		if strings.Contains(r.URL.String(), docSecret) || r.URL.Query().Get("apikey") != "" {
			t.Errorf("key in url %s", r.URL)
		}
		if r.Header.Get(apiKeyHeader) != docKey {
			t.Errorf("header %q", r.Header.Get(apiKeyHeader))
		}
		_, _ = io.WriteString(w, sampleIXF)
	}))
	defer srv.Close()

	cases := []string{
		srv.URL + "/",
		srv.URL + exportPath,
		srv.URL + "/ixpm" + exportPath,
	}
	for _, raw := range cases {
		paths, methods = nil, nil
		s := build(t, "url: "+raw+"\nkey_expires: \""+utcDay(30)+"\"\n", docKey, nil)
		s.fetch(context.Background())
		v := s.View()
		if v.Error != "" || v.MemberCount != 2 || !v.Manager || v.KeyID != docIdent {
			t.Fatalf("url %s view %+v", raw, v)
		}
		if len(paths) != 1 || !strings.HasPrefix(paths[0], exportPath) && !strings.Contains(paths[0], "/ixpm"+exportPath) {
			t.Fatalf("url %s requested %v", raw, paths)
		}
		if raw == srv.URL+"/ixpm"+exportPath && paths[0] != "/ixpm"+exportPath {
			t.Fatalf("subdirectory requested %s", paths[0])
		}
		if strings.Join(methods, ",") != http.MethodGet {
			t.Fatalf("methods %v", methods)
		}
	}

	paths = nil
	q := srv.URL + exportPath + "?ixfid_1=2&ignore_missing_ixfid=1"
	s := build(t, "url: "+q+"\nkey_expires: \""+utcDay(30)+"\"\n", docKey, nil)
	s.fetch(context.Background())
	if s.View().Error != "" {
		t.Fatal(s.View().Error)
	}
	if len(paths) != 1 || !strings.Contains(paths[0], "ixfid_1=2") || !strings.Contains(paths[0], "ignore_missing_ixfid=1") {
		t.Fatalf("query %v", paths)
	}
}

func TestURLRejected(t *testing.T) {
	if err := newErr(t, "url: https://ixp.example.invalid"+exportPath+"?apikey="+docSecret+"\n", ""); err == nil || strings.Contains(err.Error(), docSecret) || !strings.Contains(err.Error(), "apikey") {
		t.Fatalf("apikey query: %v", err)
	}
	if err := newErr(t, "url: https://ixp.example.invalid/members.json?access_key="+docSecret+"\n", ""); err == nil || strings.Contains(err.Error(), docSecret) {
		t.Fatalf("access_key: %v", err)
	}
	if err := newErr(t, "url: https://ixp.example.invalid"+exportPath+"?vlan=1\n", ""); err == nil || !strings.Contains(err.Error(), "vlan") {
		t.Fatalf("manager query: %v", err)
	}
	if err := newErr(t, "url: https://ixp.example.invalid/"+docKey+"\nkey_expires: \""+utcDay(10)+"\"\n", docKey); err == nil || strings.Contains(err.Error(), docSecret) || strings.Contains(err.Error(), docKey) {
		t.Fatalf("key in url: %v", err)
	}
	if err := newErr(t, "url: https://ixp.example.invalid/members.json\nkey_expires: \""+utcDay(10)+"\"\n", docKey); err == nil || !strings.Contains(err.Error(), "only sent") || strings.Contains(err.Error(), docSecret) {
		t.Fatalf("named with key: %v", err)
	}
	if err := newErr(t, "url: https://ixp.example.invalid"+exportPath+"evil\nkey_expires: \""+utcDay(10)+"\"\n", docKey); err == nil || !strings.Contains(err.Error(), "only sent") {
		t.Fatalf("near path: %v", err)
	}
}

func TestNamedFetchHasNoKey(t *testing.T) {
	var got string
	var header string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got = r.URL.RequestURI()
		header = r.Header.Get(apiKeyHeader)
		if r.Method != http.MethodGet {
			t.Errorf("method %s", r.Method)
		}
		_, _ = io.WriteString(w, `{"version":"1.0","member_list":[]}`)
	}))
	defer srv.Close()
	s := build(t, "url: "+srv.URL+"/members.json?vlan=1\n", "", nil)
	if s.manager {
		t.Fatal("named url classified as manager")
	}
	s.fetch(context.Background())
	v := s.View()
	if v.Error != "" || v.MemberCount != 0 || v.Manager || header != "" || got != "/members.json?vlan=1" {
		t.Fatalf("view %+v uri %s header %q", v, got, header)
	}
}

func TestRedirectDropsKey(t *testing.T) {
	var second atomic.Int32
	steal := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		second.Add(1)
		if r.Header.Get(apiKeyHeader) != "" {
			t.Error("API key was forwarded")
		}
	}))
	defer steal.Close()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get(apiKeyHeader) != docKey {
			t.Errorf("first header %q", r.Header.Get(apiKeyHeader))
		}
		http.Redirect(w, r, steal.URL+"/steal?k="+docKey, http.StatusFound)
	}))
	defer srv.Close()
	s := build(t, "url: "+srv.URL+"/\nkey_expires: \""+utcDay(20)+"\"\n", docKey, nil)
	s.fetch(context.Background())
	v := s.View()
	if second.Load() != 0 {
		t.Fatalf("redirect target saw %d requests", second.Load())
	}
	if v.Error != "member export: redirects are not followed" || strings.Contains(v.Error, docSecret) || strings.Contains(v.Error, docKey) || v.MemberCount != 0 {
		t.Fatalf("view %+v", v)
	}
}

func TestFailedFetchKeepsMembersUntilStale(t *testing.T) {
	var big atomic.Bool
	var status atomic.Int32
	status.Store(http.StatusOK)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if big.Load() {
			_, _ = w.Write(bytesRepeat(3000))
			return
		}
		w.WriteHeader(int(status.Load()))
		if status.Load() == http.StatusOK {
			_, _ = io.WriteString(w, sampleIXF)
		}
	}))
	defer srv.Close()
	s := build(t, "url: "+srv.URL+"/members.json\nmax_bytes: 2048\nrefresh: 1m\n", "", nil)
	if len(sampleIXF) > 2048 {
		t.Fatalf("fixture is %d bytes", len(sampleIXF))
	}
	s.fetch(context.Background())
	if s.View().MemberCount != 2 || s.View().Error != "" {
		t.Fatalf("first %+v", s.View())
	}
	status.Store(http.StatusInternalServerError)
	s.fetch(context.Background())
	v := s.View()
	if v.MemberCount != 2 || v.Stale || !strings.Contains(v.Error, "HTTP 500") {
		t.Fatalf("after 500 %+v", v)
	}
	big.Store(true)
	status.Store(http.StatusOK)
	s.fetch(context.Background())
	v = s.View()
	if v.MemberCount != 2 || !strings.Contains(v.Error, "larger than 2048") {
		t.Fatalf("after size %+v", v)
	}
	s.mu.Lock()
	s.view.Fetched = time.Now().Add(-3*s.refresh - time.Second)
	s.view.KeyID = docIdent
	s.mu.Unlock()
	v = s.View()
	if !v.Stale || len(v.Members) != 0 || len(v.IXPs) != 0 || v.MemberCount != 0 || v.KeyID != docIdent || v.Error != "member list is stale" || v.URL == "" {
		t.Fatalf("stale %+v", v)
	}
}

func TestStartFetchesOnce(t *testing.T) {
	var n atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		n.Add(1)
		_, _ = io.WriteString(w, sampleIXF)
	}))
	defer srv.Close()
	s := build(t, "url: "+srv.URL+"/members.json\nrefresh: 1m\n", "", nil)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	if err := s.Start(ctx); err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) && s.View().MemberCount != 2 {
		time.Sleep(10 * time.Millisecond)
	}
	if s.View().MemberCount != 2 || n.Load() != 1 {
		t.Fatalf("count %d requests %d err %s", s.View().MemberCount, n.Load(), s.View().Error)
	}
	stop, cancelStop := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancelStop()
	if err := s.Stop(stop); err != nil {
		t.Fatal(err)
	}
}

func TestFetchCancelled(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Error("fetch ran")
	}))
	defer srv.Close()
	s := build(t, "url: "+srv.URL+"/members.json\n", "", nil)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	s.fetch(ctx)
	v := s.View()
	if v.Error != "" || v.MemberCount != 0 || !v.Fetched.IsZero() {
		t.Fatalf("%+v", v)
	}
}

func bytesRepeat(n int) []byte {
	b := make([]byte, n)
	for i := range b {
		b[i] = 'x'
	}
	return b
}
