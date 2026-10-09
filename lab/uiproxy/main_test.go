package main

import (
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestProxyAddsBasicAuth(t *testing.T) {
	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		u, p, ok := r.BasicAuth()
		if !ok || u != "lab" || p != "lab-only" {
			http.Error(w, "no", http.StatusUnauthorized)
			return
		}
		if r.URL.Path != "/api/providers" {
			t.Errorf("path %s", r.URL.Path)
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, `{"mode":"observe"}`)
	}))
	defer origin.Close()

	h, err := handler(origin.URL, "lab", "lab-only")
	if err != nil {
		t.Fatal(err)
	}
	front := httptest.NewServer(h)
	defer front.Close()

	resp, err := http.Get(front.URL + "/api/providers")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK || string(body) != `{"mode":"observe"}` {
		t.Fatalf("status %d body %s", resp.StatusCode, body)
	}
}

func TestProxyRefusesOpenListenAndMissingAuth(t *testing.T) {
	if err := loopback("0.0.0.0:18089"); err == nil {
		t.Fatal("accepted a non-loopback listen address")
	}
	if err := loopback("127.0.0.1:18089"); err != nil {
		t.Fatal(err)
	}
	if _, err := handler("http://127.0.0.1:8080", "", "secret"); err == nil {
		t.Fatal("missing user accepted")
	}
	if _, err := handler("http://lab:lab-only@127.0.0.1:8080", "lab", "lab-only"); err == nil {
		t.Fatal("userinfo in the upstream URL accepted")
	}
}
