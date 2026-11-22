package main

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func env(k string) string {
	return map[string]string{"PACKETEER_ROUTER_READ_USER": "pk-reader", "PACKETEER_ROUTER_READ_PASSWORD": "lab-only-password"}[k]
}

// A CHR answers the resource read and has no switch menu.
func chr(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	switch r.URL.Path {
	case "/rest/system/resource":
		_, _ = w.Write([]byte(`{"version":"7.23.7 (long-term)","board-name":"CHR"}`))
	default:
		w.WriteHeader(http.StatusBadRequest)
	}
}

func TestChrPrintsNotApplicable(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(chr))
	defer srv.Close()
	var out bytes.Buffer
	if err := run([]string{"-url", srv.URL}, env, &out); err != nil {
		t.Fatal(err)
	}
	var got struct {
		Version    string `json:"version"`
		Applicable bool   `json:"applicable"`
	}
	if err := json.Unmarshal(out.Bytes(), &got); err != nil {
		t.Fatal(err)
	}
	if got.Applicable || got.Version != "7.23.7" {
		t.Errorf("got %+v", got)
	}
	if strings.Contains(out.String(), "lab-only-password") {
		t.Error("output holds the password")
	}
}

func TestMissingLoginIsAnError(t *testing.T) {
	err := run([]string{"-url", "http://127.0.0.1:1"}, func(string) string { return "" }, &bytes.Buffer{})
	if err == nil {
		t.Fatal("no credentials must be an error")
	}
}
