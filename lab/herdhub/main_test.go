package main

import (
	"bytes"
	"log"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestHandlerServesTheListAndLogsEachRequest(t *testing.T) {
	list := filepath.Join(t.TempDir(), "herd.json")
	rsc := filepath.Join(t.TempDir(), "rsc.json")
	var logs bytes.Buffer
	h := handler(map[string]string{"/herd.json": list, "/rsc.json": rsc}, log.New(&logs, "", 0))

	get := func(method, path string) *httptest.ResponseRecorder {
		rec := httptest.NewRecorder()
		req := httptest.NewRequest(method, path, nil)
		req.RemoteAddr = "192.0.2.10:40000"
		h.ServeHTTP(rec, req)
		return rec
	}

	if rec := get(http.MethodGet, "/herd.json"); rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("no list file: status %d, want 503", rec.Code)
	}
	if err := os.WriteFile(list, []byte(`{"schema":"packeteer-herd-hub/1","entries":[]}`), 0o644); err != nil {
		t.Fatal(err)
	}
	rec := get(http.MethodGet, "/herd.json")
	if rec.Code != http.StatusOK || rec.Header().Get("Content-Type") != "application/json" || !strings.Contains(rec.Body.String(), "packeteer-herd-hub/1") {
		t.Fatalf("GET /herd.json: %d %q %q", rec.Code, rec.Header().Get("Content-Type"), rec.Body.String())
	}
	// The file is read on every request, not cached at start.
	if err := os.WriteFile(list, []byte(`{"replaced":true}`), 0o644); err != nil {
		t.Fatal(err)
	}
	if rec := get(http.MethodGet, "/herd.json"); rec.Body.String() != `{"replaced":true}` {
		t.Fatalf("second GET served %q, want the replaced file", rec.Body.String())
	}
	if rec := get(http.MethodPost, "/herd.json"); rec.Code != http.StatusMethodNotAllowed || rec.Header().Get("Allow") != http.MethodGet {
		t.Fatalf("POST: status %d, Allow %q", rec.Code, rec.Header().Get("Allow"))
	}
	if rec := get(http.MethodGet, "/entries/64496.json"); rec.Code != http.StatusNotFound {
		t.Fatalf("other path: status %d, want 404", rec.Code)
	}
	if err := os.WriteFile(rsc, []byte(`{"schema":"packeteer-herd-rsc/1","checklists":[]}`), 0o644); err != nil {
		t.Fatal(err)
	}
	if rec := get(http.MethodGet, "/rsc.json"); rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), "packeteer-herd-rsc/1") {
		t.Fatalf("GET /rsc.json: %d %q", rec.Code, rec.Body.String())
	}
	if !strings.Contains(logs.String(), "herdhub: GET /herd.json from 192.0.2.10:40000") || strings.Count(logs.String(), "\n") != 6 {
		t.Fatalf("every request is logged with its client:\n%s", logs.String())
	}
}
