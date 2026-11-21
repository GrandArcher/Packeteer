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

	"github.com/GrandArcher/Packeteer/internal/herd"
)

func TestHandlerServesTheListAndLogsEachRequest(t *testing.T) {
	list := filepath.Join(t.TempDir(), "herd.json")
	rpkiOut := filepath.Join(t.TempDir(), "rpki-client.json")
	var logs bytes.Buffer
	h := handler(map[string]func() ([]byte, error){
		"/herd.json": func() ([]byte, error) { return os.ReadFile(list) },
		"/rsc.json":  checklistDoc(rpkiOut),
	}, log.New(&logs, "", 0))

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
	if rec := get(http.MethodGet, "/rsc.json"); rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("no rpki-client output: status %d, want 503", rec.Code)
	}
	out, err := os.ReadFile(filepath.Join("testdata", "rpki-client.json"))
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(rpkiOut, out, 0o644); err != nil {
		t.Fatal(err)
	}
	rec = get(http.MethodGet, "/rsc.json")
	if rec.Code != http.StatusOK || rec.Header().Get("Content-Type") != "application/json" {
		t.Fatalf("GET /rsc.json: %d %q", rec.Code, rec.Body.String())
	}
	// The node's own parser reads what the hub serves.
	if b, err := herd.ParseIdentityList(rec.Body.Bytes()); err != nil || len(b) != 3 {
		t.Fatalf("served checklists: %d bindings, %v; want 3:\n%s", len(b), err, rec.Body.String())
	}
	if !strings.Contains(logs.String(), "herdhub: GET /herd.json from 192.0.2.10:40000") || !strings.Contains(logs.String(), "herdhub: /rsc.json: open ") ||
		strings.Count(logs.String(), "\n") != 9 {
		t.Fatalf("every request is logged with its client:\n%s", logs.String())
	}
}
