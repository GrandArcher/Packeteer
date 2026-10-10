package main

import (
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/GrandArcher/Packeteer/internal/config"
	"github.com/GrandArcher/Packeteer/internal/httpapi"
	"github.com/GrandArcher/Packeteer/internal/mitigation"
)

// With no RIB view the picker offers nothing and says it is not ready, so
// the Protection form cannot submit a prefix that is not learned (#131).
func TestMitigationCandidatesWithoutRIB(t *testing.T) {
	mit, err := mitigation.New(mitigation.Config{Mode: config.ModeObserve, Allowlist: []netip.Prefix{netip.MustParsePrefix("203.0.113.0/24")},
		MaxRules: 2, DefaultTTL: time.Hour, MaxTTL: 2 * time.Hour}, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	srv, err := httpapi.New(httpapi.Options{User: "u", Password: "p", Mitigation: mitigationControl{mit: mit, poke: func() {}},
		Snapshot: func() httpapi.Snapshot { return httpapi.Snapshot{} }})
	if err != nil {
		t.Fatal(err)
	}
	wireMitigationCandidates(srv, mit, nil)
	req := httptest.NewRequest(http.MethodGet, "/api/mitigations/candidates", nil)
	req.SetBasicAuth("u", "p")
	rec := httptest.NewRecorder()
	srv.Handler().ServeHTTP(rec, req)
	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), `"ready":false`) || !strings.Contains(rec.Body.String(), `"prefixes":[]`) {
		t.Fatalf("candidates without a RIB: %d %s", rec.Code, rec.Body)
	}
	// A nil server or controller is a no-op.
	wireMitigationCandidates(nil, mit, nil)
	wireMitigationCandidates(srv, nil, nil)
}
