package httpapi

import (
	"encoding/json"
	"net/http"
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/GrandArcher/Packeteer/internal/policy"
)

type fakeRelease struct {
	held map[netip.Prefix]bool
	got  []netip.Prefix
}

func (f *fakeRelease) Release(p netip.Prefix) bool {
	f.got = append(f.got, p)
	ok := f.held[p.Masked()]
	delete(f.held, p.Masked())
	return ok
}

func TestQuarantineAPIMetricsAndRelease(t *testing.T) {
	p := netip.MustParsePrefix("203.0.113.0/24")
	until := time.Date(2026, 1, 1, 0, 15, 0, 0, time.UTC)
	in := sampleInput()
	in.Quarantined = []policy.Quarantine{{Prefix: p, Since: until.Add(-15 * time.Minute), Until: until, Flips: 7, Strikes: 2}}
	s, err := New(Options{User: "ops", Password: "secret", Snapshot: func() Snapshot { return Assemble(in) }})
	if err != nil {
		t.Fatal(err)
	}
	ctl := &fakeRelease{held: map[netip.Prefix]bool{p: true}}
	s.SetQuarantine(ctl)
	h := s.Handler()

	var body struct {
		Writable    bool         `json:"writable"`
		Quarantined []Quarantine `json:"quarantined"`
	}
	rec := mdo(h, http.MethodGet, "/api/quarantine", "", "", true)
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatal(err)
	}
	if !body.Writable || len(body.Quarantined) != 1 || body.Quarantined[0].Prefix != "203.0.113.0/24" || body.Quarantined[0].Flips != 7 || body.Quarantined[0].Strikes != 2 || !body.Quarantined[0].Until.Equal(until) {
		t.Fatalf("body %s", rec.Body)
	}

	var prefixes struct {
		Prefixes []struct {
			Prefix     string      `json:"prefix"`
			Quarantine *Quarantine `json:"quarantine"`
		} `json:"prefixes"`
	}
	rec = mdo(h, http.MethodGet, "/api/prefixes?prefix=203.0.113.0/24", "", "", true)
	if err := json.Unmarshal(rec.Body.Bytes(), &prefixes); err != nil {
		t.Fatal(err)
	}
	if len(prefixes.Prefixes) != 1 || prefixes.Prefixes[0].Quarantine == nil || prefixes.Prefixes[0].Quarantine.Strikes != 2 {
		t.Fatalf("prefix row lacks the quarantine: %s", rec.Body)
	}

	m := mdo(h, http.MethodGet, "/metrics", "", "", true).Body.String()
	for _, want := range []string{
		"packeteer_flap_quarantined 1",
		`packeteer_flap_quarantine{prefix="203.0.113.0/24",strikes="2"} 1`,
	} {
		if !strings.Contains(m, want) {
			t.Fatalf("metrics lack %q:\n%s", want, m)
		}
	}

	// Release needs auth, JSON, a valid prefix, and a quarantined prefix.
	if rec := mdo(h, http.MethodPost, "/api/quarantine/release", "application/json", `{"prefix":"203.0.113.0/24"}`, false); rec.Code != http.StatusUnauthorized {
		t.Fatalf("no auth: %d", rec.Code)
	}
	if rec := mdo(h, http.MethodPost, "/api/quarantine/release", "text/plain", `{"prefix":"203.0.113.0/24"}`, true); rec.Code != http.StatusUnsupportedMediaType {
		t.Fatalf("content type: %d", rec.Code)
	}
	if rec := mdo(h, http.MethodPost, "/api/quarantine/release", "application/json", `{"prefix":"nope"}`, true); rec.Code != http.StatusBadRequest {
		t.Fatalf("bad prefix: %d", rec.Code)
	}
	if rec := mdo(h, http.MethodPost, "/api/quarantine/release", "application/json", `{"prefix":"198.51.100.0/24"}`, true); rec.Code != http.StatusNotFound {
		t.Fatalf("not quarantined: %d", rec.Code)
	}
	if !ctl.held[p] {
		t.Fatal("a refused release freed the prefix")
	}
	if rec := mdo(h, http.MethodPost, "/api/quarantine/release", "application/json", `{"prefix":"203.0.113.0/24"}`, true); rec.Code != http.StatusNoContent || ctl.held[p] {
		t.Fatalf("release: %d held=%v", rec.Code, ctl.held[p])
	}
}

func TestQuarantineAPIWithoutControlOrAuth(t *testing.T) {
	s, err := New(Options{Snapshot: func() Snapshot { return Assemble(sampleInput()) }})
	if err != nil {
		t.Fatal(err)
	}
	h := s.Handler()
	rec := mdo(h, http.MethodGet, "/api/quarantine", "", "", true)
	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), `"quarantined":[]`) {
		t.Fatalf("empty list: %d %s", rec.Code, rec.Body)
	}
	if rec := mdo(h, http.MethodPost, "/api/quarantine/release", "application/json", `{"prefix":"203.0.113.0/24"}`, true); rec.Code != http.StatusForbidden {
		t.Fatalf("release without auth configured: %d", rec.Code)
	}
}
