package httpapi

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/GrandArcher/Packeteer/internal/ringlg"
)

func ringServer(t *testing.T, c *ringlg.Client) string {
	t.Helper()
	s, err := New(Options{Snapshot: func() Snapshot { return Snapshot{} }, RingLG: c})
	if err != nil {
		t.Fatal(err)
	}
	ts := httptest.NewServer(s.Handler())
	t.Cleanup(ts.Close)
	return ts.URL
}

func getRing(t *testing.T, base, prefix string) (int, ringlg.Result, string) {
	t.Helper()
	code, _, raw := do(t, http.MethodGet, base+"/api/ring_lg?prefix="+url.QueryEscape(prefix), "", "")
	var out ringlg.Result
	if code == http.StatusOK {
		if err := json.Unmarshal(raw, &out); err != nil {
			t.Fatalf("%v: %s", err, raw)
		}
	}
	return code, out, string(raw)
}

func TestRingLGOffByDefault(t *testing.T) {
	for name, c := range map[string]*ringlg.Client{"unset": nil, "disabled": ringlg.New(ringlg.Config{}, "test")} {
		base := ringServer(t, c)
		// Even a bad prefix is not examined while the panel is off.
		for _, p := range []string{"198.51.100.0/24", "not-a-prefix"} {
			code, got, raw := getRing(t, base, p)
			if code != http.StatusOK || got.State != ringlg.StateOff || strings.Contains(raw, "198.51.100") {
				t.Errorf("%s %q: %d %s", name, p, code, raw)
			}
		}
	}
}

func TestRingLGEnabledChecksThePrefix(t *testing.T) {
	base := ringServer(t, ringlg.New(ringlg.Config{Enabled: true}, "test"))
	for _, p := range []string{"", "not-a-prefix", "198.51.100.1", "198.51.100.0/24?x=1"} {
		if code, _, _ := getRing(t, base, p); code != http.StatusBadRequest {
			t.Errorf("%q: status %d, want 400", p, code)
		}
	}
	// A private prefix is refused before any request leaves the process.
	code, got, _ := getRing(t, base, "10.1.0.0/16")
	if code != http.StatusOK || got.State != ringlg.StateUnavailable || !strings.Contains(got.Message, "never sent") {
		t.Errorf("private prefix: %d %+v", code, got)
	}
}

func TestRingLGRoute(t *testing.T) {
	base := ringServer(t, nil)
	if code, _, _ := do(t, http.MethodPost, base+"/api/ring_lg?prefix=198.51.100.0/24", "", ""); code != http.StatusMethodNotAllowed {
		t.Errorf("POST status = %d, want 405", code)
	}
}
