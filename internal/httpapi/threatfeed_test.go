package httpapi

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/GrandArcher/Packeteer/internal/threatfeed"
)

func TestThreatFeedEndpointAndMetrics(t *testing.T) {
	get := func(h http.Handler, path string) *httptest.ResponseRecorder {
		req := httptest.NewRequest(http.MethodGet, path, nil)
		req.SetBasicAuth("ops", "secret")
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		return rec
	}
	off, err := New(Options{User: "ops", Password: "secret", Snapshot: func() Snapshot { return Assemble(sampleInput()) }})
	if err != nil {
		t.Fatal(err)
	}
	rec := get(off.Handler(), "/api/threat-feeds")
	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), `"enabled":false`) || !strings.Contains(rec.Body.String(), `"proposals":[]`) {
		t.Fatalf("not configured: %d %s", rec.Code, rec.Body)
	}
	if strings.Contains(get(off.Handler(), "/metrics").Body.String(), "packeteer_threat_feed") {
		t.Fatal("threat feed metrics without feeds")
	}
	ok := time.Unix(1_700_000_000, 0)
	st := threatfeed.Status{Interval: "15m0s", MaxActive: 4, MaxActionsPerHour: 6, Held: 1, Rules: []threatfeed.Rule{},
		Feeds: []threatfeed.FeedStatus{{Name: "drop", Type: "http", Entries: 3, LastFetch: ok, LastSuccess: ok},
			{Name: "down", Type: "http", Entries: 2, LastFetch: ok, LastSuccess: ok.Add(-time.Hour), Error: "feed answered 500 Internal Server Error"}},
		Proposals: []threatfeed.Proposal{{Rule: "srcs", Feed: "drop", Entry: netip.MustParsePrefix("192.0.2.1/32"), Prefix: netip.MustParsePrefix("198.51.100.0/24"),
			Action: "flowspec_drop", Mitigation: "m1", State: threatfeed.StateMitigating, Since: ok}}}
	on, err := New(Options{User: "ops", Password: "secret", ThreatFeeds: func() threatfeed.Status { return st }, Snapshot: func() Snapshot { return Assemble(sampleInput()) }})
	if err != nil {
		t.Fatal(err)
	}
	rec = get(on.Handler(), "/api/threat-feeds")
	var body struct {
		Enabled bool `json:"enabled"`
		Feeds   []struct {
			Name  string `json:"name"`
			Error string `json:"error"`
		} `json:"feeds"`
		Proposals []struct {
			Entry      string `json:"entry"`
			Prefix     string `json:"prefix"`
			Mitigation string `json:"mitigation"`
		} `json:"proposals"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatal(err)
	}
	if !body.Enabled || len(body.Feeds) != 2 || body.Feeds[1].Error == "" || len(body.Proposals) != 1 ||
		body.Proposals[0].Entry != "192.0.2.1/32" || body.Proposals[0].Prefix != "198.51.100.0/24" || body.Proposals[0].Mitigation != "m1" {
		t.Fatalf("body = %s", rec.Body)
	}
	m := get(on.Handler(), "/metrics").Body.String()
	for _, want := range []string{`packeteer_threat_feed_up{feed="drop"} 1`, `packeteer_threat_feed_up{feed="down"} 0`,
		`packeteer_threat_feed_entries{feed="drop"} 3`, "packeteer_threat_feed_mitigations 1"} {
		if !strings.Contains(m, want) {
			t.Fatalf("metrics lack %q:\n%s", want, m)
		}
	}
}
