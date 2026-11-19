package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"gopkg.in/yaml.v3"

	"github.com/GrandArcher/Packeteer/internal/config"
	"github.com/GrandArcher/Packeteer/internal/pluginhost"
	_ "github.com/GrandArcher/Packeteer/internal/plugins/all"
	"github.com/GrandArcher/Packeteer/pkg/plugin"
)

var t0 = time.Date(2026, 11, 18, 12, 0, 0, 0, time.UTC)

func serve(t *testing.T, role string) *httptest.Server {
	t.Helper()
	s := &stub{role: role, now: func() time.Time { return t0 }}
	srv := httptest.NewServer(s.handler())
	t.Cleanup(srv.Close)
	return srv
}

func get(t *testing.T, url string) (int, string) {
	t.Helper()
	resp, err := http.Get(url)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	b, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatal(err)
	}
	return resp.StatusCode, string(b)
}

// #671: the fixed data gives the agreement, disagreement, and empty cases
// the lab script checks, and every request is recorded.
func TestCollectorsAnswerTheLabCases(t *testing.T) {
	ris, rv := serve(t, "ris"), serve(t, "routeviews")
	want := map[string]map[string]string{
		"198.51.100.0/25":  {"ris": `{"origins":[64500],"prefix":"198.51.100.0/25"}`, "routeviews": `{"origins":[64500,64510],"prefix":"198.51.100.0/25"}`},
		"203.0.113.0/25":   {"ris": `{"origins":[64501],"prefix":"203.0.113.0/25"}`, "routeviews": `{"origins":[64511],"prefix":"203.0.113.0/25"}`},
		"203.0.113.128/25": {"ris": `{"origins":[],"prefix":"203.0.113.128/25"}`, "routeviews": `{"origins":[],"prefix":"203.0.113.128/25"}`},
	}
	for prefix, byRole := range want {
		for role, srv := range map[string]*httptest.Server{"ris": ris, "routeviews": rv} {
			code, body := get(t, srv.URL+"/"+role+"?prefix="+prefix)
			if code != http.StatusOK || strings.TrimSpace(body) != byRole[role] {
				t.Errorf("%s %s: %d %s", role, prefix, code, body)
			}
		}
	}
	code, _ := get(t, ris.URL+"/ris?prefix=nonsense")
	if code != http.StatusBadRequest {
		t.Errorf("bad prefix: %d", code)
	}
	resp, err := http.Post(ris.URL+"/ris?prefix=198.51.100.0/25", "text/plain", strings.NewReader("x"))
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusMethodNotAllowed {
		t.Errorf("POST: %d", resp.StatusCode)
	}
	_, body := get(t, ris.URL+"/_lab/state")
	var st State
	if err := json.Unmarshal([]byte(body), &st); err != nil {
		t.Fatal(err)
	}
	if st.Role != "ris" || len(st.Requests) != 5 || st.Requests[3].Status != http.StatusBadRequest || st.Requests[4].Method != http.MethodPost || st.Requests[4].Status != http.StatusMethodNotAllowed {
		t.Fatalf("state = %+v", st)
	}
	// The other role's endpoint does not exist here.
	if code, _ := get(t, ris.URL+"/routeviews?prefix=198.51.100.0/25"); code != http.StatusNotFound {
		t.Errorf("routeviews path on ris: %d", code)
	}
}

// The VRP document makes each /25 invalid: the ROAs allow up to /24.
func TestVRPDocument(t *testing.T) {
	_, body := get(t, serve(t, "vrp").URL+"/json")
	var doc struct {
		Metadata struct{ Generated int64 }
		ROAs     []struct {
			ASN       string
			Prefix    string
			MaxLength int
		} `json:"roas"`
	}
	if err := json.Unmarshal([]byte(body), &doc); err != nil {
		t.Fatal(err)
	}
	if doc.Metadata.Generated != t0.Unix() || len(doc.ROAs) != 2 || doc.ROAs[0].ASN != "AS64500" || doc.ROAs[0].Prefix != "198.51.100.0/24" ||
		doc.ROAs[1].ASN != "AS64501" || doc.ROAs[1].Prefix != "203.0.113.0/24" || doc.ROAs[0].MaxLength != 24 || doc.ROAs[1].MaxLength != 24 {
		t.Fatalf("document = %s", body)
	}
}

// #671: the lab config builds with the real plugins, stays in observe, and
// every collector and RPKI address it names is a stand-in. Pointed at
// in-process stand-ins, the real json plugin returns the data the script
// expects, and a stopped stand-in is an error, not an empty answer.
func TestLabConfigAgainstStandIns(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join("..", "packeteer-origin-agreement.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	var doc map[string]any
	if err := yaml.Unmarshal(raw, &doc); err != nil {
		t.Fatal(err)
	}
	var urls []string
	var walk func(v any)
	walk = func(v any) {
		switch v := v.(type) {
		case map[string]any:
			for k, x := range v {
				if s, ok := x.(string); ok && k == "url" {
					urls = append(urls, s)
				}
				walk(x)
			}
		case []any:
			for _, x := range v {
				walk(x)
			}
		}
	}
	walk(doc)
	slices.Sort(urls)
	wantURLs := []string{"http://ris-stub:8080/ris", "http://routeviews-stub:8080/routeviews", "http://vrp-stub:8080/json"}
	if !slices.Equal(urls, wantURLs) {
		t.Fatalf("urls in the lab config: %v, want %v", urls, wantURLs)
	}

	ris, rv := serve(t, "ris"), serve(t, "routeviews")
	y := strings.NewReplacer("http://ris-stub:8080", ris.URL, "http://routeviews-stub:8080", rv.URL).Replace(string(raw))
	cfg, err := config.Parse([]byte(y))
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Mode != "observe" || !cfg.OnlyInvalidOn() {
		t.Fatalf("mode %q only_invalid %v", cfg.Mode, cfg.OnlyInvalidOn())
	}
	set, err := pluginhost.Build(cfg, pluginhost.Options{CheckOnly: true})
	if err != nil {
		t.Fatal(err)
	}
	if len(set.OriginCollectors) != 2 || set.OriginCollectors[0].Name != "ris" || set.OriginCollectors[1].Name != "routeviews" {
		t.Fatalf("collectors = %+v", set.OriginCollectors)
	}
	ask := func(c plugin.OriginCollector, prefix string) ([]uint32, error) {
		return c.Origins(context.Background(), netip.MustParsePrefix(prefix))
	}
	for _, tc := range []struct {
		prefix, ris, routeviews string
	}{
		{"198.51.100.0/25", "[64500]", "[64500 64510]"},
		{"203.0.113.0/25", "[64501]", "[64511]"},
		{"203.0.113.128/25", "[]", "[]"},
	} {
		for i, want := range []string{tc.ris, tc.routeviews} {
			got, err := ask(set.OriginCollectors[i].Plugin, tc.prefix)
			if err != nil || fmt.Sprint(got) != want {
				t.Errorf("%s %s: %v, %v, want %s", set.OriginCollectors[i].Name, tc.prefix, got, err, want)
			}
		}
	}
	ris.Close()
	if got, err := ask(set.OriginCollectors[0].Plugin, "198.51.100.0/25"); err == nil || got != nil {
		t.Fatalf("a stopped stand-in answered: %v, %v", got, err)
	}
}

// The lab network has no route out, no service publishes a port, and every
// service is on that one network.
func TestLabComposeIsInternal(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join("..", "docker-compose-origin-agreement.yml"))
	if err != nil {
		t.Fatal(err)
	}
	var doc struct {
		Services map[string]struct {
			Ports    []any `yaml:"ports"`
			Networks map[string]any
		} `yaml:"services"`
		Networks map[string]struct {
			Internal bool `yaml:"internal"`
		} `yaml:"networks"`
	}
	if err := yaml.Unmarshal(raw, &doc); err != nil {
		t.Fatal(err)
	}
	if len(doc.Networks) != 1 || !doc.Networks["lab"].Internal {
		t.Fatalf("networks %+v", doc.Networks)
	}
	if len(doc.Services) != 6 {
		t.Fatalf("services %d", len(doc.Services))
	}
	for name, s := range doc.Services {
		if len(s.Ports) != 0 || len(s.Networks) != 1 {
			t.Errorf("%s: ports %v networks %v", name, s.Ports, s.Networks)
		}
	}
}
