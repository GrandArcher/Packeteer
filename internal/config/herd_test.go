package config

import (
	"strings"
	"testing"
	"time"
)

const herdKey = "ed25519:AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8="

const herdBase = minimalYAML + `
storage: {type: sqlite}
bgp:
  neighbors:
    - address: 192.0.2.254
`

const herdOn = `
herd:
  enabled: true
  share:
    classes: [measurements]
  vantage: {country: US}
  listen: 192.0.2.10:9444
  peers:
    - url: https://192.0.2.30:9444
      key: ` + herdKey + `
`

func TestHerdOffByDefault(t *testing.T) {
	for _, y := range []string{minimalYAML, minimalYAML + "herd:\n  enabled: false\n"} {
		cfg, err := Parse([]byte(y))
		if err != nil {
			t.Fatal(err)
		}
		if cfg.HerdOn() {
			t.Fatalf("herd is on for %q", y)
		}
	}
}

func TestHerdDefaults(t *testing.T) {
	cfg, err := Parse([]byte(herdBase + herdOn))
	if err != nil {
		t.Fatal(err)
	}
	h := cfg.Herd
	if h.Share.Granularity != HerdOriginASN || h.Share.Discovery != HerdQueryOnly {
		t.Errorf("granularity %q discovery %q, want origin_asn and query_only", h.Share.Granularity, h.Share.Discovery)
	}
	if got := strings.Join(h.Share.Sources, ","); got != "static,vip,outage" {
		t.Errorf("sources = %s, want static,vip,outage (no flow or span)", got)
	}
	if h.RetentionDays != 90 || h.KeyFile != DefaultHerdKeyFile {
		t.Errorf("retention %d key_file %q", h.RetentionDays, h.KeyFile)
	}
	if h.Limits.RatePerIdentity != 60 || h.Limits.Timeout != 10*time.Second || h.Limits.PulledBytes != 512<<20 {
		t.Errorf("limit defaults not applied: %+v", h.Limits)
	}
	if !h.Serving() {
		t.Error("Serving() is false for a serving config")
	}
}

func TestHerdValidation(t *testing.T) {
	tests := []struct {
		name string
		edit func(string) string
		want string
	}{
		{"no class", func(s string) string { return strings.Replace(s, "classes: [measurements]", "classes: []", 1) }, "choose at least one data class"},
		{"visibility class", func(s string) string { return strings.Replace(s, "[measurements]", "[visibility]", 1) }, `"visibility" must be`},
		{"granularity", func(s string) string { return strings.Replace(s, "classes:", "granularity: prefix\n    classes:", 1) }, "granularity"},
		{"retention low", func(s string) string { return strings.Replace(s, "  share:", "  retention_days: 29\n  share:", 1) }, "retention_days 29"},
		{"retention high", func(s string) string { return strings.Replace(s, "  share:", "  retention_days: 366\n  share:", 1) }, "retention_days 366"},
		{"country", func(s string) string { return strings.Replace(s, "US", "usa", 1) }, "alpha-2"},
		{"no peers", func(s string) string { return s[:strings.Index(s, "  peers:")] }, "at least one peer"},
		{"no listen", func(s string) string { return strings.Replace(s, "  listen: 192.0.2.10:9444\n", "", 1) }, "herd.listen"},
		{"http peer", func(s string) string { return strings.Replace(s, "https://", "http://", 1) }, "must be https://host:port"},
		{"bad key", func(s string) string { return strings.Replace(s, "ed25519:AAEC", "rsa:AAEC", 1) }, `must start with "ed25519:"`},
		{"short key", func(s string) string {
			return strings.Replace(s, "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8=", "AAEC", 1)
		}, "32-byte"},
		{"exclude prefix", func(s string) string {
			return strings.Replace(s, "  share:", "  share:\n    exclude: {prefixes: [203.0.113.5/24]}", 1)
		}, "host bits"},
		{"exclude asn", func(s string) string {
			return strings.Replace(s, "  share:", "  share:\n    exclude: {asns: [0]}", 1)
		}, "0 is not an ASN"},
		{"unknown source", func(s string) string { return strings.Replace(s, "classes:", "sources: [snmp]\n    classes:", 1) }, `"snmp" must be one of`},
		{"flow at route level", func(s string) string {
			return strings.Replace(s, "classes:", "granularity: route\n    sources: [flow]\n    classes:", 1)
		}, "cannot be shared at route level"},
		{"limit range", func(s string) string { return s + "  limits: {max_conns: 0, page_records: 9999}\n" }, "page_records 9999"},
		{"preview with listen", func(s string) string {
			return strings.Replace(s, "enabled: true", "enabled: true\n  preview_only: true", 1)
		}, "remove herd.listen, herd.peers, and herd.hub"},
		{"duplicate peer", func(s string) string {
			i := strings.Index(s, "    - url")
			return s + s[i:]
		}, "duplicate"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := Parse([]byte(herdBase + tt.edit(herdOn)))
			if err == nil || !strings.Contains(err.Error(), tt.want) {
				t.Fatalf("err = %v, want it to contain %q", err, tt.want)
			}
		})
	}
}

func TestHerdPreviewOnlyNeedsNoListener(t *testing.T) {
	y := herdBase + "herd:\n  enabled: true\n  preview_only: true\n  share: {classes: [measurements, paths], granularity: route, sources: [static]}\n  vantage: {country: DE}\n"
	cfg, err := Parse([]byte(y))
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Herd.Serving() {
		t.Error("a preview_only node reports Serving")
	}
}

func TestHerdRefusedWithIXPAndFixedProber(t *testing.T) {
	if _, err := Parse([]byte(herdBase + herdOn + "ixp: {}\n")); err == nil || !strings.Contains(err.Error(), "herd cannot be used with ixp") {
		t.Errorf("ixp: err = %v", err)
	}
	fixed := herdBase + herdOn + "probers:\n  - type: fixed\n"
	if _, err := Parse([]byte(fixed)); err == nil || !strings.Contains(err.Error(), "fixed prober") {
		t.Errorf("fixed prober: err = %v", err)
	}
}

func TestHerdNeedsStorageAndBGP(t *testing.T) {
	noStore := strings.Replace(herdBase, "storage: {type: sqlite}\n", "", 1) + herdOn
	if _, err := Parse([]byte(noStore)); err == nil || !strings.Contains(err.Error(), "herd needs storage type sqlite") {
		t.Errorf("no storage: err = %v", err)
	}
	noBGP := strings.Replace(herdBase, "bgp:\n  neighbors:\n    - address: 192.0.2.254\n", "", 1) + herdOn
	if _, err := Parse([]byte(noBGP)); err == nil || !strings.Contains(err.Error(), "herd needs bgp.neighbors") {
		t.Errorf("no bgp: err = %v", err)
	}
}

func TestHerdDisabledKeepsSettingsForRollback(t *testing.T) {
	y := minimalYAML + strings.Replace(herdOn, "enabled: true", "enabled: false", 1)
	if _, err := Parse([]byte(y)); err != nil {
		t.Fatalf("disabling herd must not need other herd keys removed: %v", err)
	}
}

const herdHubYAML = "  hub: {url: \"https://hub.example.net/herd.json\"}\n"

func TestHerdHubDefaultsAndNoPeersNeeded(t *testing.T) {
	cfg, err := Parse([]byte(herdBase + herdOn[:strings.Index(herdOn, "  peers:")] + herdHubYAML))
	if err != nil {
		t.Fatal(err)
	}
	h := cfg.Herd.Hub
	if h == nil || h.URL != "https://hub.example.net/herd.json" || h.Refresh != 6*time.Hour || h.MaxPeers != 16 {
		t.Errorf("hub = %+v, want url set, refresh 6h, max_peers 16", h)
	}
	if cfg2, err := Parse([]byte(herdBase + herdOn)); err != nil || cfg2.Herd.Hub != nil {
		t.Errorf("no hub block must stay off: %v %+v", err, cfg2.Herd.Hub)
	}
}

func TestHerdHubValidation(t *testing.T) {
	for name, tt := range map[string]struct{ hub, want string }{
		"http":         {"  hub: {url: \"http://hub.example.net/herd.json\"}\n", "must be an https URL"},
		"no url":       {"  hub: {refresh: 1h}\n", "must be an https URL"},
		"credentials":  {"  hub: {url: \"https://user:pw@hub.example.net/herd.json\"}\n", "must be an https URL"},
		"fast refresh": {"  hub: {url: \"https://hub.example.net/h.json\", refresh: 1m}\n", "herd.hub.refresh"},
		"slow refresh": {"  hub: {url: \"https://hub.example.net/h.json\", refresh: 240h}\n", "herd.hub.refresh"},
		"many peers":   {"  hub: {url: \"https://hub.example.net/h.json\", max_peers: 65}\n", "herd.hub.max_peers 65"},
		"unknown key":  {"  hub: {url: \"https://hub.example.net/h.json\", trust: true}\n", "trust"},
	} {
		t.Run(name, func(t *testing.T) {
			_, err := Parse([]byte(herdBase + herdOn + tt.hub))
			if err == nil || !strings.Contains(err.Error(), tt.want) {
				t.Fatalf("err = %v, want it to contain %q", err, tt.want)
			}
		})
	}
}

func TestHerdHubNeedsAListener(t *testing.T) {
	y := herdBase + "herd:\n  enabled: true\n  share: {classes: [measurements]}\n  vantage: {country: US}\n" + herdHubYAML
	if _, err := Parse([]byte(y)); err == nil || !strings.Contains(err.Error(), "herd.listen") {
		t.Errorf("err = %v, want herd.listen", err)
	}
}
