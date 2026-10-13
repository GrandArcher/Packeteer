package config

import (
	"strings"
	"testing"
)

func TestLinkoutsDefaults(t *testing.T) {
	cfg, err := Parse([]byte(validYAML))
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Linkouts.Enabled != nil || cfg.Linkouts.Custom != nil || cfg.Linkouts.HideInternal != nil {
		t.Fatalf("unset block = %+v", cfg.Linkouts)
	}
}

func TestLinkoutsParse(t *testing.T) {
	cfg, err := Parse([]byte(validYAML + `
linkouts:
  enabled: [he, bgptools, nlnog_ring]
  hide_internal: false
  custom:
    - {name: internal LG, url: "https://lg.example.net/?q={prefix}"}
`))
	if err != nil {
		t.Fatal(err)
	}
	l := cfg.Linkouts
	if len(l.Enabled) != 3 || l.HideInternal == nil || *l.HideInternal || len(l.Custom) != 1 || l.Custom[0].Name != "internal LG" {
		t.Fatalf("linkouts = %+v", l)
	}
	empty, err := Parse([]byte(validYAML + "linkouts:\n  enabled: []\n"))
	if err != nil {
		t.Fatal(err)
	}
	if empty.Linkouts.Enabled == nil || len(empty.Linkouts.Enabled) != 0 {
		t.Fatalf("enabled: [] must stay an empty list, not unset: %#v", empty.Linkouts.Enabled)
	}
}

func TestLinkoutsRejected(t *testing.T) {
	cases := []struct{ block, want string }{
		{"enabled: [bgpview]", `"bgpview" is not a link-out site`},
		{"enabled: [he, he]", "listed twice"},
		{"custom: [{name: a, url: \"http://lg.example.net/{prefix}\"}]", "must be an https URL"},
		{"custom: [{name: a, url: \"https://lg.example.net/{peer}\"}]", "unknown placeholder {peer}"},
		{"custom: [{name: a, url: \"https://lg.example.net/{prefix}/{asn}\"}]", "not both"},
		{"custom: [{name: a, url: \"https://lg.example.net/\"}]", "must contain {prefix} or {asn}"},
		{"custom: [{name: a, url: \"https://{asn}.example.net/\"}]", "host cannot hold"},
		{"custom: [{name: a, url: \"https://lg.example.net/{asn}\", extra: 1}]", "extra"},
		{"unknown_key: 1", "unknown_key"},
	}
	for _, tc := range cases {
		_, err := Parse([]byte(validYAML + "linkouts:\n  " + tc.block + "\n"))
		if err == nil || !strings.Contains(err.Error(), tc.want) {
			t.Errorf("%s: err = %v, want %q", tc.block, err, tc.want)
		}
	}
}
