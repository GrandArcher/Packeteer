package config

import (
	"strings"
	"testing"
)

const leakSources = `
leak_watch:
  enabled: true
  sources:
    - type: rislive
`

func TestLeakWatchOffByDefault(t *testing.T) {
	cfg, err := Parse([]byte(validYAML))
	if err != nil {
		t.Fatal(err)
	}
	if cfg.LeakWatching() {
		t.Fatal("leak_watch is on without a block")
	}
	// A block that is not enabled is ignored, sources and all.
	cfg, err = Parse([]byte(validYAML + "leak_watch:\n  sources: []\n"))
	if err != nil {
		t.Fatalf("disabled block rejected: %v", err)
	}
	if cfg.LeakWatching() {
		t.Fatal("leak_watch on with enabled unset")
	}
}

func TestLeakWatchValidation(t *testing.T) {
	cfg, err := Parse([]byte(validYAML + leakSources))
	if err != nil {
		t.Fatal(err)
	}
	if !cfg.LeakWatching() || len(cfg.LeakWatch.Sources) != 1 {
		t.Fatalf("leak_watch = %+v", cfg.LeakWatch)
	}
	if cfg.LeakWatch.ASPathRule {
		t.Fatal("as_path_rule on by default")
	}
	on, err := Parse([]byte(validYAML + strings.Replace(leakSources, "enabled: true\n", "enabled: true\n  as_path_rule: true\n", 1)))
	if err != nil || !on.LeakWatch.ASPathRule {
		t.Fatalf("as_path_rule: %v %+v", err, on)
	}
	for name, tc := range map[string]struct{ yaml, want string }{
		"no sources":    {validYAML + "leak_watch:\n  enabled: true\n", "leak_watch.sources: at least one source"},
		"no community":  {strings.Replace(validYAML, `packeteer_community: "64512:666"`, "", 1) + leakSources, "leak_watch requires packeteer_community"},
		"no type":       {validYAML + "leak_watch:\n  enabled: true\n  sources: [{name: x}]\n", "leak_watch.sources[0]: type is required"},
		"duplicate":     {validYAML + "leak_watch:\n  enabled: true\n  sources: [{type: rislive}, {type: rislive}]\n", "duplicate instance name"},
		"unknown field": {validYAML + "leak_watch:\n  enabled: true\n  poll: 5s\n", "poll"},
	} {
		t.Run(name, func(t *testing.T) {
			_, err := Parse([]byte(tc.yaml))
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("err %v, want %q", err, tc.want)
			}
		})
	}
}
