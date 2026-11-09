package main

import (
	"os"
	"path/filepath"
	"testing"

	"gopkg.in/yaml.v3"

	"github.com/GrandArcher/Packeteer/internal/config"
)

func TestInlineResultsMoveToTheFile(t *testing.T) {
	in := "mode: inject\nprobers:\n  - type: fixed\n    config:\n      paths:\n        - provider: transit-a\n          rtt_ms: 80\n        - provider: transit-b\n          rtt_ms: 10\nannouncer:\n  type: gobgp\n"
	out, state, err := fileProber([]byte(in), "/etc/packeteer/probes/state.yaml")
	if err != nil {
		t.Fatal(err)
	}
	var cfg struct {
		Mode    string `yaml:"mode"`
		Probers []struct {
			Type   string         `yaml:"type"`
			Config map[string]any `yaml:"config"`
		} `yaml:"probers"`
		Announcer struct {
			Type string `yaml:"type"`
		} `yaml:"announcer"`
	}
	if err := yaml.Unmarshal(out, &cfg); err != nil {
		t.Fatal(err)
	}
	if cfg.Mode != "inject" || cfg.Announcer.Type != "gobgp" || len(cfg.Probers) != 1 {
		t.Fatalf("rest of the config changed: %s", out)
	}
	if len(cfg.Probers[0].Config) != 1 || cfg.Probers[0].Config["file"] != "/etc/packeteer/probes/state.yaml" {
		t.Fatalf("prober config = %v, want only the file", cfg.Probers[0].Config)
	}
	var results struct {
		Paths []struct {
			Provider string  `yaml:"provider"`
			RTTMs    float64 `yaml:"rtt_ms"`
		} `yaml:"paths"`
	}
	if err := yaml.Unmarshal(state, &results); err != nil {
		t.Fatal(err)
	}
	if len(results.Paths) != 2 || results.Paths[0].Provider != "transit-a" || results.Paths[0].RTTMs != 80 || results.Paths[1].RTTMs != 10 {
		t.Fatalf("state = %s", state)
	}
}

func TestFileProberIsLeftAlone(t *testing.T) {
	in := "probers:\n  - type: fixed\n    config:\n      file: /etc/packeteer/probes/paths.yaml\n"
	out, state, err := fileProber([]byte(in), "/etc/packeteer/probes/state.yaml")
	if err != nil {
		t.Fatal(err)
	}
	if string(out) != in || state != nil {
		t.Fatalf("out = %q, state = %q; want the input and no state", out, state)
	}
}

func TestRefusesAConfigItCannotRewrite(t *testing.T) {
	for name, in := range map[string]string{
		"no probers":    "mode: observe\n",
		"icmp prober":   "probers:\n  - type: icmp\n",
		"no config":     "probers:\n  - type: fixed\n",
		"not a mapping": "- a\n- b\n",
	} {
		if _, _, err := fileProber([]byte(in), "f"); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

// The lab configs the matrix uses must still load after the rewrite, and
// only the ones with inline results get a state file.
func TestLabConfigsStillLoad(t *testing.T) {
	for name, inline := range map[string]bool{
		"packeteer-more-specific.yaml": true,
		"packeteer-mitigation.yaml":    true,
		"packeteer.yaml":               false,
		"packeteer-inbound.yaml":       false,
		"packeteer-ha-a.yaml":          false,
	} {
		raw, err := os.ReadFile(filepath.Join("..", name))
		if err != nil {
			t.Fatal(err)
		}
		out, state, err := fileProber(raw, "/etc/packeteer/probes/state.yaml")
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		if (state != nil) != inline {
			t.Errorf("%s: state written = %v, want %v", name, state != nil, inline)
		}
		if _, err := config.Parse(out); err != nil {
			t.Errorf("%s: rewritten config does not load: %v", name, err)
		}
	}
}
