package atlas

import (
	"os"
	"slices"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

// TestComposeProbeIsIsolated checks the optional probe service in the
// shipped docker-compose.yml: off unless its profile is asked for, and
// sharing nothing with Packeteer.
func TestComposeProbeIsIsolated(t *testing.T) {
	raw, err := os.ReadFile("../../docker-compose.yml")
	if err != nil {
		t.Fatal(err)
	}
	var doc struct {
		Services map[string]struct {
			Profiles    []string `yaml:"profiles"`
			Image       string   `yaml:"image"`
			NetworkMode string   `yaml:"network_mode"`
			Volumes     []string `yaml:"volumes"`
			CapDrop     []string `yaml:"cap_drop"`
			CapAdd      []string `yaml:"cap_add"`
			MemLimit    string   `yaml:"mem_limit"`
		} `yaml:"services"`
	}
	if err := yaml.Unmarshal(raw, &doc); err != nil {
		t.Fatal(err)
	}
	probe, ok := doc.Services["atlas-probe"]
	if !ok {
		t.Fatal("no atlas-probe service")
	}
	if !slices.Equal(probe.Profiles, []string{"atlas"}) {
		t.Errorf("profiles = %v: the probe must start only with --profile atlas", probe.Profiles)
	}
	if len(doc.Services["packeteer"].Profiles) != 0 {
		t.Error("packeteer itself is behind a profile")
	}
	if probe.NetworkMode != "" {
		t.Errorf("network_mode = %q: the probe must not share the host network", probe.NetworkMode)
	}
	for _, v := range probe.Volumes {
		if strings.Contains(v, "config.yaml") || strings.Contains(v, "packeteer-data") || strings.Contains(v, "plugins") {
			t.Errorf("the probe mounts Packeteer state: %s", v)
		}
	}
	if !slices.Equal(probe.CapDrop, []string{"ALL"}) || slices.Contains(probe.CapAdd, "NET_ADMIN") || probe.MemLimit == "" {
		t.Errorf("cap_drop %v cap_add %v mem_limit %q", probe.CapDrop, probe.CapAdd, probe.MemLimit)
	}
	if !strings.HasPrefix(probe.Image, "jamesits/ripe-atlas:") || strings.HasSuffix(probe.Image, ":edge") {
		t.Errorf("image = %q", probe.Image)
	}
}
