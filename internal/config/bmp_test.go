package config

import (
	"strings"
	"testing"
)

const bmpYAML = minimalYAML + `
    bmp: PREFER
bgp:
  neighbors:
    - address: 192.0.2.254
rib_sources:
  - type: bmp
    config:
      routers: [192.0.2.254]
`

func TestBMPConfig(t *testing.T) {
	c, err := Parse([]byte(bmpYAML))
	if err != nil {
		t.Fatal(err)
	}
	if c.Providers[0].BMP != BMPPrefer || len(c.RIBSources) != 1 || c.RIBSources[0].Type != "bmp" {
		t.Fatalf("parsed: %+v %+v", c.Providers[0], c.RIBSources)
	}
	for name, tc := range map[string]struct{ yaml, want string }{
		"bad usage":    {strings.Replace(bmpYAML, "bmp: PREFER", "bmp: always", 1), `bmp "always" is invalid`},
		"no source":    {strings.Replace(bmpYAML, "rib_sources:\n  - type: bmp\n    config:\n      routers: [192.0.2.254]\n", "", 1), "bmp prefer requires a rib_sources entry"},
		"no neighbors": {strings.Replace(bmpYAML, "bgp:\n  neighbors:\n    - address: 192.0.2.254\n", "", 1), "rib_sources requires at least one bgp.neighbors"},
		"source type":  {strings.Replace(bmpYAML, "type: bmp", "name: x", 1), "rib_sources[0]: type is required"},
	} {
		_, err := Parse([]byte(tc.yaml))
		if err == nil || !strings.Contains(err.Error(), tc.want) {
			t.Errorf("%s: err = %v, want %q", name, err, tc.want)
		}
	}
}

const addPathYAML = minimalYAML + `
    add_path: true
bgp:
  neighbors:
    - address: 192.0.2.254
      add_path: true
`

func TestAddPathConfig(t *testing.T) {
	c, err := Parse([]byte(addPathYAML))
	if err != nil {
		t.Fatal(err)
	}
	if !c.Providers[0].AddPath || !c.BGP.Neighbors[0].AddPath {
		t.Fatalf("parsed: %+v %+v", c.Providers[0], c.BGP.Neighbors[0])
	}
	for name, tc := range map[string]struct{ yaml, want string }{
		"no add-path neighbor": {strings.Replace(addPathYAML, "      add_path: true\n", "", 1), "add_path requires a bgp.neighbors entry with add_path: true"},
		"with bmp only": {strings.Replace(addPathYAML, "    add_path: true\n", "    add_path: true\n    bmp: only\n", 1) +
			"rib_sources:\n  - type: bmp\n    config:\n      routers: [192.0.2.254]\n", "add_path does not apply with bmp only"},
	} {
		_, err := Parse([]byte(tc.yaml))
		if err == nil || !strings.Contains(err.Error(), tc.want) {
			t.Errorf("%s: err = %v, want %q", name, err, tc.want)
		}
	}
}
