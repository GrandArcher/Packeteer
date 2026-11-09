package config

import (
	"strings"
	"testing"
)

func TestProviderASNAndType(t *testing.T) {
	y := edit(t, minimalYAML, "  next_hop: 192.0.2.1", "  next_hop: 192.0.2.1\n    asn: 64496\n    type: transit")
	cfg, err := Parse([]byte(y))
	if err != nil {
		t.Fatal(err)
	}
	if p := cfg.Providers[0]; p.ASN != 64496 || p.Type != "transit" {
		t.Fatalf("provider = %+v", p)
	}
	for _, typ := range ProviderTypes {
		if _, err := Parse([]byte(edit(t, minimalYAML, "  next_hop: 192.0.2.1", "  next_hop: 192.0.2.1\n    type: "+typ))); err != nil {
			t.Errorf("type %s: %v", typ, err)
		}
	}
	bad := edit(t, minimalYAML, "  next_hop: 192.0.2.1", "  next_hop: 192.0.2.1\n    type: upstream")
	if _, err := Parse([]byte(bad)); err == nil || !strings.Contains(err.Error(), `type "upstream" is invalid`) {
		t.Fatalf("type upstream: %v", err)
	}
}
