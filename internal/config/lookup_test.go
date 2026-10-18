package config

import (
	"strings"
	"testing"
)

const lookupBlock = `
lookup:
  type: peeringdb
  config:
    exchanges:
      - {name: example-ix, ix_id: 1}
`

func TestLookupParses(t *testing.T) {
	for name, y := range map[string]string{
		"edge":     minimalYAML + lookupBlock,
		"ixp mode": minimalYAML + "ixp: {}\n" + lookupBlock,
	} {
		cfg, err := Parse([]byte(y))
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		if cfg.Lookup == nil || cfg.Lookup.Type != "peeringdb" || cfg.Mode != ModeObserve || cfg.Announcer != nil {
			t.Fatalf("%s: lookup %+v mode %s announcer %v", name, cfg.Lookup, cfg.Mode, cfg.Announcer)
		}
	}
}

func TestLookupNeedsType(t *testing.T) {
	_, err := Parse([]byte(minimalYAML + "lookup:\n  config: {}\n"))
	if err == nil || !strings.Contains(err.Error(), "lookup: type is required") {
		t.Fatalf("err %v", err)
	}
}

func TestLookupRejectsUnknownKey(t *testing.T) {
	if _, err := Parse([]byte(minimalYAML + lookupBlock + "  write: true\n")); err == nil {
		t.Fatal("unknown lookup key accepted")
	}
}
