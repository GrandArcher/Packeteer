package config

import (
	"strings"
	"testing"
	"time"
)

const mitigationBlock = `
mitigation:
  allowlist: [203.0.113.0/24]
  announcer:
    type: gobgp
`

func TestMitigationDefaults(t *testing.T) {
	cfg, err := Parse([]byte(validYAML + mitigationBlock))
	if err != nil {
		t.Fatal(err)
	}
	m := cfg.Mitigation
	if m.Mode != ModeObserve || cfg.MitigationMode() != ModeObserve {
		t.Fatalf("mitigation mode = %q, want observe by default", m.Mode)
	}
	if m.MaxRules != DefaultMitigationMaxRules || m.DefaultTTL != time.Hour || m.MaxTTL != 24*time.Hour || m.LocalPref != cfg.LocalPref {
		t.Fatalf("defaults = %+v", m)
	}
	if got := m.MitigationAllowlist(); len(got) != 1 || got[0].String() != "203.0.113.0/24" {
		t.Fatalf("allowlist = %v", got)
	}
	// A short max_ttl pulls the default TTL down with it.
	cfg, err = Parse([]byte(validYAML + mitigationBlock + "  max_ttl: 10m\n"))
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Mitigation.DefaultTTL != 10*time.Minute {
		t.Fatalf("default_ttl = %s", cfg.Mitigation.DefaultTTL)
	}
	cfg, err = Parse([]byte(validYAML))
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Mitigation != nil || cfg.MitigationMode() != "" {
		t.Fatal("mitigation must be off unless configured")
	}
}

func TestMitigationInjectValid(t *testing.T) {
	cfg, err := Parse([]byte(injectYAML + mitigationBlock + "  mode: INJECT\n  max_rules: 5\n  local_pref: 300\n"))
	if err != nil {
		t.Fatal(err)
	}
	if m := cfg.Mitigation; m.Mode != ModeInject || m.MaxRules != 5 || m.LocalPref != 300 {
		t.Fatalf("mitigation = %+v", m)
	}
	cfg, err = Parse([]byte(injectYAML + mitigationBlock + "  mode: inject\n"))
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Mitigation.LocalPref != cfg.LocalPref || cfg.LocalPref == 0 {
		t.Fatalf("local_pref default = %d", cfg.Mitigation.LocalPref)
	}
}

func TestMitigationValidation(t *testing.T) {
	cases := map[string]struct{ base, block, want string }{
		"inject needs top-level inject": {validYAML, mitigationBlock + "  mode: inject\n", "requires mode inject"},
		"inject needs an announcer":     {injectYAML, "\nmitigation:\n  mode: inject\n  allowlist: [203.0.113.0/24]\n", "requires mitigation.announcer"},
		"bad mode":                      {validYAML, mitigationBlock + "  mode: suggest\n", "mitigation.mode"},
		"no allowlist":                  {validYAML, "\nmitigation:\n  announcer: {type: gobgp}\n", "at least one prefix"},
		"bad cidr":                      {validYAML, "\nmitigation:\n  allowlist: [nope]\n", "not a valid CIDR"},
		"host bits":                     {validYAML, "\nmitigation:\n  allowlist: [203.0.113.1/24]\n", "host bits"},
		"default route":                 {validYAML, "\nmitigation:\n  allowlist: [0.0.0.0/0]\n", "every prefix"},
		"duplicate":                     {validYAML, "\nmitigation:\n  allowlist: [203.0.113.0/24, 203.0.113.0/24]\n", "duplicate"},
		"cap too high":                  {validYAML, mitigationBlock + "  max_rules: 1001\n", "max_rules"},
		"cap negative":                  {validYAML, mitigationBlock + "  max_rules: -1\n", "max_rules"},
		"max ttl too long":              {validYAML, mitigationBlock + "  max_ttl: 200h\n", "max_ttl"},
		"default over max":              {validYAML, mitigationBlock + "  default_ttl: 2h\n  max_ttl: 1h\n", "default_ttl"},
		"announcer without type":        {validYAML, "\nmitigation:\n  allowlist: [203.0.113.0/24]\n  announcer: {config: {}}\n", "type is required"},
		"unknown key":                   {validYAML, mitigationBlock + "  rules: []\n", "rules"},
	}
	for name, c := range cases {
		_, err := Parse([]byte(c.base + c.block))
		if err == nil || !strings.Contains(err.Error(), c.want) {
			t.Errorf("%s: err = %v, want %q", name, err, c.want)
		}
	}
}
