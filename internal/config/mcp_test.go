package config

import (
	"strings"
	"testing"
)

func TestMCPDefaultsOff(t *testing.T) {
	cfg, err := Parse([]byte(validYAML))
	if err != nil {
		t.Fatal(err)
	}
	if cfg.MCPEnabled() || cfg.MCP != nil {
		t.Fatalf("mcp is on by default: %+v", cfg.MCP)
	}
}

func TestMCPDefaults(t *testing.T) {
	cfg, err := Parse([]byte(validYAML + "mcp:\n  enabled: true\n"))
	if err != nil {
		t.Fatal(err)
	}
	if m := cfg.MCP; !cfg.MCPEnabled() || m.WriteTools || m.RatePerMinute != DefaultMCPRatePerMinute {
		t.Fatalf("mcp = %+v", m)
	}
}

func TestMCPErrors(t *testing.T) {
	for _, tc := range []struct{ block, want string }{
		{"write_tools: true", "mcp.write_tools needs mcp.enabled"},
		{"enabled: true\n  rate_per_minute: -1", "rate_per_minute"},
		{"enabled: true\n  rate_per_minute: 6001", "rate_per_minute"},
		{"enabled: true\n  writes: true", "writes"},
	} {
		_, err := Parse([]byte(validYAML + "mcp:\n  " + tc.block + "\n"))
		if err == nil || !strings.Contains(err.Error(), tc.want) {
			t.Errorf("%q: %v, want an error holding %q", tc.block, err, tc.want)
		}
	}
	if _, err := Parse([]byte(validYAML + "mcp:\n  enabled: true\n  write_tools: true\n  rate_per_minute: 30\n")); err != nil {
		t.Errorf("valid block refused: %v", err)
	}
}
