package main

import (
	"testing"

	"github.com/GrandArcher/Packeteer/internal/config"
)

func TestMCPOptionsFollowConfig(t *testing.T) {
	if mcpOptions(&config.Config{}) != nil {
		t.Error("MCP options with no mcp block")
	}
	if mcpOptions(&config.Config{MCP: &config.MCP{WriteTools: true, RatePerMinute: 5}}) != nil {
		t.Error("MCP options with mcp.enabled false")
	}
	o := mcpOptions(&config.Config{MCP: &config.MCP{Enabled: true, WriteTools: true, RatePerMinute: 5}})
	if o == nil || !o.WriteTools || o.RatePerMinute != 5 {
		t.Errorf("options %+v", o)
	}
}
