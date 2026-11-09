package config

// MCP server (#302). The block turns on POST /mcp on the ops HTTP
// listener, a Model Context Protocol endpoint for AI assistants. It is a
// thin layer over the REST API: the same authentication, roles, and audit
// log apply, and it never announces anything itself.

// MCP defaults and bounds.
const (
	DefaultMCPRatePerMinute = 120
	MaxMCPRatePerMinute     = 6000
)

// MCP configures the MCP endpoint.
type MCP struct {
	// Enabled serves POST /mcp. Default false.
	Enabled bool `yaml:"enabled"`
	// WriteTools lists the write tools (maintenance windows). Default
	// false. A write tool also needs a token with the mcp:write scope and
	// the role the matching REST call needs.
	WriteTools bool `yaml:"write_tools"`
	// RatePerMinute caps the requests one user may make per minute
	// (default 120).
	RatePerMinute int `yaml:"rate_per_minute"`
}

// MCPEnabled reports whether the MCP endpoint is on.
func (c *Config) MCPEnabled() bool { return c != nil && c.MCP != nil && c.MCP.Enabled }

func (c *Config) defaultMCP() {
	if c.MCP != nil && c.MCP.RatePerMinute == 0 {
		c.MCP.RatePerMinute = DefaultMCPRatePerMinute
	}
}

func (c *Config) validateMCP(add func(string, ...any)) {
	m := c.MCP
	if m == nil {
		return
	}
	if m.RatePerMinute < 1 || m.RatePerMinute > MaxMCPRatePerMinute {
		add("mcp.rate_per_minute %d must be between 1 and %d", m.RatePerMinute, MaxMCPRatePerMinute)
	}
	if m.WriteTools && !m.Enabled {
		add("mcp.write_tools needs mcp.enabled: true")
	}
}
