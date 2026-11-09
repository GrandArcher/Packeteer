package config

import "time"

// Indirect probing defaults and bounds (#123). They match the traceroute
// source's so one trace costs the same either way.
const (
	DefaultIndirectMaxHops    = 16
	MaxIndirectMaxHops        = 64
	DefaultIndirectProbes     = 3
	MaxIndirectProbes         = 10
	DefaultIndirectMinReplies = 2
	DefaultIndirectTimeout    = 500 * time.Millisecond
	MaxIndirectTimeout        = 5 * time.Second
	DefaultIndirectPort       = 33434
	DefaultIndirectBudget     = 10 * time.Second
	MaxIndirectBudget         = 30 * time.Second
	DefaultIndirectCacheTTL   = 30 * time.Minute
	MinIndirectCacheTTL       = time.Minute
	MaxIndirectCacheTTL       = 24 * time.Hour
	DefaultIndirectMaxQueue   = 1024
	MaxIndirectMaxQueue       = 100000
)

// ProbeIndirect is per-provider indirect probing (#123). When every
// address probed inside a prefix is silent for a provider, the prefix is
// traced in the background from that provider's source address and the
// provider is scored at its own highest stable hop. Omitted or
// enabled: false leaves it off. Measurement only.
type ProbeIndirect struct {
	Enabled bool `yaml:"enabled"`
	// MaxHops, Probes, MinReplies, Timeout, and Port shape one trace,
	// as on the traceroute source.
	MaxHops    int           `yaml:"max_hops"`
	Probes     int           `yaml:"probes"`
	MinReplies int           `yaml:"min_replies"`
	Timeout    time.Duration `yaml:"timeout"`
	Port       int           `yaml:"port"`
	// Budget is the wall clock for one background pass across every
	// queued trace. Passes are at least probe.interval apart.
	Budget time.Duration `yaml:"budget"`
	// CacheTTL is how long a discovered hop is reused before the prefix
	// is traced again. An in-prefix reply drops it sooner.
	CacheTTL time.Duration `yaml:"cache_ttl"`
	// MaxQueue caps traces waiting for a pass.
	MaxQueue int `yaml:"max_queue"`
}

func (c *Config) defaultIndirect() {
	in := c.Probe.Indirect
	if in == nil {
		return
	}
	if in.MaxHops == 0 {
		in.MaxHops = DefaultIndirectMaxHops
	}
	if in.Probes == 0 {
		in.Probes = DefaultIndirectProbes
	}
	if in.MinReplies == 0 {
		in.MinReplies = min(DefaultIndirectMinReplies, in.Probes)
	}
	if in.Timeout == 0 {
		in.Timeout = DefaultIndirectTimeout
	}
	if in.Port == 0 {
		in.Port = DefaultIndirectPort
	}
	if in.Budget == 0 {
		in.Budget = DefaultIndirectBudget
	}
	if in.CacheTTL == 0 {
		in.CacheTTL = DefaultIndirectCacheTTL
	}
	if in.MaxQueue == 0 {
		in.MaxQueue = DefaultIndirectMaxQueue
	}
}

func (c *Config) validateIndirect(add func(string, ...any)) {
	in := c.Probe.Indirect
	if in == nil {
		return
	}
	if in.MaxHops < 1 || in.MaxHops > MaxIndirectMaxHops {
		add("probe.indirect.max_hops %d must be between 1 and %d", in.MaxHops, MaxIndirectMaxHops)
	}
	if in.Probes < 1 || in.Probes > MaxIndirectProbes {
		add("probe.indirect.probes %d must be between 1 and %d", in.Probes, MaxIndirectProbes)
	}
	if in.MinReplies < 1 || in.MinReplies > in.Probes {
		add("probe.indirect.min_replies %d must be between 1 and probes (%d)", in.MinReplies, in.Probes)
	}
	if in.Timeout < time.Millisecond || in.Timeout > MaxIndirectTimeout {
		add("probe.indirect.timeout %s must be between 1ms and %s", in.Timeout, MaxIndirectTimeout)
	}
	if in.Port < 1 || in.Port > 65535 {
		add("probe.indirect.port %d must be between 1 and 65535", in.Port)
	}
	if in.Budget < in.Timeout || in.Budget > MaxIndirectBudget {
		add("probe.indirect.budget %s must be between probe.indirect.timeout (%s) and %s", in.Budget, in.Timeout, MaxIndirectBudget)
	}
	if in.CacheTTL < MinIndirectCacheTTL || in.CacheTTL > MaxIndirectCacheTTL {
		add("probe.indirect.cache_ttl %s must be between %s and %s", in.CacheTTL, MinIndirectCacheTTL, MaxIndirectCacheTTL)
	}
	if in.MaxQueue < 1 || in.MaxQueue > MaxIndirectMaxQueue {
		add("probe.indirect.max_queue %d must be between 1 and %d", in.MaxQueue, MaxIndirectMaxQueue)
	}
}
