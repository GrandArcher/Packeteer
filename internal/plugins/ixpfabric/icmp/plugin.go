// Package icmp is the ixp.fabric prober (#162). It sends ICMP echo from
// each configured vantage to member LAN addresses on that peering LAN and
// records loss, RTT, and jitter. It does not announce and it is not an
// input to Decide.
package icmp

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"time"

	"golang.org/x/time/rate"

	"github.com/GrandArcher/Packeteer/internal/plugins/ixpmember/ixf"
	"github.com/GrandArcher/Packeteer/pkg/plugin"

	// The packet sender is the built-in icmp prober. Register it even when
	// the controller did not import the prober set on its own.
	_ "github.com/GrandArcher/Packeteer/internal/plugins/prober/icmp"
)

// TypeName is the config type.
const TypeName = "icmp"

// Defaults and bounds. A zero value in config selects the default.
const (
	DefaultInterval  = time.Minute
	minInterval      = 10 * time.Second
	maxInterval      = time.Hour
	DefaultTimeout   = time.Second
	minTimeout       = 100 * time.Millisecond
	maxTimeout       = 5 * time.Second
	DefaultPackets   = 5
	maxPackets       = 20
	DefaultWorkers   = 4
	maxWorkers       = 64
	DefaultRate      = 20
	maxRate          = 10000
	DefaultMemberPPS = 1

	// nagiosTimeout bounds the Can Ping fetch. It is not a config knob:
	// the list is small and a slow manager must not stall the process.
	nagiosTimeout  = 30 * time.Second
	nagiosMaxBytes = 2 << 20
)

// errNoRedirect refuses every redirect so the API key header cannot be
// forwarded to another host.
var errNoRedirect = errors.New("redirects are not followed")

// Config is the fabric prober's config block.
type Config struct {
	Interval     time.Duration `yaml:"interval"`
	Timeout      time.Duration `yaml:"timeout"`
	Packets      int           `yaml:"packets"`
	Workers      int           `yaml:"workers"`
	RateLimitPPS int           `yaml:"rate_limit_pps"`
	MemberPPS    int           `yaml:"member_pps"`
}

func init() { plugin.FabricProbes.Register(TypeName, New) }

// The controller stores the prober as a FabricProbe.
var _ plugin.FabricProbe = (*Prober)(nil)

// Prober is the icmp fabric prober.
type Prober struct {
	r *runner
}

// New validates the config. It does not dial and it does not fetch.
func New(c plugin.Config, env plugin.Env) (plugin.FabricProbe, error) {
	var cfg Config
	if err := c.Decode(&cfg); err != nil {
		return nil, err
	}
	if err := applyDefaults(&cfg); err != nil {
		return nil, err
	}
	getenv := env.Getenv
	if getenv == nil {
		getenv = func(string) string { return "" }
	}
	log := env.Logger
	if log == nil {
		log = slog.New(slog.DiscardHandler)
	}
	sender, err := plugin.Probers.New(TypeName, plugin.NewConfig(nil), env)
	if err != nil {
		return nil, err
	}
	return &Prober{r: &runner{
		log:       log,
		prober:    sender,
		interval:  cfg.Interval,
		timeout:   cfg.Timeout,
		packets:   cfg.Packets,
		workers:   cfg.Workers,
		memberPPS: cfg.MemberPPS,
		global:    rate.NewLimiter(rate.Limit(cfg.RateLimitPPS), burst(cfg.RateLimitPPS, cfg.Packets)),
		apiKey:    getenv(ixf.APIKeyEnv),
		http: &http.Client{
			Timeout: nagiosTimeout,
			CheckRedirect: func(*http.Request, []*http.Request) error {
				return errNoRedirect
			},
		},
		view: plugin.FabricView{
			Configured: true,
			Vantages:   []plugin.FabricVantageStatus{},
			Samples:    []plugin.FabricSample{},
		},
		memberLim: map[uint32]*rate.Limiter{},
	}}, nil
}

func applyDefaults(cfg *Config) error {
	if cfg.Interval == 0 {
		cfg.Interval = DefaultInterval
	}
	if cfg.Interval < minInterval || cfg.Interval > maxInterval {
		return fmt.Errorf("interval %s must be between %s and %s", cfg.Interval, minInterval, maxInterval)
	}
	if cfg.Timeout == 0 {
		cfg.Timeout = DefaultTimeout
	}
	if cfg.Timeout < minTimeout || cfg.Timeout > maxTimeout {
		return fmt.Errorf("timeout %s must be between %s and %s", cfg.Timeout, minTimeout, maxTimeout)
	}
	if cfg.Packets == 0 {
		cfg.Packets = DefaultPackets
	}
	if cfg.Packets < 1 || cfg.Packets > maxPackets {
		return fmt.Errorf("packets %d must be between 1 and %d", cfg.Packets, maxPackets)
	}
	if cfg.Workers == 0 {
		cfg.Workers = DefaultWorkers
	}
	if cfg.Workers < 1 || cfg.Workers > maxWorkers {
		return fmt.Errorf("workers %d must be between 1 and %d", cfg.Workers, maxWorkers)
	}
	if cfg.RateLimitPPS == 0 {
		cfg.RateLimitPPS = DefaultRate
	}
	if cfg.RateLimitPPS < 1 || cfg.RateLimitPPS > maxRate {
		return fmt.Errorf("rate_limit_pps %d must be between 1 and %d", cfg.RateLimitPPS, maxRate)
	}
	if cfg.MemberPPS == 0 {
		cfg.MemberPPS = DefaultMemberPPS
	}
	if cfg.MemberPPS < 1 || cfg.MemberPPS > maxRate {
		return fmt.Errorf("member_pps %d must be between 1 and %d", cfg.MemberPPS, maxRate)
	}
	if cfg.MemberPPS > cfg.RateLimitPPS {
		return fmt.Errorf("member_pps %d must not exceed rate_limit_pps %d", cfg.MemberPPS, cfg.RateLimitPPS)
	}
	return nil
}

// burst is large enough for one probe. The limiter's rate is the sustained
// cap; the first probe may send its packets together, matching the edge
// probe engine.
func burst(pps, packets int) int {
	if pps < packets {
		return packets
	}
	return pps
}

// SetMembers records the IX-F view. The controller calls it before Start.
func (p *Prober) SetMembers(fn func() plugin.MemberView) { p.r.setMembers(fn) }

// SetVantages records the monitoring addresses. The controller calls it
// before Start.
func (p *Prober) SetVantages(v []plugin.FabricVantage) { p.r.setVantages(v) }

// View returns the latest round.
func (p *Prober) View() plugin.FabricView { return p.r.snapshot() }

// Start begins the probe loop. It does not block.
func (p *Prober) Start(ctx context.Context) error { return p.r.start(ctx) }

// Stop cancels the loop and waits for it to leave.
func (p *Prober) Stop(ctx context.Context) error { return p.r.stop(ctx) }
